use dns_lookup;
use hex_slice;
use pnet;
use socket2;
use time;

use std::fmt;

use socket2::{SockAddr, Socket};
use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use time::SteadyTime;

use dns_lookup::lookup_addr;
// only used for debug printing packets

use hex_slice::AsHex;

use super::start::{TraceProtocol, TraceRouteSpec};
use crate::libtraceroute::packet::{
    make_icmp_packet_out, make_tcp_packet_out, make_udp_packet_out, static_analyse_v4_payload,
    static_analyse_v6_payload, static_unwrap_payload_ip_packet_in,
};

use crate::rawsocket::async_std::RawSocket;

use async_std::future;
use async_std::pin::Pin;
use async_std::prelude::*;
use async_std::stream::Stream;
use async_std::task::{Context, Poll};
use futures::{
    future::{FutureExt, LocalBoxFuture},
    select,
    stream::{FuturesUnordered, StreamExt},
};

pub const MAX_PACKET_SIZE: usize = 4096 + 128;
pub const ICMP_HEADER_LEN: usize = 8;
pub const UDP_HEADER_LEN: usize = 8;
pub const TCP_HEADER_LEN: usize = 40;
pub const SRC_BASE_PORT: u16 = 0x5000;
pub const DST_BASE_PORT: u16 = 0x8000 + 666;

pub enum IcmpPacketIn {
    V4(Ipv4Packet<'static>),
    V6(Icmpv6Packet<'static>),
}

#[derive(Debug, Clone)]
pub struct HopTimeOutError {
    pub message: String,
    pub line: usize,
    pub column: usize,
}

#[derive(Debug)]
pub enum HopOrError {
    HopOk(TraceHop),
    HopError(HopTimeOutError),
}

impl fmt::Display for HopTimeOutError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "* {}", self.message)
    }
}

impl Serialize for HopTimeOutError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        let mut s = serializer.serialize_struct("HopTimeOutError", 1)?;
        s.serialize_field("x", &"*".to_string())?;
        s.end()
    }
}

impl Serialize for HopOrError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        match *self {
            HopOrError::HopOk(ref hop) => serializer.serialize_newtype_struct("TraceHop", hop),
            HopOrError::HopError(ref err) => serializer.serialize_newtype_struct("TraceHop", err),
        }
    }
}

pub struct HopFutures(pub Vec<Box<dyn Future<Output = HopOrError>>>);

impl fmt::Debug for HopFutures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "something, something")
    }
}

impl HopFutures {
    pub fn push(mut self, hf: Box<dyn Future<Output = HopOrError>>) {
        self.0.push(hf)
    }
}

#[derive(Debug, Serialize)]
pub struct TraceResult {
    // This is a global error for all hops in this sequence
    #[serde(skip_serializing)]
    pub error: io::Result<Error>,
    pub hop: u8,
    // #[serde(skip_serializing)]
    pub result: Vec<HopOrError>,
}

// To satisfy the coherency rules
// we wrap the hop rtt in a tuple-like struct.
// As always turns out that the compiler is right,
// this is actually better.
pub struct HopDuration(time::Duration);
#[derive(Debug)]
pub struct FromIp(SocketAddr);

#[derive(Debug, Serialize)]
pub struct TraceHop {
    /// IP address of the hophost
    pub from: FromIp,
    /// The resolved hostname
    pub hop_name: String,
    /// Time-to-live for this hop
    pub ttl: u8,
    /// Round-trip-time for this packet
    pub rtt: HopDuration,
    /// Size of the reply
    pub size: usize,
}

impl Serialize for FromIp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let FromIp(s) = self;
        serializer.serialize_str(&s.ip().to_string())
    }
}

impl Serialize for HopDuration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let HopDuration(d) = *self;
        serializer.serialize_f64(d.num_microseconds().unwrap() as f64 / 1000.0)
    }
}

impl fmt::Debug for HopDuration {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let HopDuration(d) = self;
        write!(f, "{}µs", d.num_microseconds().unwrap())
    }
}

#[derive(Debug)]
pub struct TraceHopsIterator<'a> {
    pub dst_addr: SocketAddr,
    // af is based on either the user option, or from the
    // destination address if it was an IP address.
    // pub af: AddressFamily,
    // inferred from user options
    pub spec: TraceRouteSpec,
    // invariants for this tr
    pub src_addr: SocketAddr,
    pub socket_in: &'a RawSocket,
    pub socket_out: Socket,
    // mutable state
    pub ttl: u16,
    pub ident: u16,
    pub seq_num: u16,
    pub done: bool,
    pub result: Vec<TraceResult>,
    pub ident_collection: &'a Vec<u16>,
}

impl<'a> TraceHopsIterator<'a> {
    pub fn new(
        spec: TraceRouteSpec,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        socket_in: &'a RawSocket,
        socket_out: Socket,
        ttl: u16,
        ident: u16,
        seq_num: u16,
        ident_collection: &'a Vec<u16>,
    ) -> TraceHopsIterator<'a> {
        TraceHopsIterator {
            spec: spec,
            src_addr: src_addr,
            dst_addr: dst_addr,
            ttl: ttl,
            ident: ident,
            seq_num: seq_num,
            done: false,
            result: Vec::new(),
            ident_collection: ident_collection,
            socket_in: socket_in,
            socket_out: socket_out,
        }
    }

    fn set_ttl(&self, socket: &Socket) -> Result<u32, Error> {
        // In IPv6 IP_TTL is NOT called IPV6_TTL, but
        // IPV6_UNICAST_HOPS
        match &self.src_addr {
            SocketAddr::V4(_) => {
                //println!("socket ttl: {:?}", self.ttl);
                socket.set_ttl(self.ttl as u32)?;
                socket.ttl()
            }
            SocketAddr::V6(_) => {
                socket.set_unicast_hops_v6(self.ttl as u32)?;
                socket.unicast_hops_v6()
            }
        }
    }

    async fn static_hop_listen(
        socket_in: &'a RawSocket,
        start_time: time::SteadyTime,
        packet_out: Vec<u8>,
        timeout: u64,
        ttl: u16,
        src_addr: SocketAddr,
        max_hops: u16,
        proto: TraceProtocol,
        public_ip: Option<IpAddr>,
        paris: Option<u8>,
        ident: u16,
        ident_collection: &'a Vec<u16>,
        seq_num: u16,
        verbose: bool,
        // the result of the hop (from, ttl, etc.), true if the last hop has been reached: "done", inferred hop number
    ) -> (HopOrError, bool, u8) {
        let dur = std::time::Duration::from_millis(1000 * timeout as u64);
        let mut buf_in: Vec<u8> = vec![0; MAX_PACKET_SIZE];
        match future::timeout(dur, socket_in.recv_from(buf_in.as_mut_slice())).await {
            Err(e) => {
                println!("future timeout for hop {}: {:?}", ttl, e);
                (
                    HopOrError::HopError(HopTimeOutError {
                        message: "* wut?".to_string(),
                        line: 0,
                        column: 0,
                    }),
                    false,
                    seq_num as u8,
                )
            }
            Ok(r) => {
                let (packet_len, sender) = r.unwrap();
                let rtt = SteadyTime::now() - start_time;

                // The IP packet that wraps the incoming ICMP message.
                let (packet_in, ttl_in) =
                    static_unwrap_payload_ip_packet_in(&buf_in, src_addr, verbose);

                match packet_in {
                    IcmpPacketIn::V6(icmp_packet_in) => {
                        match static_analyse_v6_payload(
                            &packet_out,
                            &icmp_packet_in,
                            ident,
                            seq_num,
                            ident_collection,
                            max_hops,
                            ttl,
                            proto,
                            public_ip,
                            paris,
                            verbose,
                        ) {
                            (Ok(_), done) => {
                                let host = SocketAddr::V6(sender.as_inet6().unwrap());
                                (
                                    HopOrError::HopOk(TraceHop {
                                        ttl: ttl_in,
                                        size: packet_len,
                                        from: FromIp(host),
                                        hop_name: lookup_addr(&host.ip()).unwrap(),
                                        rtt: HopDuration(rtt),
                                    }),
                                    done,
                                    seq_num as u8,
                                )
                            }
                            (Err(ref err), done)
                                if err.kind() == ErrorKind::InvalidData
                                    || err.kind() == ErrorKind::Other =>
                            {
                                if verbose {
                                    println!("Error occurred");
                                    println!("{:?}", err);
                                };
                                (
                                    HopOrError::HopError(HopTimeOutError {
                                        message: "*".to_string(),
                                        line: 0,
                                        column: 0,
                                    }),
                                    done,
                                    seq_num as u8,
                                )
                            }
                            (Err(e), done) => (
                                HopOrError::HopError(HopTimeOutError {
                                    message: e.to_string(),
                                    line: 0,
                                    column: 0,
                                }),
                                done,
                                seq_num as u8,
                            ),
                        }
                    }
                    IcmpPacketIn::V4(ip_packet_in) => {
                        // let ip_payload = ip_packet_in.payload();
                        // let icmp_packet_in = IcmpPacket::new(&ip_packet_in.payload()).unwrap();
                        match static_analyse_v4_payload(
                            &packet_out,
                            // &icmp_packet_in,
                            // &ip_payload,
                            ip_packet_in,
                            ident_collection,
                            // seq_num,
                            // max_hops,
                            // ttl,
                            proto,
                            public_ip,
                            paris,
                            verbose,
                        ) {
                            (Ok(inferred_seq_num), done) => {
                                let host = SocketAddr::V4(sender.as_inet().unwrap());
                                (
                                    HopOrError::HopOk(TraceHop {
                                        ttl: ttl_in,
                                        size: packet_len,
                                        from: FromIp(host),
                                        hop_name: lookup_addr(&host.ip()).unwrap(),
                                        rtt: HopDuration(rtt),
                                    }),
                                    done,
                                    match inferred_seq_num {
                                        Some(seq_num) => seq_num,
                                        _ => seq_num as u8,
                                    },
                                )
                            }
                            (err, done) => {
                                if verbose {
                                    println!("* Error occured");
                                    println!("{:?}", err);
                                }
                                (
                                    HopOrError::HopError(HopTimeOutError {
                                        message: "* wut?".to_string(),
                                        line: 0,
                                        column: 0,
                                    }),
                                    done,
                                    seq_num as u8,
                                )
                            }
                        }
                    }
                }
            }
        }
    }

    #[allow(unused_variables)]
    pub fn collect_all_futures(
        &mut self,
        futures_buf: &FuturesUnordered<LocalBoxFuture<'a, (HopOrError, bool, u8)>>,
    ) -> io::Result<()> {
        let mut ident_iterator = self.ident_collection.iter();

        'hop: for hop_count in self.spec.start_ttl..self.spec.max_hops {
            self.seq_num += 1;
            self.ttl += 1;

            if self.spec.verbose {
                println!("==============");
                println!("START HOP {}", self.seq_num);
            }

            // binding the src_addr makes sure no temporary
            // ipv6 addresses are created to send the packet.
            // Temporary ipv6 addresses (a privacy feature) will
            // result in wrong UDP/TCP checksums, since that
            // will use the secured IPv6 address of the interface
            // sending as the src_addr to calculate checksums with.
            self.socket_out
                .bind(&SockAddr::from(self.src_addr))
                .unwrap();

            self.socket_out.set_reuse_address(true)?;

            let src = SocketAddr::new(self.src_addr.ip(), self.ident);

            'trt: for count in 0..self.spec.packets_per_hop {
                let ttl = self.set_ttl(&self.socket_out);
                // self.ident = SRC_BASE_PORT - <u16>::from(rand::random::<u8>());
                self.ident = ident_iterator.next().unwrap().to_owned();
                let packet_out = match self.spec.proto {
                    TraceProtocol::ICMP => {
                        make_icmp_packet_out(&self.src_addr, self.ident, self.seq_num)
                    }
                    TraceProtocol::UDP => make_udp_packet_out(
                        &self.src_addr,
                        &self.dst_addr,
                        self.seq_num,
                        self.spec.paris,
                        self.spec.verbose,
                    ),
                    TraceProtocol::TCP => make_tcp_packet_out(
                        &self.src_addr,
                        &self.dst_addr,
                        self.seq_num,
                        self.ident,
                        self.spec.paris,
                        self.spec.tcp_dest_port,
                        self.spec.verbose,
                    ),
                };

                if self.spec.verbose {
                    println!("identifier: {:02x}", &[self.ident].as_hex());
                };

                let dst_port_for_hop = match self.spec.proto {
                    TraceProtocol::ICMP => self.seq_num + DST_BASE_PORT,
                    // Increase the port number only for
                    // classic traceroute for UDP,
                    // paris traceroute uses the UDP checksum to identify
                    // packets
                    TraceProtocol::UDP => match self.spec.paris {
                        None => self.seq_num + DST_BASE_PORT,
                        Some(paris_id) => DST_BASE_PORT,
                    },
                    TraceProtocol::TCP => match self.spec.paris {
                        None => self.spec.tcp_dest_port + self.seq_num,
                        Some(paris_id) => self.spec.tcp_dest_port,
                    },
                };

                // create it again, since we're borrowing non-mutable,
                // we can't directly set the port.
                let dst_addr: SockAddr =
                    SocketAddr::new(self.dst_addr.ip(), dst_port_for_hop).into();

                if self.spec.verbose {
                    println!("dst_addr: {:?}", dst_addr);
                    println!(
                        "dst_addr port: {:?}/{:02x}",
                        &[self.dst_addr.port()],
                        &[self.dst_addr.port()].as_hex()
                    );
                    println!("local addr: {:?}", self.socket_out.local_addr());
                };

                let wrote = self.socket_out.send_to(&packet_out, &dst_addr)?;
                assert_eq!(wrote, packet_out.len());
                let start_time = SteadyTime::now();

                futures_buf.push(
                    Self::static_hop_listen(
                        &self.socket_in,
                        start_time,
                        packet_out,
                        self.spec.timeout as u64,
                        self.ttl,
                        self.src_addr,
                        self.spec.max_hops,
                        self.spec.proto,
                        self.spec.public_ip,
                        self.spec.paris,
                        self.ident,
                        &self.ident_collection,
                        self.seq_num,
                        self.spec.verbose,
                    )
                    .boxed_local(),
                );
            }
        }
        Ok(())
    }
}

impl<'a> Stream for TraceHopsIterator<'a> {
    type Item = io::Result<Vec<TraceResult>>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut futures_buf: FuturesUnordered<LocalBoxFuture<'a, (HopOrError, bool, u8)>> =
            FuturesUnordered::new();

        let mut trace_hops: Vec<TraceResult> = Vec::with_capacity(self.spec.max_hops as usize);

        for x in 0..(self.spec.max_hops - self.spec.start_ttl + 1) {
            trace_hops.push(TraceResult {
                hop: x as u8,
                error: Err(Error::new(ErrorKind::Other, "-42")),
                result: Vec::new(),
            })
        }

        if self.done {
            return Poll::Ready(None);
        }
        if self.ttl == self.spec.max_hops {
            return Poll::Ready(None);
        }
        match self.collect_all_futures(&mut futures_buf) {
            Ok(()) => {
                println!("no of futures : {:?}", futures_buf.len());
                async_std::task::block_on(async {
                    // let mut done: bool;

                    loop {
                        select! {
                            h = futures_buf.next() => {
                                println!("async select {:?}", h);
                                match h {
                                    None => {
                                        trace_hops[(self.seq_num - self.spec.start_ttl) as usize].error = Err(Error::new(ErrorKind::Other, "-42"));
                                     },
                                    Some(hop) => {
                                        self.done = hop.1;
                                        trace_hops[(hop.2 - self.spec.start_ttl as u8) as usize].result.push(hop.0);
                                    }
                                };
                            }
                            complete => { break; }
                        }
                    }
                });
            }
            Err(e) => {
                // This is a fatal condition,
                // probably a socket that cannot be opened,
                // or a packet that just gets stuck on its way out of localhost.
                // gracefully end all this.
                self.done = true;
                trace_hops[self.seq_num as usize].error = Err(e);
            }
        };

        // trace_hops contains all hops counting from zero,
        // but if the user specified a hight start TTL then we
        // don't want to return the hops lower that start ttl.
        let trace_hops_from_first_ttl: Vec<TraceResult> = trace_hops
            .into_iter()
            .filter(|h| h.hop != 0 && h.hop >= self.spec.start_ttl as u8)
            .collect();
        Poll::Ready(Some(Ok(trace_hops_from_first_ttl)))
    }
}
