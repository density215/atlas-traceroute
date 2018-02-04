#![feature(ip)]

extern crate dns_lookup;
extern crate hex_slice;
extern crate ipnetwork;
extern crate pnet;
extern crate rand;
extern crate socket2;
extern crate time;

use std::iter::Iterator;

use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, SocketAddrV4};
use std::net::{SocketAddr, SocketAddrV6, ToSocketAddrs};
use ipnetwork::IpNetwork;

use time::{Duration, SteadyTime};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::Packet;
use pnet::packet::icmp::checksum;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::datalink::NetworkInterface;

use dns_lookup::lookup_addr;
// only used for debig printing packets
//use hex_slice::AsHex;

const MAX_PACKET_SIZE: usize = 4096 + 128;
const ICMP_HEADER_LEN: usize = 8;
const SRC_BASE_PORT: u16 = 20480;
const DST_BASE_PORT: u16 = 80;
const DEFAULT_TRT_COUNT: u8 = 3;

#[derive(Debug)]
enum AddressFamily {
    V4,
    V6,
}

enum IcmpPacketIn {
    V4(Ipv4Packet<'static>),
    V6(Icmpv6Packet<'static>),
}

pub fn make_icmp6_packet(payload: &[u8]) -> Icmpv6Packet {
    Icmpv6Packet::new(&payload).unwrap()
}

#[derive(Debug)]
pub struct TraceRoute {
    src_addr: SockAddr,
    dst_addr: SocketAddr,
    af: AddressFamily,
    proto: TraceProtocol,
    ttl: u32,
    ident: u16,
    seq_num: u16,
    done: bool,
    timeout: Duration,
    pub result: Vec<TraceResult>,
    socket_in: Socket,
}

#[derive(Debug)]
pub struct TraceResult {
    error: io::Result<Error>,
    hop: u32,
    pub result: Vec<io::Result<TraceHop>>,
}

#[derive(Debug)]
pub enum TraceProtocol {
    ICMP,
    UDP,
    TCP,
}

#[derive(Debug)]
pub struct TraceHop {
    /// IP address of the hophost
    pub host: SocketAddr,
    /// The resolved hostname
    pub hop_name: String,
    /// Time-to-live for this hop
    pub ttl: u32,
    /// Round-trip-time for this packet
    pub rtt: Duration,
    /// Size of the reply
    pub size: usize,
}

fn get_sock_addr<'a>(af: AddressFamily) -> SockAddr {
    let filter_public_if_for_af = |addr: &IpNetwork| match af {
        AddressFamily::V4 => addr.is_ipv4() && !addr.ip().is_loopback(),
        AddressFamily::V6 => addr.is_ipv6() && addr.ip().is_global(),
    };
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.ips.len() > 0)
        .flat_map(|i| i.ips)
        .filter(filter_public_if_for_af)
        .map(|a| a.ip())
        .nth(0)
        .unwrap();
    println!("src_addr: {:?}", interface);

    match interface {
        IpAddr::V4(addrv4) => <SockAddr>::from(SocketAddrV4::new(addrv4, SRC_BASE_PORT)),
        IpAddr::V6(addrv6) => <SockAddr>::from(SocketAddrV6::new(addrv6, SRC_BASE_PORT, 0, 0x0)),
    }
}

impl TraceRoute {
    fn create_socket(&self, out: bool) -> Socket {
        let af = &self.af;
        let protocol = match (out, &self.proto) {
            (false, _) => match af {
                &AddressFamily::V4 => Some(<Protocol>::icmpv4()),
                &AddressFamily::V6 => Some(<Protocol>::icmpv6()),
            },
            (true, &TraceProtocol::ICMP) => match af {
                &AddressFamily::V4 => Some(<Protocol>::icmpv4()),
                &AddressFamily::V6 => Some(<Protocol>::icmpv6()),
            },
            (true, &TraceProtocol::UDP) => Some(<Protocol>::udp()),
            (true, &TraceProtocol::TCP) => Some(<Protocol>::tcp()),
        };

        let sock_type = match (out, &self.proto) {
            (false, _) => Type::raw(),
            (true, &TraceProtocol::ICMP) => Type::raw(),
            (true, &TraceProtocol::UDP) => Type::dgram(),
            (true, &TraceProtocol::TCP) => Type::dgram(),
        };

        match af {
            &AddressFamily::V4 => Socket::new(Domain::ipv4(), sock_type, protocol).unwrap(),
            &AddressFamily::V6 => Socket::new(Domain::ipv6(), sock_type, protocol).unwrap(),
        }
    }

    fn make_echo_request_packet_out(&self) -> Vec<u8> {
        match self.af {
            AddressFamily::V4 => {
                let icmp_buffer = vec![00u8; ICMP_HEADER_LEN];
                let mut echo_request_packet = MutableEchoRequestPacket::owned(icmp_buffer).unwrap();
                echo_request_packet.set_icmp_type(IcmpTypes::EchoRequest);
                echo_request_packet.set_identifier(self.ident);
                echo_request_packet.set_sequence_number(self.seq_num);
                // checksum needs to be set automatically
                // failing to set will have the traceroute run until exhaustion
                let p_checksum = checksum(&IcmpPacket::new(&echo_request_packet.packet()).unwrap());
                echo_request_packet.set_checksum(p_checksum);
                echo_request_packet.packet().to_owned()
            }
            AddressFamily::V6 => {
                let icmp_buffer = vec![00u8; ICMP_HEADER_LEN];
                let mut echo_request_packet = MutableIcmpv6Packet::owned(icmp_buffer).unwrap();
                echo_request_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                echo_request_packet.set_identifier(self.ident);
                echo_request_packet.set_sequence_number(self.seq_num);
                echo_request_packet.packet().to_owned()
            }
        }
    }

    fn unwrap_payload_ip_packet_in(&mut self, buf_in: &[u8]) -> IcmpPacketIn {
        let packet_in = match self.af {
            AddressFamily::V4 => IcmpPacketIn::V4(Ipv4Packet::owned(buf_in.to_owned()).unwrap()),
            // IPv6 holds IP header of incoming packet in ancillary data, so
            // we unpack the ICMPv6 packet directly here.
            AddressFamily::V6 => IcmpPacketIn::V6(Icmpv6Packet::owned(buf_in.to_owned()).unwrap()),
        };
        packet_in
    }

    fn analyse_v4_payload(
        &mut self,
        packet_out: &[u8],
        icmp_packet_in: &IcmpPacket,
        ip_payload: &[u8],
    ) -> Result<(), Error> {
        match icmp_packet_in.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let icmp_echo_reply = EchoReplyPacket::new(&ip_payload).unwrap();
                if icmp_echo_reply.get_identifier() == self.ident
                    && icmp_echo_reply.get_sequence_number() == self.seq_num
                {
                    self.done = true;
                    Ok(())
                } else {
                    Err(Error::new(ErrorKind::InvalidData, "invalid "))
                }
            }
            IcmpTypes::DestinationUnreachable => Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "destination unreachable",
            )),
            IcmpTypes::TimeExceeded => {
                // `Time Exceeded` packages do not have a identifier or sequence number
                // They do return up to 576 bytes of the original IP packet
                // So that's where we identify the packet to belong to this `packet_out`.
                if self.ttl == 255 {
                    self.done = true;
                    return Err(Error::new(ErrorKind::TimedOut, "too many hops"));
                }
                let icmp_time_exceeded = TimeExceededPacket::new(&ip_payload)
                    .unwrap()
                    .payload()
                    .to_owned();
                let wrapped_ip_packet = Ipv4Packet::new(&icmp_time_exceeded).unwrap();

                // We don't have any ICMP data right now
                // So we're only using the last 4 bytes in the payload to compare.
                match &self.proto {
                    &TraceProtocol::ICMP
                        if wrapped_ip_packet.payload()[4..8] == packet_out[4..8] =>
                    {
                        Ok(())
                    }
                    &TraceProtocol::UDP
                        if wrapped_ip_packet.payload()[8..16] == packet_out[..8] =>
                    {
                        Ok(())
                    }
                    _ => {
                        println!("{:?}", &wrapped_ip_packet.payload()[..64]);
                        println!("{:?}", &packet_out);
                        println!("{:?}", &icmp_packet_in.packet()[..64]);
                        Err(Error::new(
                            ErrorKind::InvalidData,
                            "invalid TimeExceeded packet",
                        ))
                    }
                }
            }
            _ => Err(Error::new(ErrorKind::Other, "unidentified packet type")),
        }
    }

    fn analyse_v6_payload(
        &mut self,
        packet_out: &[u8],
        icmp_packet_in: &Icmpv6Packet,
    ) -> Result<(), Error> {
        match icmp_packet_in.get_icmpv6_type() {
            Icmpv6Types::EchoReply => {
                //println!("icmp payload: {:02x}", icmp_packet_in.payload().as_hex());
                if icmp_packet_in.get_identifier() == self.ident
                    && icmp_packet_in.get_sequence_number() == self.seq_num
                {
                    self.done = true;
                    Ok(())
                } else {
                    //println!("seq: {:?}", icmp_packet_in.get_sequence_number());
                    Err(Error::new(ErrorKind::InvalidData, "invalid "))
                }
            }
            Icmpv6Types::DestinationUnreachable => Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "destination unreachable",
            )),
            Icmpv6Types::TimeExceeded => {
                //println!("time exceeded: {:02x}", icmp_packet_in.payload().as_hex());
                // `Time Exceeded` packages do not have a identifier or sequence number
                // They do return up to 576 bytes of the original IP packet
                // So that's where we identify the packet to belong to this `packet_out`.
                if self.ttl == 255 {
                    self.done = true;
                    return Err(Error::new(ErrorKind::TimedOut, "too many hops"));
                }
                let wrapped_ip_packet = Ipv6Packet::new(&icmp_packet_in.payload()).unwrap();
                //println!("unwrap ip: {:?}", wrapped_ip_packet);
                // We don't have any ICMP data right now
                // So we're only using the last 4 bytes in the payload to compare.
                if wrapped_ip_packet.payload()[4..8] == packet_out[4..8] {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        "invalid TimeExceeded packet",
                    ))
                }
            }
            _ => {
                println!("{:?}", icmp_packet_in.get_icmpv6_type());
                Err(Error::new(ErrorKind::Other, "unidentified packet type"))
            }
        }
    }

    fn set_ttl(&self, socket: &Socket) -> Result<u32, Error> {
        // In IPv6 IP_TTL is NOT called IPV6_TTL, but
        // IPV6_UNICAST_HOPS
        match self.af {
            AddressFamily::V4 => {
                //println!("socket ttl: {:?}", self.ttl);
                try!(socket.set_ttl(self.ttl));
                socket.ttl()
            }
            AddressFamily::V6 => {
                try!(socket.set_ipv6_unicast_hops(self.ttl));
                socket.ipv6_unicast_hops()
            }
        }
    }

    #[allow(unused_variables)]
    fn find_next_hop(&mut self) -> io::Result<TraceResult> {
        let socket_out = self.create_socket(true);
        socket_out.bind(&self.src_addr).unwrap();

        // let socket_in = match self.proto {
        //     TraceProtocol::ICMP => socket_out.try_clone().unwrap(),
        //     _ => {
        //         println!("creating incoming socket...");
        //         self.create_socket(false)
        //     }
        // };
        // try!(socket_in.set_nonblocking(false));
        // try!(socket_in.set_read_timeout(Some(self.timeout.to_std().unwrap())));

        loop {
            self.seq_num += 1;
            //let trace_hops = Vec::new();
            let mut trace_result = TraceResult {
                error: Err(Error::new(ErrorKind::Other, "-42")),
                hop: self.ttl,
                result: Vec::with_capacity(DEFAULT_TRT_COUNT as usize),
            };
            //let packet_out = self.make_echo_request_packet_out().to_owned();

            self.ttl += 1;
            let ttl = self.set_ttl(&socket_out);
            let mut trace_hops = Vec::with_capacity(DEFAULT_TRT_COUNT as usize);

            // After deadline passes, restart the loop to advance the TTL and resend.
            for count in 0..DEFAULT_TRT_COUNT {
                self.ident = rand::random();
                //println!("{:?}", self.ident);
                //self.seq_num = rand::random::<u16>();
                let icmp_out = self.make_echo_request_packet_out();
                let packet_out = icmp_out;
                println!(
                    "ttl: {:?}, seq: {:?}, id: {:?}",
                    self.ttl, self.seq_num, self.ident
                );
                let wrote = try!(socket_out.send_to(&packet_out, &<SockAddr>::from(self.dst_addr)));
                assert_eq!(wrote, packet_out.len());
                let start_time = SteadyTime::now();

                //while SteadyTime::now() < start_time + self.timeout {
                let mut read: Result<(usize, SockAddr, Duration), Error>;
                let sender: SockAddr;
                let packet_len: usize;
                let rtt: Duration;

                let mut buf_in = vec![0; MAX_PACKET_SIZE];
                while SteadyTime::now() < start_time + self.timeout {
                    let read = match self.socket_in.recv_from(buf_in.as_mut_slice()) {
                        Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                            // println!("{:?}", err);
                            //print!("* seq: {:?} count: {:?}) ", self.seq_num, count);
                            //trace_hops.push(Err(Error::new(ErrorKind::ConnectionAborted, "*")));
                            //let ten_millis = std::time::Duration::from_millis(10);
                            //std::thread::sleep(ten_millis);
                            //println!("{:?}", self.socket_in.recv_from(buf_in.as_mut_slice()));
                            continue;
                        }
                        Err(e) => {
                            //trace_hops.push(Err(e));
                            //return Err(e);
                            println!("error in rcv_from: {:?}", e);
                            Err(e)
                        }
                        Ok((len, s)) => {
                            Ok((len, s, SteadyTime::now() - start_time))
                            //break;
                        } //println!("*({:?},{:?}) ", self.seq_num, count);
                          //println!("count: {:?}, {:?} {:}", count, sender, rtt);
                    };

                    let (packet_len, sender, rtt) = match read {
                        Ok(recv) => recv,
                        _ => {
                            continue;
                        }
                    };

                    // The IP packet that wraps the incoming ICMP message.
                    let packet_in = self.unwrap_payload_ip_packet_in(&buf_in);

                    // TODO: unwrapping UDP return packets just doesn't work like this.
                    match packet_in {
                        IcmpPacketIn::V6(icmp_packet_in) => {
                            match self.analyse_v6_payload(&packet_out, &icmp_packet_in) {
                                Ok(()) => {
                                    let host = SocketAddr::V6(sender.as_inet6().unwrap());
                                    let hop = TraceHop {
                                        ttl: self.ttl,
                                        size: packet_len,
                                        host: host,
                                        hop_name: lookup_addr(&host.ip()).unwrap(),
                                        rtt: rtt,
                                    };
                                    trace_hops.push(Ok(hop))
                                }
                                Err(ref err)
                                    if err.kind() == ErrorKind::InvalidData
                                        || err.kind() == ErrorKind::Other =>
                                {
                                    println!("*");
                                    println!("{:?}", err);
                                    trace_hops
                                        .push(Err(Error::new(ErrorKind::InvalidData, "invalid ")));
                                    continue;
                                }
                                Err(e) => trace_hops.push(Err(e)),
                            }
                        }
                        IcmpPacketIn::V4(ip_packet_in) => {
                            let ip_payload = ip_packet_in.payload();
                            let icmp_packet_in = IcmpPacket::new(&ip_packet_in.payload()).unwrap();
                            match self.analyse_v4_payload(&packet_out, &icmp_packet_in, &ip_payload)
                            {
                                Ok(()) => {
                                    let host = SocketAddr::V4(sender.as_inet().unwrap());
                                    let hop = TraceHop {
                                        ttl: self.ttl,
                                        size: packet_len,
                                        host: host,
                                        hop_name: lookup_addr(&host.ip()).unwrap(),
                                        rtt: rtt,
                                    };
                                    trace_hops.push(Ok(hop))
                                }
                                err => {
                                    println!("* wut?");
                                    println!("{:?}", err);
                                    trace_hops.push(Err(Error::new(ErrorKind::Other, "invalid ")));
                                    //continue;
                                }
                            }
                        }
                    }
                }
            }
            trace_result.result = trace_hops;

            //self.result.push(&trace_result);
            return Ok(trace_result);
        }
    }
}

impl Iterator for TraceRoute {
    type Item = TraceResult;

    fn next(&mut self) -> Option<TraceResult> {
        if self.done {
            return None;
        }

        let trace_result = self.find_next_hop();

        // if trace_result.error.is_err {
        //     self.done = true;
        // }

        Some(trace_result.unwrap())
    }
}

/// Do traceroute
pub fn start<'a, T: ToSocketAddrs>(address: T) -> io::Result<TraceRoute> {
    sync_start_with_timeout(address, Duration::seconds(1))
}

/// Run-of-the-mill icmp ipv4/ipv6 traceroute implementation (for now)
// Completely synchronous. Every packet that's send will trigger a wait for its return
pub fn sync_start_with_timeout<'a, T: ToSocketAddrs>(
    address: T,
    timeout: Duration,
) -> io::Result<TraceRoute> {
    match timeout.num_microseconds() {
        None => return Err(Error::new(ErrorKind::InvalidInput, "Timeout too large")),
        Some(0) => return Err(Error::new(ErrorKind::InvalidInput, "Timeout too small")),
        _ => (),
    };

    const AF: AddressFamily = AddressFamily::V4;

    let socket_in = match AF {
        AddressFamily::V4 => {
            Socket::new(Domain::ipv4(), Type::raw(), Some(<Protocol>::icmpv4())).unwrap()
        }
        AddressFamily::V6 => {
            Socket::new(Domain::ipv6(), Type::raw(), Some(<Protocol>::icmpv6())).unwrap()
        }
    };

    socket_in
        .set_nonblocking(false)
        .expect("Cannot set socket to blocking mode");
    socket_in
        .set_read_timeout(Some(timeout.to_std().unwrap()))
        .expect("Cannot set read timeout on socket");

    let mut addr_iter = try!(address.to_socket_addrs());
    match addr_iter.next() {
        None => Err(Error::new(
            ErrorKind::InvalidInput,
            "Could not interpret address",
        )),
        Some(mut dst_addr) => {
            println!("dst_addr: {:?}", dst_addr);
            println!("timestamp: {:?}", time::get_time().sec);
            Ok({
                match dst_addr.is_ipv4() {
                    true => {
                        let src_addr = get_sock_addr(AddressFamily::V4);
                        dst_addr.set_port(DST_BASE_PORT);
                        TraceRoute {
                            src_addr: src_addr,
                            dst_addr: dst_addr,
                            af: AF,
                            proto: TraceProtocol::UDP,
                            ttl: 0,
                            ident: rand::random(),
                            seq_num: 0,
                            done: false,
                            timeout: timeout,
                            result: Vec::new(),
                            socket_in: socket_in,
                        }
                    }
                    false => {
                        let src_addr = get_sock_addr(AddressFamily::V6);
                        dst_addr.set_port(DST_BASE_PORT);
                        TraceRoute {
                            src_addr: src_addr,
                            dst_addr: dst_addr,
                            af: AF,
                            proto: TraceProtocol::UDP,
                            ttl: 0,
                            ident: rand::random(),
                            seq_num: 0,
                            done: false,
                            timeout: timeout,
                            result: Vec::new(),
                            socket_in: socket_in,
                        }
                    }
                }
            })
        }
    }
}
