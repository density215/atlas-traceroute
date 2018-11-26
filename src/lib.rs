#![feature(ip)]

extern crate dns_lookup;
extern crate hex_slice;
extern crate ipnetwork;
extern crate pnet;
extern crate rand;
extern crate socket2;
extern crate time;

use std::fmt;
use std::iter::Iterator;

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, SocketAddrV4};
use std::net::{SocketAddr, SocketAddrV6, ToSocketAddrs};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

use serde::ser::{Serialize, SerializeStruct, Serializer};

use pnet::datalink::NetworkInterface;
use pnet::packet::icmp::checksum;
use pnet::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::ipv4_checksum as tcp_ipv4_checksum;
use pnet::packet::tcp::TcpFlags::SYN;
use pnet::packet::tcp::{ipv6_checksum as tcp_ipv6_checksum, MutableTcpPacket, TcpPacket};
use pnet::packet::udp::{ipv4_checksum, ipv6_checksum};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use time::{Duration, SteadyTime};

use dns_lookup::lookup_addr;
// only used for debug printing packets
use hex_slice::AsHex;

const MAX_PACKET_SIZE: usize = 4096 + 128;
const ICMP_HEADER_LEN: usize = 8;
const UDP_HEADER_LEN: usize = 8;
const SRC_BASE_PORT: u16 = 0x5000;
const DST_BASE_PORT: u16 = 0x8000 + 666;
const DEFAULT_TCP_DEST_PORT: u16 = 0x5000; // port 0x50 (80) is the actual UI default in Atlas.
const DEFAULT_TRT_COUNT: u8 = 3;
const PACKET_IN_TIMEOUT: i64 = 1;
const START_TTL: u16 = 0; // yeah,yeah, wasting a byte here, but we're going to sum this with DST_BASE_PORT

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
    ttl: u16,
    ident: u16,
    seq_num: u16,
    done: bool,
    timeout: Duration,
    pub result: Vec<TraceResult>,
    socket_in: Socket,
}

#[derive(Debug, Clone)]
pub struct HopTimeOutError {
    pub message: String,
    pub line: usize,
    pub column: usize,
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

#[derive(Debug, Serialize)]
pub struct TraceResult {
    // This is a global error for all hops in this sequence
    #[serde(skip_serializing)]
    pub error: io::Result<Error>,
    pub hop: u8,
    pub result: Vec<Result<TraceHop, HopTimeOutError>>,
}

#[derive(Debug)]
pub enum TraceProtocol {
    ICMP,
    UDP,
    TCP,
}

// To satisfy the coherency rules
// we wrap the hop rtt in a tuple-like struct.
// As always turns out that the compiler is right,
// this is actually better.
pub struct HopDuration(time::Duration);

#[derive(Debug, Serialize)]
pub struct TraceHop {
    /// IP address of the hophost
    pub from: SocketAddr,
    /// The resolved hostname
    pub hop_name: String,
    /// Time-to-live for this hop
    pub ttl: u8,
    /// Round-trip-time for this packet
    pub rtt: HopDuration,
    /// Size of the reply
    pub size: usize,
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

fn get_sock_addr<'a>(af: &AddressFamily, port: u16) -> SockAddr {
    let interfaces = pnet::datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.ips.len() > 0)
        .flat_map(|i| i.ips)
        // select the appropriate interface for the requested address family.
        .filter(|addr| match af {
            &AddressFamily::V4 => addr.is_ipv4() && !addr.ip().is_loopback(),
            &AddressFamily::V6 => addr.is_ipv6() && addr.ip().is_global(),
        }).map(|a| a.ip())
        .nth(0)
        .unwrap();

    match interface {
        IpAddr::V4(addrv4) => <SockAddr>::from(SocketAddrV4::new(addrv4, port)),
        IpAddr::V6(addrv6) => <SockAddr>::from(SocketAddrV6::new(addrv6, port, 0, 0x0)),
    }
}

impl TraceRoute {
    // TODO: refactor to be only used for OUTGOING socket.
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
            (true, &TraceProtocol::TCP) => Type::raw(),
        };

        let socket_out = match af {
            &AddressFamily::V4 => Socket::new(Domain::ipv4(), sock_type, protocol).unwrap(),
            &AddressFamily::V6 => Socket::new(Domain::ipv6(), sock_type, protocol).unwrap(),
        };
        socket_out.set_reuse_address(true).unwrap();
        //println!("{:?}", self.src_addr);
        //socket_out.bind(&self.src_addr).unwrap();
        //let dst_addr = <SockAddr>::from(self.dst_addr);
        //socket_out.connect(&dst_addr).unwrap();
        socket_out
            .set_nonblocking(true)
            .expect("Cannot set socket to blocking mode");
        // socket_out
        //     .set_read_timeout(Some(Duration::seconds(PACKET_IN_TIMEOUT).to_std().unwrap()))
        //     .expect("Cannot set read timeout on socket");
        socket_out
    }

    fn make_icmp_packet_out(&self) -> Vec<u8> {
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

    fn make_udp_packet_out(&self) -> Vec<u8> {
        match self.af {
            AddressFamily::V4 => {
                let src_ip = self
                    .src_addr
                    .as_inet()
                    .expect("invalid source address")
                    .ip()
                    .clone();
                let dst_ip = <SockAddr>::from(self.dst_addr)
                    .as_inet()
                    .expect("invalid destination address")
                    .ip()
                    .clone();
                let udp_buffer = vec![00u8; UDP_HEADER_LEN];
                let mut udp_packet = MutableUdpPacket::owned(udp_buffer).unwrap();
                udp_packet.set_source(self.ident);
                udp_packet.set_destination(self.seq_num + DST_BASE_PORT);
                udp_packet.set_length(0x00);
                //The `official` udp checksum
                let udp_checksum = ipv4_checksum(
                    &UdpPacket::new(&udp_packet.packet()).unwrap(),
                    &src_ip,
                    &dst_ip,
                );
                udp_packet.set_checksum(udp_checksum);
                udp_packet.packet().to_owned()
            }
            AddressFamily::V6 => {
                let src_ip = self
                    .src_addr
                    .as_inet6()
                    .expect("invalid source address")
                    .ip()
                    .clone();
                let dst_ip = <SockAddr>::from(self.dst_addr)
                    .as_inet6()
                    .expect("invalid destination address")
                    .ip()
                    .clone();
                let udp_buffer = vec![00u8; UDP_HEADER_LEN];
                let mut udp_packet = MutableUdpPacket::owned(udp_buffer).unwrap();
                udp_packet.set_source(SRC_BASE_PORT);
                udp_packet.set_destination(DST_BASE_PORT);
                let udp_checksum = ipv6_checksum(
                    &UdpPacket::new(&udp_packet.packet()).unwrap(),
                    &src_ip,
                    &dst_ip,
                );
                udp_packet.set_checksum(udp_checksum);
                udp_packet.packet().to_owned()
            }
        }
    }

    fn make_tcp_packet_out(&self) -> Vec<u8> {
        match self.af {
            AddressFamily::V4 => {
                let src_ip = self
                    .src_addr
                    .as_inet()
                    .expect("invalid source address")
                    .ip()
                    .clone();
                let dst_ip = <SockAddr>::from(self.dst_addr)
                    .as_inet()
                    .expect("invalid destination address")
                    .ip()
                    .clone();
                // TODO: this stuff no work. with header length and shit.
                let tcp_buffer = vec![00u8; 40];
                let mut tcp_packet = MutableTcpPacket::owned(tcp_buffer).unwrap();
                tcp_packet.set_data_offset(5);
                tcp_packet.set_flags(SYN);
                tcp_packet.set_source(SRC_BASE_PORT);
                tcp_packet.set_destination(DEFAULT_TCP_DEST_PORT);
                //tcp_packet.packet_size(0x00);
                //The `official` tcp checksum
                let tcp_checksum = tcp_ipv4_checksum(
                    &TcpPacket::new(&tcp_packet.packet()).unwrap(),
                    &src_ip,
                    &dst_ip,
                );
                tcp_packet.set_checksum(tcp_checksum);
                tcp_packet.packet().to_owned()
            }
            // TODO: Make this TCP. This is not tcp at all, this is just
            // a copy of the V6 udp tr
            AddressFamily::V6 => {
                let src_ip = self
                    .src_addr
                    .as_inet6()
                    .expect("invalid source address")
                    .ip()
                    .clone();
                let dst_ip = <SockAddr>::from(self.dst_addr)
                    .as_inet6()
                    .expect("invalid destination address")
                    .ip()
                    .clone();
                let udp_buffer = vec![00u8; UDP_HEADER_LEN];
                let mut udp_packet = MutableUdpPacket::owned(udp_buffer).unwrap();
                udp_packet.set_source(SRC_BASE_PORT);
                udp_packet.set_destination(DST_BASE_PORT);
                let udp_checksum = ipv6_checksum(
                    &UdpPacket::new(&udp_packet.packet()).unwrap(),
                    &src_ip,
                    &dst_ip,
                );
                udp_packet.set_checksum(udp_checksum);
                udp_packet.packet().to_owned()
            }
        }
    }

    fn unwrap_payload_ip_packet_in(&mut self, buf_in: &[u8]) -> (IcmpPacketIn, u8) {
        //println!("64b of raw packet in: {:02x}", buf_in[..64].as_hex());
        let ttl_in: u8;
        match self.af {
            AddressFamily::V4 => {
                let pack = Ipv4Packet::owned(buf_in.to_owned()).unwrap();
                ttl_in = pack.get_ttl();
                (IcmpPacketIn::V4(pack), ttl_in)
            }
            // IPv6 holds IP header of incoming packet in ancillary data, so
            // we unpack the ICMPv6 packet directly here.
            AddressFamily::V6 => {
                let icmp_pack = Icmpv6Packet::owned(buf_in.to_owned()).unwrap();
                let ip_pack = Ipv6Packet::owned(buf_in.to_owned()).unwrap();
                (IcmpPacketIn::V6(icmp_pack), ip_pack.get_hop_limit())
            }
        }
    }

    fn analyse_icmp_packet_in(
        &self,
        wrapped_ip_packet: &[u8],
        icmp_packet_in: &[u8],
        packet_out: &[u8],
    ) -> Result<(), Error> {
        // We don't have any ICMP header data right now
        // So we're only using the last 4 bytes in the payload to compare.
        match &self.proto {
            &TraceProtocol::ICMP if wrapped_ip_packet[4..8] == packet_out[4..8] => Ok(()),
            &TraceProtocol::UDP if wrapped_ip_packet[8..16] == packet_out[..8] => Ok(()),
            /* Unfortunately, cheap home routers may
             * forget to restore the checksum field
             * when they are doing NAT. Ignore the
             * sequence number if it seems wrong.
             */
            &TraceProtocol::UDP if wrapped_ip_packet[..4] == packet_out[..4] => {
                println!("checksum invalid - ignoring");

                print!("packet out {:?}: {:02x}", &self.proto, &packet_out.as_hex());
                print!(" -> ");
                println!("icmp payload: {:02x}", &wrapped_ip_packet[..8].as_hex());
                println!(
                    "64b of icmp in packet: {:02x}",
                    &icmp_packet_in[..8].as_hex()
                );

                Ok(())
            }
            &TraceProtocol::UDP if icmp_packet_in[28..36] == wrapped_ip_packet[..8] => Ok(()),
            &TraceProtocol::TCP if wrapped_ip_packet[..12] == packet_out[..12] => Ok(()),
            _ => {
                print!("packet out {:?}: {:02x}", &self.proto, &packet_out.as_hex());
                print!(" -> ");
                println!("icmp payload: {:02x}", &wrapped_ip_packet[..64].as_hex());
                println!(
                    "64b of icmp in packet: {:02x}",
                    &icmp_packet_in[..64].as_hex()
                );
                Err(Error::new(
                    ErrorKind::InvalidData,
                    "invalid TimeExceeded packet",
                ))
            }
        }
    }

    fn analyse_v4_payload(
        &mut self,
        packet_out: &[u8],
        icmp_packet_in: &IcmpPacket,
        ip_payload: &[u8],
    ) -> Result<(), Error> {
        match icmp_packet_in.get_icmp_type() {
            IcmpTypes::TimeExceeded => {
                // This is where intermediate packets with TTL set to lower than the number of hops
                // to the final server should be answered as.
                //
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
                self.analyse_icmp_packet_in(
                    wrapped_ip_packet.payload(),
                    &icmp_packet_in.packet(),
                    packet_out,
                )
            }

            // If the outgoing packet was icmp then the final
            // packages from the requested server should come as ICMP type Echo Reply
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

            // UDP and TCP packets that were send out should get these as the final answer,
            // that is, only if the requested server does not listen on the destination port!
            IcmpTypes::DestinationUnreachable => {
                self.done = true;

                let dest_unreachable = DestinationUnreachablePacket::new(&ip_payload)
                    .unwrap()
                    .payload()
                    .to_owned();
                let wrapped_ip_packet = Ipv4Packet::new(&dest_unreachable).unwrap();
                //println!("{:02x}", wrapped_ip_packet.packet().as_hex());
                self.analyse_icmp_packet_in(
                    wrapped_ip_packet.payload(),
                    &icmp_packet_in.packet(),
                    packet_out,
                )
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
                self.analyse_icmp_packet_in(
                    wrapped_ip_packet.payload(),
                    &icmp_packet_in.packet(),
                    packet_out,
                )
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
                try!(socket.set_ttl(self.ttl as u32));
                socket.ttl()
            }
            AddressFamily::V6 => {
                try!(socket.set_unicast_hops_v6(self.ttl as u32));
                socket.unicast_hops_v6()
            }
        }
    }

    #[allow(unused_variables)]
    fn next_hop(&mut self) -> io::Result<TraceResult> {
        self.seq_num += 1;
        let mut trace_result = TraceResult {
            error: Err(Error::new(ErrorKind::Other, "-42")),
            hop: self.seq_num as u8,
            result: Vec::with_capacity(DEFAULT_TRT_COUNT as usize),
        };

        self.ttl += 1;
        let mut trace_hops: Vec<Result<TraceHop, HopTimeOutError>> =
            Vec::with_capacity(DEFAULT_TRT_COUNT as usize);
        let socket_out = self.create_socket(true);
        socket_out.set_reuse_address(true).unwrap();
        let src = get_sock_addr(&self.af, self.ident);

        //socket_out.bind(&src).unwrap();
        socket_out.set_nonblocking(true).unwrap();

        'trt: for count in 0..DEFAULT_TRT_COUNT {
            let ttl = self.set_ttl(&socket_out);
            self.ident = SRC_BASE_PORT - <u16>::from(rand::random::<u8>());
            let packet_out = match self.proto {
                TraceProtocol::ICMP => self.make_icmp_packet_out(),
                TraceProtocol::UDP => self.make_udp_packet_out(),
                TraceProtocol::TCP => self.make_tcp_packet_out(),
            };
            // println!(
            //     "ttl: {:?}, seq: {:?}, id: {:02x}",
            //     self.ttl,
            //     self.seq_num,
            //     &[self.ident].as_hex()
            // );

            let dst_port_for_hop = match self.proto {
                TraceProtocol::ICMP => self.seq_num + DST_BASE_PORT,
                TraceProtocol::UDP => self.seq_num + DST_BASE_PORT,
                TraceProtocol::TCP => DEFAULT_TCP_DEST_PORT
            };
            self.dst_addr.set_port(dst_port_for_hop);
            println!("dst_addr port: {:02x}", &[self.dst_addr.port()].as_hex());
            let wrote = socket_out.send_to(&packet_out, &<SockAddr>::from(self.dst_addr))?;
            assert_eq!(wrote, packet_out.len());
            let start_time = SteadyTime::now();

            let mut read: Result<(usize, SockAddr, Duration), Error>;
            let sender: SockAddr;
            let packet_len: usize;
            let rtt: Duration;

            let mut buf_in = vec![0; MAX_PACKET_SIZE];

            // If hop is not overwritten with a TraceHop struct within the while loop below
            // then the result will be a timed-out error
            let mut hop: Result<TraceHop, HopTimeOutError> = Err(HopTimeOutError {
                message: "hop timeout".to_string(),
                line: 0,
                column: 0,
            });

            'timeout: while SteadyTime::now() < start_time + self.timeout {
                // let read_tcp = match socket_out.recv_from(buf_in.as_mut_slice()) {
                //     Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                //         //println!("blup!");
                //         continue 'timeout;
                //     }
                //     Err(e) => {
                //         println!("error in rcv_from: {:?}", e);
                //         Err(e)
                //     }
                //     Ok((len, s)) => {
                //         println!("got a tcp packet");
                //         Ok((len, s, SteadyTime::now() - start_time))
                //     }
                // };

                let read = match self.socket_in.recv_from(buf_in.as_mut_slice()) {
                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                        //println!("blip!");
                        continue 'timeout;
                    }
                    Err(e) => {
                        //println!("error in rcv_from: {:?}", e);
                        Err(e)
                    }
                    Ok((len, s)) => Ok((len, s, SteadyTime::now() - start_time)),
                };

                let (packet_len, sender, rtt) = match read {
                    Ok(recv) => recv,
                    _ => {
                        continue 'timeout;
                    }
                };

                // The IP packet that wraps the incoming ICMP message.
                let (packet_in, ttl_in) = self.unwrap_payload_ip_packet_in(&buf_in);

                match packet_in {
                    IcmpPacketIn::V6(icmp_packet_in) => {
                        match self.analyse_v6_payload(&packet_out, &icmp_packet_in) {
                            Ok(()) => {
                                let host = SocketAddr::V6(sender.as_inet6().unwrap());
                                hop = Ok(TraceHop {
                                    ttl: ttl_in,
                                    size: packet_len,
                                    from: host,
                                    hop_name: lookup_addr(&host.ip()).unwrap(),
                                    rtt: HopDuration(rtt),
                                });
                                // we've got a positive result,
                                // so break out of the while loop
                                break 'timeout;
                            }
                            Err(ref err)
                                if err.kind() == ErrorKind::InvalidData
                                    || err.kind() == ErrorKind::Other =>
                            {
                                println!("*");
                                println!("{:?}", err);
                                hop = Err(HopTimeOutError {
                                    message: "*".to_string(),
                                    line: 0,
                                    column: 0,
                                });
                                // this packet might not be meant for this tracehop,
                                // so DO NOT break the while loop and listen for some
                                // other packet that might come in.
                                continue 'timeout;
                            }
                            Err(e) => trace_hops.push(Err(HopTimeOutError {
                                message: e.to_string(),
                                line: 0,
                                column: 0,
                            })),
                        }
                    }
                    IcmpPacketIn::V4(ip_packet_in) => {
                        let ip_payload = ip_packet_in.payload();
                        let icmp_packet_in = IcmpPacket::new(&ip_packet_in.payload()).unwrap();
                        match self.analyse_v4_payload(&packet_out, &icmp_packet_in, &ip_payload) {
                            Ok(()) => {
                                let host = SocketAddr::V4(sender.as_inet().unwrap());
                                hop = Ok(TraceHop {
                                    ttl: ttl_in,
                                    size: packet_len,
                                    from: host,
                                    hop_name: lookup_addr(&host.ip()).unwrap(),
                                    rtt: HopDuration(rtt),
                                });
                                break 'timeout;
                            }
                            err => {
                                println!("* wut?");
                                println!("{:?}", err);
                                hop = Err(HopTimeOutError {
                                    message: "* wut?".to_string(),
                                    line: 0,
                                    column: 0,
                                });
                                continue 'timeout;
                            }
                        }
                    }
                }
            }
            trace_hops.push(hop);
        }
        trace_result.result = trace_hops;
        Ok(trace_result)
    }
}

impl Iterator for TraceRoute {
    type Item = io::Result<TraceResult>;

    fn next(&mut self) -> Option<io::Result<TraceResult>> {
        if self.done {
            return None;
        }

        let trace_result = match self.next_hop() {
            Ok(r) => Result::Ok(r),
            Err(e) => {
                // This is a fatal condition,
                // probably a socket that cannot be opened,
                // or a packet that just gets stuck on its way out of localhost.
                // gracefully end all this.
                self.done = true;
                Result::Err(e)
            }
        };

        Some(trace_result)
    }
}

/// Do traceroute
pub fn start<'a, T: ToSocketAddrs>(address: T) -> io::Result<TraceRoute> {
    sync_start_with_timeout(address, Duration::seconds(PACKET_IN_TIMEOUT))
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

    let mut addr_iter = address.to_socket_addrs()?.peekable();
    let mut addr_iter_first = match addr_iter.peek() {
        Some(&addr) => addr,
        None => panic!("Cannot parse the resolved IP address(es) for requested hostname"),
    };

    println!("{:?}", &addr_iter_first);
    // TODO: for TCP there also needs to be a socket listening to Protocol TCP
    // to catch the SYN+ACK packet coming in from the destination.
    // which seems impossible to do in BSDs, so they would need to be caught at
    // the datalink layer (with libpcap I guess), so maybe we should do that for
    // all OSes (since we depend on lipcap anyway)?

    // create a socket based on the address family of the specified destination address.
    // let socket_in = match &addr_iter_first {
    //     SocketAddr::V4(_) => Socket::new(Domain::ipv4(), Type::raw(), Some(<Protocol>::icmpv4()))?,
    //     SocketAddr::V6(_) => Socket::new(Domain::ipv6(), Type::raw(), Some(<Protocol>::icmpv6()))?,
    // };

    // let mut addr_iter = address.to_socket_addrs()?;
    let src_addr;
    let af;
    let socket_in;

    // match addr_iter_first {
    //     None => Err(Error::new(
    //         ErrorKind::InvalidInput,
    //         "Could not interpret address",
    //     )),
    //     Some(mut dst_addr) => {
    match addr_iter_first {
        SocketAddr::V4(_) => {
            src_addr = get_sock_addr(&AddressFamily::V4, SRC_BASE_PORT);
            af = AddressFamily::V4;
            socket_in = Socket::new(Domain::ipv4(), Type::raw(), Some(<Protocol>::icmpv4()))?;
            addr_iter_first.set_port(DST_BASE_PORT)
        }
        SocketAddr::V6(_) => {
            src_addr = get_sock_addr(&AddressFamily::V6, SRC_BASE_PORT);
            af = AddressFamily::V6;
            socket_in = Socket::new(Domain::ipv6(), Type::raw(), Some(<Protocol>::icmpv6()))?;
            addr_iter_first.set_port(DST_BASE_PORT)
        }
    };

    socket_in.set_reuse_address(true).unwrap();
    socket_in
        .set_nonblocking(true)
        .expect("Cannot set socket to blocking mode");
    // socket_in
    //     .set_read_timeout(Some(timeout.to_std().unwrap()))
    //     .expect("Cannot set read timeout on socket");

    println!("af: IP{:?}", af);
    println!("src_addr: {:?}", src_addr);
    println!("dst_addr: {:?}", addr_iter_first);
    println!("timestamp: {:?}", time::get_time().sec);

    Ok({
        TraceRoute {
            src_addr: src_addr,
            dst_addr: addr_iter_first,
            af: af,
            ttl: START_TTL,
            ident: rand::random(),
            seq_num: START_TTL,
            done: false,
            timeout: timeout,
            result: Vec::new(),
            socket_in: socket_in,
        }
    })
}
// }
// }
