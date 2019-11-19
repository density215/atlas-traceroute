#![feature(ip)]

extern crate byteorder;
extern crate dns_lookup;
extern crate hex_slice;
extern crate ipnetwork;
extern crate pnet;
extern crate rand;
extern crate socket2;
extern crate time;

use std::fmt;
use std::iter::Iterator;
use std::str::FromStr;

#[macro_use]
extern crate serde_derive;

extern crate serde;
extern crate serde_json;

use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, SocketAddrV4};
use std::net::{SocketAddr, SocketAddrV6, ToSocketAddrs};

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
use byteorder::{ByteOrder, NetworkEndian};
use hex_slice::AsHex;

const MAX_PACKET_SIZE: usize = 4096 + 128;
const ICMP_HEADER_LEN: usize = 8;
const UDP_HEADER_LEN: usize = 8;
const TCP_HEADER_LEN: usize = 40;
const SRC_BASE_PORT: u16 = 0x5000;
const DST_BASE_PORT: u16 = 0x8000 + 666;

#[derive(Debug, Clone, Copy)]
pub enum AddressFamily {
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
pub struct TraceRouteSpec {
    pub proto: TraceProtocol,
    pub af: Option<AddressFamily>, // might be empty, but could then be inferred from the dst_addr (if it's an IP address)
    pub start_ttl: u16,
    pub max_hops: u16,
    pub paris: Option<u8>,
    pub packets_per_hop: u8,
    pub tcp_dest_port: u16,
    pub timeout: i64,
    pub uuid: String,
    // this implementation specific options
    pub public_ip: Option<String>,
    pub verbose: bool,
}

#[derive(Debug)]
pub struct TraceRoute<'a> {
    dst_addr: SocketAddr,
    // af is based on either the user option, or from the
    // destination address if it was an IP address.
    af: AddressFamily,
    // inferred from user options
    spec: &'a TraceRouteSpec,
    // invariants for this tr
    src_addr: SockAddr,
    socket_in: Socket,
    // mutable state
    ttl: u16,
    ident: u16,
    seq_num: u16,
    done: bool,
    pub result: Vec<TraceResult>,
}

#[derive(Debug, Clone)]
pub struct HopTimeOutError {
    pub message: String,
    pub line: usize,
    pub column: usize,
}

pub type ResultVec = Vec<HopOrError>;

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

#[derive(Debug, Serialize)]
pub struct TraceResult {
    // This is a global error for all hops in this sequence
    #[serde(skip_serializing)]
    pub error: io::Result<Error>,
    pub hop: u8,
    pub result: Vec<HopOrError>,
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
        })
        .map(|a| a.ip())
        .nth(0)
        .unwrap();

    match interface {
        IpAddr::V4(addrv4) => <SockAddr>::from(SocketAddrV4::new(addrv4, port)),
        IpAddr::V6(addrv6) => <SockAddr>::from(SocketAddrV6::new(addrv6, port, 0, 0x0)),
    }
}

enum PacketType<'a> {
    UDP(UdpPacket<'a>),
    TCP(TcpPacket<'a>),
}

impl<'a> PacketType<'a> {
    fn checksum_for_af(&self, &src_ipaddr: &IpAddr, &dst_ipaddr: &IpAddr) -> u16 {
        match &self {
            PacketType::UDP(p) => match &src_ipaddr {
                IpAddr::V4(src_ip) => {
                    if let IpAddr::V4(dst_ip) = dst_ipaddr {
                        ipv4_checksum(&p, &src_ip, &dst_ip)
                    } else {
                        panic!("wrong ip address type, combination of ipv4 and ipv6");
                    }
                }
                IpAddr::V6(src_ip) => {
                    if let IpAddr::V6(dst_ip) = dst_ipaddr {
                        ipv6_checksum(&p, &src_ip, &dst_ip)
                    } else {
                        panic!("wrong ip address type, combination of ipv4 and ipv6");
                    }
                }
            },
            PacketType::TCP(p) => match &src_ipaddr {
                IpAddr::V4(src_ip) => {
                    if let IpAddr::V4(dst_ip) = dst_ipaddr {
                        tcp_ipv4_checksum(&p, &src_ip, &dst_ip)
                    } else {
                        panic!("wrong ip address type, combination of ipv4 and ipv6");
                    }
                }
                IpAddr::V6(src_ip) => {
                    if let IpAddr::V6(dst_ip) = dst_ipaddr {
                        tcp_ipv6_checksum(&p, &src_ip, &dst_ip)
                    } else {
                        panic!("wrong ip address type, combination of ipv4 and ipv6");
                    }
                }
            },
        }
    }
}

impl<'a> TraceRoute<'a> {
    // TODO: refactor to be only used for OUTGOING socket.
    fn create_socket(&self, out: bool) -> Socket {
        let af = &self.af;
        let protocol = match (out, &self.spec.proto) {
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

        let sock_type = match (out, &self.spec.proto) {
            (false, _) => Type::raw(),
            (true, &TraceProtocol::ICMP) => Type::raw(),
            (true, &TraceProtocol::UDP) => Type::raw(),
            (true, &TraceProtocol::TCP) => Type::raw(),
        };

        let socket_out = match af {
            &AddressFamily::V4 => Socket::new(Domain::ipv4(), sock_type, protocol).unwrap(),
            &AddressFamily::V6 => Socket::new(Domain::ipv6(), sock_type, protocol).unwrap(),
        };

        socket_out.set_reuse_address(true).unwrap();
        // disable nagle's algo
        socket_out.set_nodelay(true);

        // binding the src_addr makes sure no temporary
        // ipv6 addresses are created to send the packet.
        // Temporary ipv6 addresses (a privacy feature) will
        // result in wrong UDP/TCP checksums, since that
        // will use the secured IPv6 address of the interface
        // sending as the src_addr to calculate checksums with.
        socket_out.bind(&self.src_addr).unwrap();

        //println!("{:?}", self.src_addr);
        //socket_out.bind(&self.src_addr).unwrap();
        //let dst_addr = <SockAddr>::from(self.dst_addr);
        //socket_out.connect(&dst_addr).unwrap();
        // socket_out
        //     .set_nonblocking(false)
        //     .expect("Cannot set socket to blocking mode");
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
        let udp_buffer = vec![0x00; UDP_HEADER_LEN + 0x02];
        let mut udp_packet = MutableUdpPacket::owned(udp_buffer).unwrap();
        udp_packet.set_source(SRC_BASE_PORT);
        let src_ip_enum: IpAddr;
        let dst_ip_enum: IpAddr;

        match self.af {
            AddressFamily::V4 => {
                src_ip_enum = IpAddr::V4(
                    *self
                        .src_addr
                        .as_inet()
                        .expect("invalid source address")
                        .ip(),
                );
                dst_ip_enum = IpAddr::V4(
                    *<SockAddr>::from(self.dst_addr)
                        .as_inet()
                        .expect("invalid destination address")
                        .ip(),
                )
            }
            AddressFamily::V6 => {
                src_ip_enum = IpAddr::V6(
                    *self
                        .src_addr
                        .as_inet6()
                        .expect("invalid source address")
                        .ip(),
                );
                dst_ip_enum = IpAddr::V6(
                    *<SockAddr>::from(self.dst_addr)
                        .as_inet6()
                        .expect("invalid destination address")
                        .ip(),
                )
            }
        }

        match self.spec.paris {
            // 'classic' traceroute
            // uses the dst_port to fingerprint returning ICMP packets.
            // So for each hop the dst_port is increased with one,
            // so we can differentiate between them. easy.
            None => {
                println!("classic traceroute");
                udp_packet.set_destination(self.seq_num + DST_BASE_PORT);
            }
            // paris traceroute
            // paris traceroute tries to keep the five
            // tos, proto, src_addr, dst_addr, src_port, dst_port as
            // invariants between hops for UDP (TCP and ICMP traceroutes work diffrerently).
            // So this rules out the dst_port trick that 'classic' uses.
            // As an alternative strategy paris traceroute tries to vary the
            // checksum field between hops, thus using it as an identifier for a hop.
            // As a consequence the payload needs to be calculated to fit the desired checksum.
            //
            // Since I have no desire to reimplement the UDP checksum from scratch, let alone
            // implement the reverse algorithm (yeah, I know, not hard, one's complement and carry bit, yada, yada),
            // I've decided to first calculate a temporary checksum with the payload set to zero.
            // Then I can calculate by how much
            // the payload needs to increased to offset to the desired the checksum.
            // This is actually pretty easy, because if the pauyload is increased by 0x01,
            // the checksum goes down by 0x01...
            Some(paris_id) => {
                udp_packet.set_destination(DST_BASE_PORT);
                udp_packet.set_length(0x00);
                udp_packet.set_payload(&vec![0x00; 2]);
                let temp_checksum = PacketType::UDP(udp_packet.to_immutable())
                    .checksum_for_af(&src_ip_enum, &dst_ip_enum)
                    - 0x0a
                    - self.seq_num;
                if self.spec.verbose {
                    println!("paris traceroute (id): {:?}", self.spec.paris.unwrap());
                    println!("temp checksum (udp payload): {:02x}", temp_checksum);
                }
                udp_packet.set_payload(&temp_checksum.to_be_bytes());
            }
        }
        udp_packet.set_source(SRC_BASE_PORT);
        udp_packet.set_length(0x0a);
        let udp_checksum =
            PacketType::UDP(udp_packet.to_immutable()).checksum_for_af(&src_ip_enum, &dst_ip_enum);
        udp_packet.set_checksum(udp_checksum);
        if self.spec.verbose {
            println!("udp checksum: {:02x}", udp_checksum);
        }
        udp_packet.packet().to_owned()
    }

    fn make_tcp_packet_out(&self) -> Vec<u8> {
        let tcp_buffer: Vec<u8>;
        let src_ip_enum: IpAddr;
        let dst_ip_enum: IpAddr;

        match self.af {
            AddressFamily::V4 => {
                src_ip_enum = IpAddr::V4(
                    *self
                        .src_addr
                        .as_inet()
                        .expect("invalid source address")
                        .ip(),
                );
                dst_ip_enum = IpAddr::V4(
                    *<SockAddr>::from(self.dst_addr)
                        .as_inet()
                        .expect("invalid destination address")
                        .ip(),
                );
                tcp_buffer = vec![00u8; 40];
            }
            AddressFamily::V6 => {
                src_ip_enum = IpAddr::V6(
                    *self
                        .src_addr
                        .as_inet6()
                        .expect("invalid source address")
                        .ip(),
                );
                dst_ip_enum = IpAddr::V6(
                    *<SockAddr>::from(self.dst_addr)
                        .as_inet6()
                        .expect("invalid destination address")
                        .ip(),
                );
                tcp_buffer = vec![00u8; 22];
            }
        }
        let mut tcp_packet = MutableTcpPacket::owned(tcp_buffer).unwrap();
        let payload = &mut [00u8; 2];
        byteorder::NetworkEndian::write_u16(payload, self.ident);
        tcp_packet.set_sequence(self.seq_num.into());
        tcp_packet.set_payload(payload);
        // this seems to be a viable minimum (20 bytes of header length; ask wireshark)
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(SYN);
        tcp_packet.set_source(SRC_BASE_PORT);

        // Same paris traceroute story applies to TCP
        match self.spec.paris {
            None => {
                println!("classic traceroute");
                tcp_packet.set_destination(self.seq_num + self.spec.tcp_dest_port);
            }
            Some(paris_id) => {
                tcp_packet.set_destination(self.spec.tcp_dest_port);
                tcp_packet.set_payload(&vec![0x00; 2]);
                let temp_checksum = PacketType::TCP(tcp_packet.to_immutable())
                    .checksum_for_af(&src_ip_enum, &dst_ip_enum)
                    - 0x0a
                    - self.seq_num;
                if self.spec.verbose {
                    println!("paris traceroute (id): {:?}", self.spec.paris.unwrap());
                    println!("temp checksum (udp payload): {:02x}", temp_checksum);
                }
                tcp_packet.set_payload(&temp_checksum.to_be_bytes());
            }
        }

        let tcp_checksum = PacketType::TCP(TcpPacket::new(&tcp_packet.packet()).unwrap())
            .checksum_for_af(&src_ip_enum, &dst_ip_enum);
        tcp_packet.set_checksum(tcp_checksum);
        if self.spec.verbose {
            println!("tcp checksum: {:02x}", tcp_checksum);
            println!("packet created: {:02x}", &tcp_packet.packet().as_hex());
            println!("src used in checksum: {:?}", &src_ip_enum);
            println!("dst used in checksum: {:?}", &dst_ip_enum);
        }
        tcp_packet.packet().to_owned()
    }

    fn unwrap_payload_ip_packet_in(&mut self, buf_in: &[u8]) -> (IcmpPacketIn, u8) {
        if self.spec.verbose {
            match &buf_in[0] {
                0x45 => {
                    println!("src addr source packet: {:?}", &buf_in[12..16]);
                    println!("dst addr source packet: {:?}", &buf_in[16..20]);
                }
                _ => {
                    println!("src addr source packet: {:02x}", &buf_in[32..48].as_hex());
                    println!("dst addr source packet: {:02x}", &buf_in[16..32].as_hex());
                }
            };
        };

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
        // println!("wrapped ip packet: {:02x}", wrapped_ip_packet[..32].as_hex());

        // in TCP we witness that reflected packets are sometimes cutoff after 12 bytes,
        // and filled with zeros up till 4176 bytes (or less).
        // Another situation is that their length might be less than 12 bytes
        // sent out by us as a packet.
        // So we're taking *up to* 12 bytes of the reflected packet.
        // println!("{:02x}",wrapped_ip_packet[..packet_out.len()].as_hex());
        let wrapped_ip_snip: &[u8] = match packet_out.len() {
            l if l > 12 => &wrapped_ip_packet[..12],
            _ => &wrapped_ip_packet[..packet_out.len()],
        };
        // UDP paris traceroutes have to rely on the checksum of the udp header to match up the
        // hop number of the packet sent and the icmp packet received. However if our
        // machine is behind a NAT, then the router performning NAT will very likely rewrite
        // the UDP checksum of the outhoing packet to match the src IP address of the public ip
        // address, hence the --publicip option.
        // This process has no knowledge of the public ip address, so we have to rewrite
        // the expected IP packet to have the checksum reflect the public address as set by
        // the user.
        // Note that we're also checking if the incoming packet matches with our original
        // created outgoing packet, in case the user inappropriately set the public_ip property
        // in the spec. (like there's no NAT after all, or the public ip address is wrong).
        // Also note that this *only* applies to UDP paris traceroutes and even then only
        // if you want to sent packets in async/burst mode. In sync mode we sent one packet
        // and wait for the timeout per hop and matching the source ports in the udp header
        // is enough.

        let expected_packet = match self.spec.proto {
            TraceProtocol::UDP => {
                let mut udp_packet = MutableUdpPacket::owned(packet_out.to_vec()).unwrap();
                match &self.spec.public_ip {
                    Some(public_ip) => {
                        // let mut udp_packet = MutableUdpPacket::owned(packet_out.to_vec()).unwrap();
                        udp_packet.set_checksum(ipv4_checksum(
                            &udp_packet.to_immutable(),
                            // the public ip address used in NAT
                            // &<std::net::Ipv4Addr>::new(83,160,104,137),
                            // the IP of the if to send this packet out (no NAT)
                            &<std::net::Ipv4Addr>::from_str(public_ip).unwrap(),
                            // the dst of the traceroute
                            &<std::net::Ipv4Addr>::new(
                                icmp_packet_in[24],
                                icmp_packet_in[25],
                                icmp_packet_in[26],
                                icmp_packet_in[27],
                            ),
                        ));
                        udp_packet.packet().to_owned()
                    }
                    _ => packet_out.to_owned(),
                }
            }
            TraceProtocol::TCP => {
                let mut tcp_packet = MutableTcpPacket::owned(packet_out.to_vec()).unwrap();
                match &self.spec.public_ip {
                    Some(public_ip) => {
                        // let mut udp_packet = MutableUdpPacket::owned(packet_out.to_vec()).unwrap();
                        tcp_packet.set_checksum(tcp_ipv4_checksum(
                            &tcp_packet.to_immutable(),
                            // the public ip address used in NAT
                            // &<std::net::Ipv4Addr>::new(83,160,104,137),
                            // the IP of the if to send this packet out (no NAT)
                            &<std::net::Ipv4Addr>::from_str(public_ip).unwrap(),
                            // the dst of the traceroute
                            &<std::net::Ipv4Addr>::new(
                                icmp_packet_in[24],
                                icmp_packet_in[25],
                                icmp_packet_in[26],
                                icmp_packet_in[27],
                            ),
                        ));
                        if self.spec.verbose {
                            println!("checksum rewritten using dst_addr {:?}", &public_ip);
                        };
                        tcp_packet.packet().to_owned()
                    }
                    _ => packet_out.to_owned(),
                }
            }
            _ => packet_out.to_owned(),
        };

        if self.spec.verbose {
            self.debug_print_packet_in(&icmp_packet_in, &packet_out, &expected_packet);
        };

        match &self.spec.proto {
            &TraceProtocol::ICMP if wrapped_ip_packet[4..8] == packet_out[4..8] => Ok(()),
            /* Some routers may return all of the udp packet we sent, so including the
             * payload.
             */
            &TraceProtocol::UDP
                if wrapped_ip_packet.to_vec() == expected_packet
                    || wrapped_ip_packet == packet_out =>
            {
                if self.spec.verbose {
                    println!("😍 PERFECT MATCH (checksum, payload)");
                };
                Ok(())
            }
            /* This should be the 'normal' situation, where 8 bytes from the udp packet
             * we sent are returned, i.e. the udp header
             */
            &TraceProtocol::UDP
                if wrapped_ip_packet[..8] == expected_packet[..8]
                    || wrapped_ip_packet[..8] == packet_out[..8] =>
            {
                if self.spec.verbose {
                    println!("😁 CHECKSUM MATCH (no payload)");
                };
                Ok(())
            }
            // this from the atlas traceroute probes implentation:
            /* Unfortunately, cheap home routers may
             * forget to restore the checksum field
             * when they are doing NAT. Ignore the
             * sequence number if it seems wrong.
             */
            &TraceProtocol::UDP
                if wrapped_ip_packet[9..10] == expected_packet[9..10]
                    || wrapped_ip_packet[9..10] == packet_out[9..10] =>
            {
                if self.spec.verbose {
                    println!("😐 PAYLOAD AND SRC PORT MATCH ONLY (no checksum)");
                };
                Ok(())
            }
            // tnis might be a hop from an earlier probe, so then
            // dst_port should be higher than or equal to the udp base port
            // (a constant for now), but lower than UDP_BASE_PORT + this hopnr
            &TraceProtocol::UDP
                if self.spec.paris.is_none()
                    && NetworkEndian::read_u16(&wrapped_ip_packet[2..4]) >= DST_BASE_PORT
                    && NetworkEndian::read_u16(&wrapped_ip_packet[2..4])
                        <= DST_BASE_PORT + 0xff =>
            {
                println!("wrong hopno! earlier hop");
                Ok(())
            }
            // check to see if the source ports on the packet out and the reflected packet
            // match up. This is for classic sync traceroute only.
            &TraceProtocol::UDP
                if wrapped_ip_packet[2..4] == expected_packet[2..4]
                    || wrapped_ip_packet[2..4] == packet_out[2..4] =>
            {
                if self.spec.verbose {
                    println!("😐 SRC PORT MATCH ONLY (no payload, no checksum)");
                    println!("icmp packet in: {:02x}", icmp_packet_in[..64].as_hex());
                    println!(
                        "returned packet snip: {:02x}",
                        icmp_packet_in[28..36].as_hex()
                    );
                }
                Ok(())
            }
            &TraceProtocol::TCP
                if wrapped_ip_packet[..22] == expected_packet[..22]
                    || wrapped_ip_packet[..22] == packet_out[..22] =>
            {
                if self.spec.verbose {
                    println!("😍 PACKETS MATCHED");
                }
                Ok(())
            }
            &TraceProtocol::TCP if wrapped_ip_packet[4..8] == expected_packet[4..8] => {
                if self.spec.verbose {
                    println!("😁 SRC PORT AND SEQUENCE NUMBER MATCHED");
                }
                Ok(())
            }
            &TraceProtocol::TCP
                if wrapped_ip_packet[16..18] == expected_packet[16..18]
                    || wrapped_ip_packet[16..18] == packet_out[16..18] =>
            {
                if self.spec.verbose {
                    println!("😁 SRC PORT AND CHECKSUM MATCH (no sequence number, no payload)");
                };
                Ok(())
            }
            // see the above comment about cutting off of reflected ip packets
            &TraceProtocol::TCP if wrapped_ip_snip == &expected_packet[..wrapped_ip_snip.len()] => {
                if self.spec.verbose {
                    println!("😐 SRC AND DST PORT MATCH ONLY (no sequence number, no checksum, no payload)");
                }
                Ok(())
            }
            _ => {
                if self.spec.verbose {
                    println!("😠 UNIDENTIFIED INCOMING PACKET");
                    print!(
                        "packet out {:?}: {:02x}",
                        &self.spec.proto,
                        &packet_out.as_hex()
                    );
                    print!(" -> ");
                    println!("icmp payload: {:02x}", &wrapped_ip_packet[..64].as_hex());
                    println!(
                        "64b of icmp in packet: {:02x}",
                        &icmp_packet_in[..64].as_hex()
                    );
                };
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
                if self.ttl == self.spec.max_hops {
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
            _ => {
                if self.spec.verbose {
                    println!("unknown : {:02x}", &ip_payload.as_hex());
                };
                Err(Error::new(
                    ErrorKind::Other,
                    "unidentified packet type - ipv4",
                ))
            }
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
                if self.ttl == self.spec.max_hops {
                    self.done = true;
                    return Err(Error::new(ErrorKind::TimedOut, "too many hops"));
                }
                let wrapped_ip_packet = Ipv6Packet::new(&icmp_packet_in.payload()).unwrap();

                self.analyse_icmp_packet_in(
                    wrapped_ip_packet.payload(),
                    &icmp_packet_in.packet(),
                    packet_out,
                )
            }
            _ => {
                if self.spec.verbose {
                    println!("unknown : {:?}", icmp_packet_in.get_icmpv6_type());
                    println!(
                        "64b of icmp packet in : {:02x}",
                        &icmp_packet_in.payload()[..64].as_hex()
                    );
                };
                Err(Error::new(
                    ErrorKind::Other,
                    "unidentified packet type - ipv6",
                ))
            }
        }
    }

    fn set_ttl(&self, socket: &Socket) -> Result<u32, Error> {
        // In IPv6 IP_TTL is NOT called IPV6_TTL, but
        // IPV6_UNICAST_HOPS
        match self.af {
            AddressFamily::V4 => {
                //println!("socket ttl: {:?}", self.ttl);
                socket.set_ttl(self.ttl as u32)?;
                socket.ttl()
            }
            AddressFamily::V6 => {
                socket.set_unicast_hops_v6(self.ttl as u32)?;
                socket.unicast_hops_v6()
            }
        }
    }

    #[allow(unused_variables)]
    fn next_hop(&mut self) -> io::Result<TraceResult> {
        self.seq_num += 1;
        if self.spec.verbose {
            println!("==============");
            println!("START HOP {}", self.seq_num);
        }

        let mut trace_result = TraceResult {
            error: Err(Error::new(ErrorKind::Other, "-42")),
            hop: self.seq_num as u8,
            result: Vec::with_capacity(self.spec.packets_per_hop as usize),
        };

        self.ttl += 1;
        let mut trace_hops: Vec<HopOrError> =
            Vec::with_capacity(self.spec.packets_per_hop as usize);
        let socket_out = self.create_socket(true);
        socket_out.set_reuse_address(true)?;
        let src = get_sock_addr(&self.af, self.ident);

        //socket_out.bind(&src).unwrap();
        // socket_out.set_nonblocking(true).unwrap();

        'trt: for count in 0..self.spec.packets_per_hop {
            let ttl = self.set_ttl(&socket_out);
            self.ident = SRC_BASE_PORT - <u16>::from(rand::random::<u8>());
            let packet_out = match self.spec.proto {
                TraceProtocol::ICMP => self.make_icmp_packet_out(),
                TraceProtocol::UDP => self.make_udp_packet_out(),
                TraceProtocol::TCP => self.make_tcp_packet_out(),
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
            self.dst_addr.set_port(dst_port_for_hop);

            if self.spec.verbose {
                println!("dst_addr: {}", self.dst_addr.ip());
                println!(
                    "dst_addr port: {:?}/{:02x}",
                    &[self.dst_addr.port()],
                    &[self.dst_addr.port()].as_hex()
                );
                println!("local addr: {:?}", socket_out.local_addr());
            };
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
            let mut hop: HopOrError = HopOrError::HopError(HopTimeOutError {
                message: "hop timeout".to_string(),
                line: 0,
                column: 0,
            });

            // Set the read timeout on the socket will break out of the
            // 'timeout loop down here. We will need that if we're infering
            // timeouts while using a blocking mode socket.
            // Using nonblocking mode will have CPU go to 100%, unless we use epoll
            // which is in turn heavily platform specific, so we prefer blocking.
            self.socket_in
                .set_read_timeout(Some(Duration::seconds(self.spec.timeout).to_std().unwrap()));

            'timeout: while SteadyTime::now() < start_time + Duration::seconds(self.spec.timeout) {
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
                                hop = HopOrError::HopOk(TraceHop {
                                    ttl: ttl_in,
                                    size: packet_len,
                                    from: FromIp(host),
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
                                if self.spec.verbose {
                                    println!("Error occurred");
                                    println!("{:?}", err);
                                };
                                hop = HopOrError::HopError(HopTimeOutError {
                                    message: "*".to_string(),
                                    line: 0,
                                    column: 0,
                                });
                                // this packet might not be meant for this tracehop,
                                // so DO NOT break the while loop and listen for some
                                // other packet that might come in.
                                continue 'timeout;
                            }
                            Err(e) => trace_hops.push(HopOrError::HopError(HopTimeOutError {
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
                                hop = HopOrError::HopOk(TraceHop {
                                    ttl: ttl_in,
                                    size: packet_len,
                                    from: FromIp(host),
                                    hop_name: lookup_addr(&host.ip()).unwrap(),
                                    rtt: HopDuration(rtt),
                                });

                                break 'timeout;
                            }
                            err => {
                                if self.spec.verbose {
                                    println!("* Error occured");
                                    println!("{:?}", err);
                                }
                                hop = HopOrError::HopError(HopTimeOutError {
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

    fn debug_print_packet_in(&self, packet: &[u8], packet_out: &[u8], expected_udp_packet: &[u8]) {
        println!("-------------------------");
        println!("outgoing packet");
        println!("-------------------------");
        match &self.spec.proto {
            TraceProtocol::UDP => {
                println!("udp packet out: {:02x}", &packet_out.as_hex());
                println!("expected udp packet: {:02x}", &expected_udp_packet.as_hex());
            }
            TraceProtocol::TCP => {
                println!("tcp packet header out: {:02x}", &packet_out[..20].as_hex());
                println!("tcp payload out: {:02x}", &packet_out[20..].as_hex());
                println!(
                    "expected tcp header: {:02x}",
                    &expected_udp_packet[..20].as_hex()
                );
                println!(
                    "expected tcp payload: {:02x}",
                    &expected_udp_packet[20..].as_hex()
                );
            }
            _ => {
                println!("not implemented");
            }
        }
        println!("-------------------------");
        println!("incoming packet breakdown");
        println!("-------------------------");
        println!("icmp header: {:02x}", &packet[..8].as_hex());
        println!("icmp body");
        println!("---------");
        match &packet[8] {
            0x45 => {
                println!("ip header: {:02x}", &packet[8..28].as_hex());
                println!("src addr: {:?}", &packet[20..24]);
                println!("dst addr: {:?}", &packet[24..28]);
            }
            _ => {
                println!("ip header: {:02x}", &packet[8..48].as_hex());
                println!("src addr:  {:02x}", &packet[16..32].as_hex());
                println!("dst addr: {:02x}", &packet[32..48].as_hex());
            }
        };
        println!("ip payload");
        println!("----------");
        match &self.spec.proto {
            TraceProtocol::UDP => {
                println!("udp header: {:02x}", &packet[28..36].as_hex());
                println!("udp payload: {:02x}", &packet[36..38].as_hex());
            }
            TraceProtocol::TCP => {
                println!("tcp header: {:02x}", &packet[28..48].as_hex());
                println!("tcp payload: {:02x}", &packet[48..64].as_hex());
            }
            _ => {
                println!("not implemented");
            }
        }
        println!(
            "128 and beyond (mpls labels): {:02x}",
            &packet[136..148].as_hex()
        );
        println!("-----------");
    }
}

impl<'a> Iterator for TraceRoute<'a> {
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

/// Run-of-the-mill icmp ipv4/ipv6 traceroute implementation (for now)
// Completely synchronous. Every packet that's send will trigger a wait for its return
pub fn sync_start_with_timeout<'a, T: ToSocketAddrs>(
    address: T,
    spec: &'a TraceRouteSpec, // address: T,
                              // timeout: Duration
) -> io::Result<TraceRoute<'a>> {
    match Duration::seconds(spec.timeout).num_microseconds() {
        None => return Err(Error::new(ErrorKind::InvalidInput, "Timeout too large")),
        Some(0) => return Err(Error::new(ErrorKind::InvalidInput, "Timeout too small")),
        _ => (),
    };

    let mut addr_iter = address.to_socket_addrs()?;

    let mut dst_addr = match spec.af {
        // No address family was specified by the user
        // so get the first resolved address we can get our hands on.
        // That address will determine the address family.
        None => match addr_iter.next() {
            Some(addr) => addr,
            None => panic!("Cannot parse the resolved IP address(es) for requested hostname"),
        },
        Some(af) => addr_iter
            .find(|addr| match (addr, af) {
                (SocketAddr::V4(_), AddressFamily::V4) => true,
                (SocketAddr::V6(_), AddressFamily::V6) => true,
                _ => false,
            })
            .expect("Cannot match requested address family and destination address."),
    };

    println!("dst addr {:?}", &dst_addr);
    // TODO: for TCP there also needs to be a socket listening to Protocol TCP
    // to catch the SYN+ACK packet coming in from the destination.
    // which seems impossible to do in BSDs, so they would need to be caught at
    // the datalink layer (with libpcap I guess), so maybe we should do that for
    // all OSes (since we depend on lipcap anyway)?

    let src_addr;
    let socket_in;
    let af: AddressFamily;

    // figure out the address family from the destination address.
    match dst_addr {
        SocketAddr::V4(_) => {
            src_addr = get_sock_addr(&AddressFamily::V4, SRC_BASE_PORT);
            af = AddressFamily::V4;
            socket_in = Socket::new(Domain::ipv4(), Type::raw(), Some(<Protocol>::icmpv4()))?;
            dst_addr.set_port(DST_BASE_PORT)
        }
        SocketAddr::V6(_) => {
            src_addr = get_sock_addr(&AddressFamily::V6, SRC_BASE_PORT);
            af = AddressFamily::V6;
            socket_in = Socket::new(Domain::ipv6(), Type::raw(), Some(<Protocol>::icmpv6()))?;
            dst_addr.set_port(DST_BASE_PORT)
        }
    };

    socket_in.set_reuse_address(true).unwrap();
    socket_in
        .set_nonblocking(false)
        .expect("Cannot set socket to blocking mode");

    println!("af: IP{:?}", af);
    println!("src_addr: {:?}", src_addr);
    println!("dst_addr: {:?}", dst_addr);
    println!("timestamp: {:?}", time::get_time().sec);

    Ok({
        TraceRoute {
            src_addr: src_addr,
            dst_addr: dst_addr,
            af: af,
            spec: spec,
            ttl: spec.start_ttl,
            ident: rand::random(),
            seq_num: spec.start_ttl,
            done: false,
            result: Vec::new(),
            socket_in: socket_in,
        }
    })
}
