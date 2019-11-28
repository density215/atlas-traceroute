use byteorder;
use dns_lookup;
use hex_slice;
use pnet;
use rand;
use socket2;
use time;

use std::fmt;
// use std::iter::Iterator;
use std::str::FromStr;

use socket2::{SockAddr, Socket};
use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};

use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};

use pnet::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::{checksum, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types, MutableIcmpv6Packet};
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

use super::debug::debug_print_packet_in;
use super::start::{TraceProtocol, TraceRouteSpec};

use crate::rawsocket::async_std::RawSocket;

use async_std::future;
use async_std::pin::Pin;
use async_std::prelude::*;
use async_std::stream::Stream;
use async_std::task::{Context, Poll};
use futures::{
    future::{Fuse, FusedFuture, FutureExt},
    pin_mut, select,
    stream::{FusedStream, FuturesUnordered, StreamExt},
};

pub const MAX_PACKET_SIZE: usize = 4096 + 128;
pub const ICMP_HEADER_LEN: usize = 8;
pub const UDP_HEADER_LEN: usize = 8;
pub const TCP_HEADER_LEN: usize = 40;
pub const SRC_BASE_PORT: u16 = 0x5000;
pub const DST_BASE_PORT: u16 = 0x8000 + 666;

enum IcmpPacketIn {
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

// impl fmt::Debug for Vec<Box<dyn Future<Output = HopOrError>>> {
//     fn fmt(&self, f: &mut fmt::Formatter<'_>) {
//         println!("fck off");
//     }
// }

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
    pub result_buf: &'a HopFutures, //Vec::with_capacity((spec.max_hops * spec.packets_per_hop as u16) as usize),
}

// pub proto: TraceProtocol,
// --pub af: Option<AddressFamily>, // might be empty, but could then be inferred from the dst_addr (if it's an IP address)
// --pub start_ttl: u16,
// pub max_hops: u16,
// pub paris: Option<u8>,
// pub packets_per_hop: u8,
// pub tcp_dest_port: u16,
// pub timeout: i64,
// --pub uuid: String,
// // this implementation specific options
// pub public_ip: Option<String>,
// pub verbose: bool,

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
        result_buf: &'a HopFutures,
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
            result_buf: result_buf,
            socket_in: socket_in,
            socket_out: socket_out,
        }
    }

    fn make_icmp_packet_out(&self) -> Vec<u8> {
        match &self.src_addr {
            &SocketAddr::V4(_) => {
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
            &SocketAddr::V6(_) => {
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
        let src_ip: IpAddr = self.src_addr.ip();
        let dst_ip: IpAddr = self.dst_addr.ip();

        match self.spec.paris {
            // 'classic' traceroute
            // uses the dst_port to fingerprint returning ICMP packets.
            // So for each hop the dst_port is increased with one,
            // so we can differentiate between them. easy.
            None => {
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
            Some(_paris_id) => {
                udp_packet.set_destination(DST_BASE_PORT);
                udp_packet.set_length(0x00);
                udp_packet.set_payload(&vec![0x00; 2]);
                let temp_checksum = PacketType::UDP(udp_packet.to_immutable())
                    .checksum_for_af(&src_ip, &dst_ip)
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
            PacketType::UDP(udp_packet.to_immutable()).checksum_for_af(&src_ip, &dst_ip);
        udp_packet.set_checksum(udp_checksum);
        if self.spec.verbose {
            println!("udp checksum: {:02x}", udp_checksum);
        }
        udp_packet.packet().to_owned()
    }

    fn make_tcp_packet_out(&self) -> Vec<u8> {
        let tcp_buffer: Vec<u8>;
        let src_ip: &IpAddr = &self.src_addr.ip();
        let dst_ip: &IpAddr = &self.dst_addr.ip();

        match &self.src_addr {
            SocketAddr::V4(_) => {
                tcp_buffer = vec![00u8; TCP_HEADER_LEN];
            }
            SocketAddr::V6(_) => {
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
            Some(_paris_id) => {
                tcp_packet.set_destination(self.spec.tcp_dest_port);
                tcp_packet.set_payload(&vec![0x00; 2]);
                let temp_checksum = PacketType::TCP(tcp_packet.to_immutable())
                    .checksum_for_af(src_ip, dst_ip)
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
            .checksum_for_af(src_ip, dst_ip);
        tcp_packet.set_checksum(tcp_checksum);
        if self.spec.verbose {
            println!("tcp checksum: {:02x}", tcp_checksum);
            println!("packet created: {:02x}", &tcp_packet.packet().as_hex());
            println!("src used in checksum: {:?}", src_ip);
            println!("dst used in checksum: {:?}", dst_ip);
        }
        tcp_packet.packet().to_owned()
    }

    fn unwrap_payload_ip_packet_in(&self, buf_in: &[u8]) -> (IcmpPacketIn, u8) {
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
        match &self.src_addr {
            SocketAddr::V4(_) => {
                let pack = Ipv4Packet::owned(buf_in.to_owned()).unwrap();
                ttl_in = pack.get_ttl();
                (IcmpPacketIn::V4(pack), ttl_in)
            }
            // IPv6 holds IP header of incoming packet in ancillary data, so
            // we unpack the ICMPv6 packet directly here.
            SocketAddr::V6(_) => {
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
            debug_print_packet_in(
                &self.spec.proto,
                &icmp_packet_in,
                &packet_out,
                &expected_packet,
            );
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
        &self,
        packet_out: &[u8],
        icmp_packet_in: &IcmpPacket,
        ip_payload: &[u8],
    ) -> (Result<(), Error>, bool) {
        match icmp_packet_in.get_icmp_type() {
            IcmpTypes::TimeExceeded => {
                // This is where intermediate packets with TTL set to lower than the number of hops
                // to the final server should be answered as.
                //
                // `Time Exceeded` packages do not have a identifier or sequence number
                // They do return up to 576 bytes of the original IP packet
                // So that's where we identify the packet to belong to this `packet_out`.
                if self.ttl == self.spec.max_hops {
                    // self.done = true;
                    return (Err(Error::new(ErrorKind::TimedOut, "too many hops")), true);
                }
                let icmp_time_exceeded = TimeExceededPacket::new(&ip_payload)
                    .unwrap()
                    .payload()
                    .to_owned();
                let wrapped_ip_packet = Ipv4Packet::new(&icmp_time_exceeded).unwrap();

                // We don't have any ICMP data right now
                // So we're only using the last 4 bytes in the payload to compare.
                (
                    self.analyse_icmp_packet_in(
                        wrapped_ip_packet.payload(),
                        &icmp_packet_in.packet(),
                        packet_out,
                    ),
                    false,
                )
            }

            // If the outgoing packet was icmp then the final
            // packages from the requested server should come as ICMP type Echo Reply
            IcmpTypes::EchoReply => {
                let icmp_echo_reply = EchoReplyPacket::new(&ip_payload).unwrap();
                if icmp_echo_reply.get_identifier() == self.ident
                    && icmp_echo_reply.get_sequence_number() == self.seq_num
                {
                    // self.done = true;
                    (Ok(()), true)
                } else {
                    (Err(Error::new(ErrorKind::InvalidData, "invalid ")), false)
                }
            }

            // UDP and TCP packets that were send out should get these as the final answer,
            // that is, only if the requested server does not listen on the destination port!
            IcmpTypes::DestinationUnreachable => {
                // self.done = true;

                let dest_unreachable = DestinationUnreachablePacket::new(&ip_payload)
                    .unwrap()
                    .payload()
                    .to_owned();
                let wrapped_ip_packet = Ipv4Packet::new(&dest_unreachable).unwrap();
                //println!("{:02x}", wrapped_ip_packet.packet().as_hex());
                (
                    self.analyse_icmp_packet_in(
                        wrapped_ip_packet.payload(),
                        &icmp_packet_in.packet(),
                        packet_out,
                    ),
                    true,
                )
            }
            _ => {
                if self.spec.verbose {
                    println!("unknown : {:02x}", &ip_payload.as_hex());
                };
                (
                    Err(Error::new(
                        ErrorKind::Other,
                        "unidentified packet type - ipv4",
                    )),
                    false,
                )
            }
        }
    }

    fn analyse_v6_payload(
        &self,
        packet_out: &[u8],
        icmp_packet_in: &Icmpv6Packet,
    ) -> (Result<(), Error>, bool) {
        match icmp_packet_in.get_icmpv6_type() {
            Icmpv6Types::EchoReply => {
                //println!("icmp payload: {:02x}", icmp_packet_in.payload().as_hex());
                if icmp_packet_in.get_identifier() == self.ident
                    && icmp_packet_in.get_sequence_number() == self.seq_num
                {
                    // self.done = true;
                    (Ok(()), true)
                } else {
                    //println!("seq: {:?}", icmp_packet_in.get_sequence_number());
                    (Err(Error::new(ErrorKind::InvalidData, "invalid ")), false)
                }
            }
            Icmpv6Types::DestinationUnreachable => (
                Err(Error::new(
                    ErrorKind::AddrNotAvailable,
                    "destination unreachable",
                )),
                false,
            ),
            Icmpv6Types::TimeExceeded => {
                //println!("time exceeded: {:02x}", icmp_packet_in.payload().as_hex());
                // `Time Exceeded` packages do not have a identifier or sequence number
                // They do return up to 576 bytes of the original IP packet
                // So that's where we identify the packet to belong to this `packet_out`.
                if self.ttl == self.spec.max_hops {
                    // self.done = true;
                    return (Err(Error::new(ErrorKind::TimedOut, "too many hops")), true);
                }
                let wrapped_ip_packet = Ipv6Packet::new(&icmp_packet_in.payload()).unwrap();

                (
                    self.analyse_icmp_packet_in(
                        wrapped_ip_packet.payload(),
                        &icmp_packet_in.packet(),
                        packet_out,
                    ),
                    false,
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
                (
                    Err(Error::new(
                        ErrorKind::Other,
                        "unidentified packet type - ipv6",
                    )),
                    false,
                )
            }
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

    #[allow(unused_variables)]
    pub fn next_hop(&mut self) -> io::Result<TraceResult> {
        self.seq_num += 1;
        if self.spec.verbose {
            println!("==============");
            println!("START HOP {}", self.seq_num);
        }

        let mut trace_result = TraceResult {
            error: Err(Error::new(ErrorKind::Other, "-42")),
            hop: self.seq_num as u8,
            // result: HopFutures(Vec::with_capacity(self.spec.packets_per_hop as usize)),
            result: Vec::with_capacity(self.spec.packets_per_hop as usize),
        };

        self.ttl += 1;
        // let mut trace_hops: Vec<Box<dyn Future<Output = HopOrError>>> =
        //     Vec::with_capacity(self.spec.packets_per_hop as usize);
        let mut trace_hops = Vec::with_capacity(self.spec.packets_per_hop as usize);

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
        let mut futures_list = FuturesUnordered::new();

        'trt: for count in 0..self.spec.packets_per_hop {
            let ttl = self.set_ttl(&self.socket_out);
            // self.ident = SRC_BASE_PORT - <u16>::from(rand::random::<u8>());
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

            // create it again, since we're borrowing non-mutable,
            // we can't directly set the port.
            let dst_addr: SockAddr = SocketAddr::new(self.dst_addr.ip(), dst_port_for_hop).into();

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

            futures_list.push(self.hop_listen(start_time, packet_out, self.spec.timeout as u64))
        }

        println!("no of futures : {:?}", futures_list.len());
        async_std::task::block_on(async {
            let mut done: bool;

            loop {
                select! {
                    h = futures_list.next() => {
                        println!("async select {:?}", h);
                        let hh: HopOrError = match h {
                            None => HopOrError::HopError(HopTimeOutError {message: "crazy".to_string(), line: 0, column: 0}),
                            Some(hop) => { done = hop.1; hop.0 }
                        };
                        trace_hops.push(hh);
                    }
                    complete => { break; }
                }
            }
        });
        trace_result.result = trace_hops;
        Ok(trace_result)
    }

    async fn hop_listen(
        &self,
        start_time: time::SteadyTime,
        packet_out: Vec<u8>,
        timeout: u64,
    ) -> (HopOrError, bool) {
        let mut buf_in = vec![0; MAX_PACKET_SIZE];
        let dur = std::time::Duration::from_millis(1000 * self.spec.timeout as u64);
        match future::timeout(dur, self.socket_in.recv_from(buf_in.as_mut_slice())).await {
            Err(e) => {
                println!("future timeout for hop {}: {:?}", self.ttl, e);
                (
                    HopOrError::HopError(HopTimeOutError {
                        message: "* wut?".to_string(),
                        line: 0,
                        column: 0,
                    }),
                    false,
                )
            }
            Ok(r) => {
                let (packet_len, sender) = r.unwrap();
                let rtt = SteadyTime::now() - start_time;

                // The IP packet that wraps the incoming ICMP message.
                let (packet_in, ttl_in) = self.unwrap_payload_ip_packet_in(&buf_in);

                match packet_in {
                    IcmpPacketIn::V6(icmp_packet_in) => {
                        match self.analyse_v6_payload(&packet_out, &icmp_packet_in) {
                            (Ok(()), done) => {
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
                                )
                            }
                            (Err(ref err), done)
                                if err.kind() == ErrorKind::InvalidData
                                    || err.kind() == ErrorKind::Other =>
                            {
                                if self.spec.verbose {
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
                                )
                            }
                            (Err(e), done) => (
                                HopOrError::HopError(HopTimeOutError {
                                    message: e.to_string(),
                                    line: 0,
                                    column: 0,
                                }),
                                done,
                            ),
                        }
                    }
                    IcmpPacketIn::V4(ip_packet_in) => {
                        let ip_payload = ip_packet_in.payload();
                        let icmp_packet_in = IcmpPacket::new(&ip_packet_in.payload()).unwrap();
                        match self.analyse_v4_payload(&packet_out, &icmp_packet_in, &ip_payload) {
                            (Ok(()), done) => {
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
                                )
                            }
                            (err, done) => {
                                if self.spec.verbose {
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
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// impl Iterator for TraceHopsIterator {
//     type Item = io::Result<TraceResult>;

//     fn next(&mut self) -> Option<io::Result<TraceResult>> {
//         if self.done {
//             return None;
//         }

//         let trace_result = match self.next_hop() {
//             Ok(r) => Result::Ok(r),
//             Err(e) => {
//                 // This is a fatal condition,
//                 // probably a socket that cannot be opened,
//                 // or a packet that just gets stuck on its way out of localhost.
//                 // gracefully end all this.
//                 self.done = true;
//                 Result::Err(e)
//             }
//         };

//         Some(trace_result)
//     }
// }

impl<'a> Stream for TraceHopsIterator<'a> {
    type Item = io::Result<TraceResult>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.done {
            return Poll::Ready(None);
        }
        if self.ttl == self.spec.max_hops {
            return Poll::Ready(None);
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

        Poll::Ready(Some(trace_result))
    }
}
