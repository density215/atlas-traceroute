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

pub struct TraceResult {
    src_addr: SockAddr,
    dst_addr: SocketAddr,
    af: AddressFamily,
    ttl: u32,
    ident: u16,
    seq_num: u16,
    done: bool,
    timeout: Duration,
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

impl TraceResult {
    fn create_socket<'a>(&self) -> Socket {
        match self.af {
            AddressFamily::V4 => {
                Socket::new(Domain::ipv4(), Type::raw(), Some(<Protocol>::icmpv4())).unwrap()
            }
            AddressFamily::V6 => {
                Socket::new(Domain::ipv6(), Type::raw(), Some(<Protocol>::icmpv6())).unwrap()
            }
        }
    }

    fn make_echo_request_packet_out<'a>(&self) -> Vec<u8> {
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
        packet_out: &Vec<u8>,
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
                    Err(Error::new(ErrorKind::TimedOut, "too many hops"))
                }
            }
            IcmpTypes::DestinationUnreachable => {
                Err(Error::new(ErrorKind::TimedOut, "too many hops"))
            }
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
                if wrapped_ip_packet.payload()[4..8] == packet_out[4..8] {
                    Ok(())
                } else {
                    Err(Error::new(ErrorKind::TimedOut, "too many hops"))
                }
            }
            _ => Err(Error::new(ErrorKind::TimedOut, "too many hops")),
        }
    }

    fn analyse_v6_payload(
        &mut self,
        packet_out: &Vec<u8>,
        icmp_packet_in: &Icmpv6Packet,
    ) -> Result<(), Error> {
        match icmp_packet_in.get_icmpv6_type() {
            Icmpv6Types::EchoReply => {
                //println!("icmp payload: {:02x}", icmp_packet_in.payload().as_hex());
                if icmp_packet_in.get_identifier() == self.ident
                    && icmp_packet_in.get_sequence_number() == self.seq_num
                {
                    Ok(())
                } else {
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
            _ => Err(Error::new(ErrorKind::Other, "unidentified packet type")),
        }
    }

    fn set_ttl(&self, socket: &Socket) -> Result<u32, Error> {
        // In IPv6 IP_TTL is NOT called IPV6_TTL, but
        // IPV6_UNICAST_HOPS
        match self.af {
            AddressFamily::V4 => {
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
    fn find_next_hop(&mut self) -> io::Result<TraceHop> {
        let socket = self.create_socket();
        socket.bind(&self.src_addr).unwrap();

        loop {
            self.seq_num += 1;
            let packet_out = self.make_echo_request_packet_out().to_owned();

            self.ttl += 1;
            let ttl = self.set_ttl(&socket);
            try!(socket.set_read_timeout(Some(self.timeout.to_std().unwrap())));

            let wrote = try!(socket.send_to(&packet_out, &<SockAddr>::from(self.dst_addr)));
            assert_eq!(wrote, packet_out.len());
            let start_time = SteadyTime::now();

            // After deadline passes, restart the loop to advance the TTL and resend.
            while SteadyTime::now() < start_time + self.timeout {
                let (sender, packet_len, rtt);
                let mut buf_in = vec![0; MAX_PACKET_SIZE];
                match socket.recv_from(buf_in.as_mut_slice()) {
                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                    Ok((len, s)) => {
                        packet_len = len;
                        sender = s;
                        rtt = SteadyTime::now() - start_time;
                    }
                }

                // The IP packet that wraps the incoming ICMP message.
                let packet_in = self.unwrap_payload_ip_packet_in(&buf_in);

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
                                return Ok(hop);
                            }
                            Err(ref err)
                                if err.kind() == ErrorKind::InvalidData
                                    || err.kind() == ErrorKind::Other =>
                            {
                                continue
                            }
                            Err(e) => return Err(e),
                        }
                    }
                    IcmpPacketIn::V4(ip_packet_in) => {
                        let ip_payload = ip_packet_in.payload();
                        let icmp_packet_in = IcmpPacket::new(&ip_packet_in.payload()).unwrap();
                        match self.analyse_v4_payload(&packet_out, &icmp_packet_in, &ip_payload) {
                            Ok(()) => {
                                let host = SocketAddr::V4(sender.as_inet().unwrap());
                                let hop = TraceHop {
                                    ttl: self.ttl,
                                    size: packet_len,
                                    host: host,
                                    hop_name: lookup_addr(&host.ip()).unwrap(),
                                    rtt: SteadyTime::now() - start_time,
                                };
                                return Ok(hop);
                            }
                            err => continue,
                        }
                    }
                }
            }
        }
    }
}

impl Iterator for TraceResult {
    type Item = io::Result<TraceHop>;

    fn next(&mut self) -> Option<io::Result<TraceHop>> {
        if self.done {
            return None;
        }

        let res = self.find_next_hop();
        if res.is_err() {
            self.done = true;
        }
        Some(res)
    }
}

/// Do traceroute
pub fn start<'a, T: ToSocketAddrs>(address: T) -> io::Result<TraceResult> {
    sync_start_with_timeout(address, Duration::seconds(1))
}

/// Run-of-the-mill icmp ipv4/ipv6 traceroute implementation (for now)
// Completely synchronous. Every packet that's send will trigger a wait for its return
pub fn sync_start_with_timeout<'a, T: ToSocketAddrs>(
    address: T,
    timeout: Duration,
) -> io::Result<TraceResult> {
    match timeout.num_microseconds() {
        None => return Err(Error::new(ErrorKind::InvalidInput, "Timeout too large")),
        Some(0) => return Err(Error::new(ErrorKind::InvalidInput, "Timeout too small")),
        _ => (),
    };

    let mut addr_iter = try!(address.to_socket_addrs());
    match addr_iter.next() {
        None => Err(Error::new(
            ErrorKind::InvalidInput,
            "Could not interpret address",
        )),
        Some(dst_addr) => {
            println!("dst_addr: {:?}", dst_addr);
            println!("timestamp: {:?}", time::get_time().sec);
            Ok({
                match dst_addr.is_ipv4() {
                    true => {
                        let src_addr = get_sock_addr(AddressFamily::V4);
                        TraceResult {
                            src_addr: src_addr,
                            dst_addr: dst_addr,
                            af: AddressFamily::V4,
                            ttl: 0,
                            ident: rand::random(),
                            seq_num: 0,
                            done: false,
                            timeout: timeout,
                        }
                    }
                    false => {
                        let src_addr = get_sock_addr(AddressFamily::V6);
                        TraceResult {
                            src_addr: src_addr,
                            dst_addr: dst_addr,
                            af: AddressFamily::V6,
                            ttl: 0,
                            ident: rand::random(),
                            seq_num: 0,
                            done: false,
                            timeout: timeout,
                        }
                    }
                }
            })
        }
    }
}
