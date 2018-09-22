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
use pnet::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::Packet;
use pnet::packet::icmp::checksum;
use pnet::packet::udp::{ipv4_checksum, ipv6_checksum};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::datalink::NetworkInterface;

use dns_lookup::lookup_addr;
// only used for debug printing packets
use hex_slice::AsHex;

const MAX_PACKET_SIZE: usize = 4096 + 128;
const ICMP_HEADER_LEN: usize = 8;
const UDP_HEADER_LEN: usize = 8;
const SRC_BASE_PORT: u16 = 0x5000;
const DST_BASE_PORT: u16 = 0x8000 + 666;
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
    pub error: io::Result<Error>,
    pub hop: u8,
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
    pub ttl: u8,
    /// Round-trip-time for this packet
    pub rtt: Duration,
    /// Size of the reply
    pub size: usize,
}

fn get_sock_addr<'a>(af: &AddressFamily, port: u16) -> SockAddr {
    let filter_public_if_for_af = |addr: &IpNetwork| match af {
        &AddressFamily::V4 => addr.is_ipv4() && !addr.ip().is_loopback(),
        &AddressFamily::V6 => addr.is_ipv6() && addr.ip().is_global(),
    };
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
    //println!("src_addr: {:?}, port: {:02x}", interface, &[port].as_hex());

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
            (true, &TraceProtocol::TCP) => Type::dgram(),
        };

        match af {
            &AddressFamily::V4 => Socket::new(Domain::ipv4(), sock_type, protocol).unwrap(),
            &AddressFamily::V6 => Socket::new(Domain::ipv6(), sock_type, protocol).unwrap(),
        }
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
                let src_ip = self.src_addr
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
                    src_ip,
                    dst_ip,
                );
                udp_packet.set_checksum(udp_checksum);
                udp_packet.packet().to_owned()
            }
            AddressFamily::V6 => {
                let src_ip = self.src_addr
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
                println!(
                    "icmp payload: {:02x}",
                    &wrapped_ip_packet[..8].as_hex()
                );
                println!(
                    "64b of icmp in packet: {:02x}",
                    &icmp_packet_in[..8].as_hex()
                );

                Ok(())
            }
            _ => {
                print!("packet out {:?}: {:02x}", &self.proto, &packet_out.as_hex());
                print!(" -> ");
                println!(
                    "icmp payload: {:02x}",
                    &wrapped_ip_packet[..64].as_hex()
                );
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
                self.analyse_icmp_packet_in(wrapped_ip_packet.payload(), &icmp_packet_in.packet(), packet_out)
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
            // that is, only if the requested server does not listen on the destiation port!
            IcmpTypes::DestinationUnreachable => {
                self.done = true;

                let dest_unreachable = DestinationUnreachablePacket::new(&ip_payload)
                    .unwrap()
                    .payload()
                    .to_owned();
                let wrapped_ip_packet = Ipv4Packet::new(&dest_unreachable).unwrap();
                //println!("{:02x}", wrapped_ip_packet.packet().as_hex());
                self.analyse_icmp_packet_in(wrapped_ip_packet.payload(), &icmp_packet_in.packet(), packet_out)
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
                self.analyse_icmp_packet_in(wrapped_ip_packet.payload(), &icmp_packet_in.packet(), packet_out)
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
                try!(socket.set_unicast_hops_v6(self.ttl));
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
        let mut trace_hops = Vec::with_capacity(DEFAULT_TRT_COUNT as usize);

        for count in 0..DEFAULT_TRT_COUNT {
            let socket_out = self.create_socket(true);
            let ttl = self.set_ttl(&socket_out);
            self.ident = SRC_BASE_PORT - <u16>::from(rand::random::<u8>());
            let src = get_sock_addr(&self.af, self.ident);
            socket_out.bind(&src).unwrap();
            let packet_out = match self.proto {
                TraceProtocol::ICMP => self.make_icmp_packet_out(),
                TraceProtocol::UDP => self.make_udp_packet_out(),
                _ => self.make_icmp_packet_out(),
            };
            // println!(
            //     "ttl: {:?}, seq: {:?}, id: {:02x}",
            //     self.ttl,
            //     self.seq_num,
            //     &[self.ident].as_hex()
            // );
            self.dst_addr.set_port(self.seq_num + DST_BASE_PORT);
            //println!("src_port: {:02x}", &[self.dst_addr.port()].as_hex());
            let wrote = try!(socket_out.send_to(&packet_out, &<SockAddr>::from(self.dst_addr)));
            assert_eq!(wrote, packet_out.len());
            let start_time = SteadyTime::now();

            let mut read: Result<(usize, SockAddr, Duration), Error>;
            let sender: SockAddr;
            let packet_len: usize;
            let rtt: Duration;

            let mut buf_in = vec![0; MAX_PACKET_SIZE];

            // If hop is not overwritten with a TraceHop struct within the while loop below
            // then the result will be a timed-out error
            let mut hop: io::Result<TraceHop> = Err(Error::new(ErrorKind::TimedOut, "*"));

            while SteadyTime::now() < start_time + self.timeout {
                let read = match self.socket_in.recv_from(buf_in.as_mut_slice()) {
                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => {
                        continue;
                    }
                    Err(e) => {
                        println!("error in rcv_from: {:?}", e);
                        Err(e)
                    }
                    Ok((len, s)) => Ok((len, s, SteadyTime::now() - start_time)),
                };

                let (packet_len, sender, rtt) = match read {
                    Ok(recv) => recv,
                    _ => {
                        continue;
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
                                    host: host,
                                    hop_name: lookup_addr(&host.ip()).unwrap(),
                                    rtt: rtt,
                                });
                                // we've got a positive result,
                                // so break out of the while loop
                                break;
                            }
                            Err(ref err)
                                if err.kind() == ErrorKind::InvalidData
                                    || err.kind() == ErrorKind::Other =>
                            {
                                println!("*");
                                println!("{:?}", err);
                                hop = Err(Error::new(ErrorKind::InvalidData, "*"));
                                // this packet might not be meant for this tracehop,
                                // so DO NOT break the while loop and listen for some
                                // other packet that might come in.
                                continue;
                            }
                            Err(e) => trace_hops.push(Err(e)),
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
                                    host: host,
                                    hop_name: lookup_addr(&host.ip()).unwrap(),
                                    rtt: rtt,
                                });
                                break;
                            }
                            err => {
                                println!("* wut?");
                                println!("{:?}", err);
                                hop = Err(Error::new(ErrorKind::Other, "*"));
                                continue;
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
    type Item = TraceResult;

    fn next(&mut self) -> Option<TraceResult> {
        if self.done {
            return None;
        }

        let trace_result = self.next_hop();

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

    let socket_in = match address.to_socket_addrs().unwrap().next().unwrap().is_ipv4() {
        true => Socket::new(Domain::ipv4(), Type::raw(), Some(<Protocol>::icmpv4())).unwrap(),
        false => Socket::new(Domain::ipv6(), Type::raw(), Some(<Protocol>::icmpv6())).unwrap(),
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
                        let src_addr = get_sock_addr(&AddressFamily::V4, SRC_BASE_PORT);
                        dst_addr.set_port(DST_BASE_PORT);
                        TraceRoute {
                            src_addr: src_addr,
                            dst_addr: dst_addr,
                            af: AddressFamily::V4,
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
                        let src_addr = get_sock_addr(&AddressFamily::V6, SRC_BASE_PORT);
                        dst_addr.set_port(DST_BASE_PORT);
                        TraceRoute {
                            src_addr: src_addr,
                            dst_addr: dst_addr,
                            af: AddressFamily::V6,
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
