#![feature(ip)]

extern crate dns_lookup;
extern crate hex_slice;
extern crate ipaddress;
extern crate ipnetwork;
extern crate pnet;
extern crate rand;
extern crate socket2;
extern crate time;

use std::iter::Iterator;

use std::io::{self, Error, ErrorKind};

use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6, ToSocketAddrs};
use ipnetwork::IpNetwork;

use time::{Duration, SteadyTime};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
//use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket as MutableEchoRequestV6Packet;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::Packet;
use pnet::packet::icmp::checksum;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::icmpv6::MutableIcmpv6Packet;
use pnet::datalink::{interfaces, NetworkInterface};

use ipaddress::IPAddress;
use dns_lookup::lookup_addr;
use hex_slice::AsHex;

//const MAX_PACKET_SIZE: usize = 4096 + 128;
const MAX_PACKET_SIZE: usize = 128;
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
    dest_addr: SocketAddr,
    af: AddressFamily,
    //socket: Socket,
    //protocol: Protocol,
    //echo_request_packet: IcmpEchoRequest<'a>,
    ttl: u32,
    ident: u16,
    seq_num: u16,
    done: bool,
    timeout: Duration,
}

#[derive(Debug)]
pub struct TraceHop {
    /// ip address of the hophost
    pub host: SocketAddr,
    /// The resolved hostname
    pub host_name: String,
    /// time-to-live for this hop
    pub ttl: u32,
    /// round-trip-time for this packet
    pub rtt: Duration,
}

impl TraceResult {
    fn get_sock_addr2<'a>(&self) -> SockAddr {
        let filter_public_if_for_af = |addr: &IpNetwork| match self.af {
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
        println!("if : {:?}", interface);

        match interface {
            IpAddr::V4(addrv4) => <SockAddr>::from(SocketAddrV4::new(addrv4, SRC_BASE_PORT)),
            IpAddr::V6(addrv6) => {
                <SockAddr>::from(SocketAddrV6::new(addrv6, SRC_BASE_PORT, 0, 0x0))
            }
        }
    }

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
                // failing to set will have the traceroute until exhaustion
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

    // TODO: make this work. Should retrieve the IP version and return the right package struct.
    fn unwrap_payload_ip_packet_in(&mut self, buf_in: &[u8]) -> IcmpPacketIn {
        match self.af {
            AddressFamily::V4 => IcmpPacketIn::V4(Ipv4Packet::owned(buf_in.to_owned()).unwrap()),
            AddressFamily::V6 => IcmpPacketIn::V6(Icmpv6Packet::owned(buf_in.to_owned()).unwrap()),
        }
    }

    fn set_ttl_or_unicast_hops(&self, socket: &Socket) -> Result<u32, Error> {
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

    fn get_sock_addr(&self) -> SockAddr {
        //let interface_has_ips_match = |iface: &NetworkInterface| iface.ips.len() > 0;
        let interfaces = pnet::datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .filter(|iface: &NetworkInterface| iface.ips.len() > 0)
            .flat_map(|i| i.ips)
            .filter(|addr: &IpNetwork| addr.is_ipv6() && addr.ip().is_global())
            .map(|a| a.ip());
        //.iter()
        //.filter(|iface: &NetworkInterface| iface.name == "en0" )
        //.next()
        //.unwrap();
        //println!("ips: {:?}", interface);
        for intf in interface {
            println!("if: {:?}", intf);
        }
        //     .ips
        //     .into_iter()
        //     .filter(
        //        |addr: &IpNetwork| addr.is_ipv6()
        //     )
        // );

        match self.af {
            AddressFamily::V4 => <SockAddr>::from(SocketAddrV4::new(
                Ipv4Addr::new(192, 168, 178, 100),
                SRC_BASE_PORT,
            )),
            AddressFamily::V6 => <SockAddr>::from(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0x470, 0x1f15, 0xf8d, 0xa65e, 0x60ff, 0xfec2, 0xc373),
                SRC_BASE_PORT,
                0,
                0x0,
            )),
        }
    }

    fn find_next_hop(&mut self) -> io::Result<TraceHop> {
        let src = self.get_sock_addr2();
        println!("src: {:?}", src);
        let socket = self.create_socket(); //.bind(&src).unwrap();
        socket.bind(&src).unwrap();
        println!("{:?}", socket);

        loop {
            self.seq_num += 1;
            let packet_out = self.make_echo_request_packet_out().to_owned();

            println!("hophost: {:?}", self.dest_addr);
            self.ttl += 1;
            let ttl = self.set_ttl_or_unicast_hops(&socket);
            println!("hops: {:?}", ttl.unwrap());
            try!(socket.set_read_timeout(Some(self.timeout.to_std().unwrap())));

            let wrote = try!(socket.send_to(&packet_out, &<SockAddr>::from(self.dest_addr)));
            assert_eq!(wrote, packet_out.len());
            let start_time = SteadyTime::now();

            // After deadline passes, restart the loop to advance the TTL and resend.
            while SteadyTime::now() < start_time + self.timeout {
                let (packet_len, sender);
                let mut buf_in = vec![0; MAX_PACKET_SIZE];
                match socket.recv_from(buf_in.as_mut_slice()) {
                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                    Ok((len, s)) => {
                        packet_len = len;
                        sender = s;
                        println!("length: {}", len);
                    }
                }

                // The IP packet that wraps the incoming ICMP message.
                //let ip_packet_in = Ipv6Packet::new(&buf_in).unwrap().payload().to_owned();
                let packet_in = self.unwrap_payload_ip_packet_in(&buf_in);

                //println!("{:?}", ip_packet_in);
                //println!("{:?}", buf_in);
                // The ICMP packet hopefully inside the payload of the IP packet
                //let icmp_packet_in = Icmpv6Packet::new(&buf_in).unwrap();
                //println!("payload#1: {:?}", icmp_packet_in);
                match packet_in {
                    IcmpPacketIn::V6(icmp_packet_in) => match icmp_packet_in.get_icmpv6_type() {
                        Icmpv6Types::EchoReply => {
                            println!("Echo reply in: {:?}", icmp_packet_in);
                            println!("icmp payload: {:02x}", icmp_packet_in.payload().as_hex());
                            let icmp_echo_reply = &icmp_packet_in;
                            if icmp_echo_reply.get_identifier() == self.ident
                                && icmp_echo_reply.get_sequence_number() == self.seq_num
                            {
                                println!("echo reply; end now");
                                let host = SocketAddr::V6(sender.as_inet6().unwrap());
                                let hop = TraceHop {
                                    ttl: self.ttl,
                                    host: host,
                                    host_name: lookup_addr(&host.ip()).unwrap(),
                                    rtt: SteadyTime::now() - start_time,
                                };
                                self.done = true;
                                return Ok(hop);
                            }
                        }
                        Icmpv6Types::DestinationUnreachable => {
                            println!("dest unreachable; end now")
                        }
                        Icmpv6Types::TimeExceeded => {
                            println!("time exceeded: {:02x}", icmp_packet_in.payload().as_hex());
                            // `Time Exceeded` packages do not have a identifier or sequence number
                            // They do return up to 576 bytes of the original IP packet
                            // So that's where we identify the packet to belong to this `packet_out`.
                            if self.ttl == 255 {
                                self.done = true;
                                return Err(Error::new(ErrorKind::TimedOut, "too many hops"));
                            }
                            let wrapped_ip_packet =
                                Ipv6Packet::new(&icmp_packet_in.payload()).unwrap();
                            println!("unwrap ip: {:?}", wrapped_ip_packet);
                            // We don't have any ICMP data right now
                            // So we're only using the last 4 bytes in the payload to compare.
                            if wrapped_ip_packet.payload()[4..8] == packet_out[4..8] {
                                let host = SocketAddr::V6(sender.as_inet6().unwrap());
                                let hop = TraceHop {
                                    ttl: self.ttl,
                                    host: host,
                                    host_name: lookup_addr(&host.ip()).unwrap(),
                                    rtt: SteadyTime::now() - start_time,
                                };
                                return Ok(hop);
                            }
                        }
                        _ => (
                        //println!("incoming packet {:?}", icmp_packet_in)
                    ),
                    },
                    IcmpPacketIn::V4(ip_packet_in) => {
                        let ip_payload = ip_packet_in.payload();
                        let icmp_packet_in = IcmpPacket::new(&ip_packet_in.payload()).unwrap();
                        match icmp_packet_in.get_icmp_type() {
                            IcmpTypes::EchoReply => {
                                let icmp_echo_reply = EchoReplyPacket::new(&ip_payload).unwrap();
                                if icmp_echo_reply.get_identifier() == self.ident
                                    && icmp_echo_reply.get_sequence_number() == self.seq_num
                                {
                                    let host = SocketAddr::V4(sender.as_inet().unwrap());
                                    let hop = TraceHop {
                                        ttl: self.ttl,
                                        host: host,
                                        host_name: lookup_addr(&host.ip()).unwrap(),
                                        rtt: SteadyTime::now() - start_time,
                                    };
                                    self.done = true;
                                    return Ok(hop);
                                }
                            }
                            IcmpTypes::DestinationUnreachable => {
                                println!("dest unreachable; end now")
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
                                let wrapped_ip_packet =
                                    Ipv4Packet::new(&icmp_time_exceeded).unwrap();

                                // We don't have any ICMP data right now
                                // So we're only using the last 4 bytes in the payload to compare.
                                if wrapped_ip_packet.payload()[4..8] == packet_out[4..8] {
                                    let host = SocketAddr::V4(sender.as_inet().unwrap());
                                    let hop = TraceHop {
                                        ttl: self.ttl,
                                        host: host,
                                        host_name: lookup_addr(&host.ip()).unwrap(),
                                        rtt: SteadyTime::now() - start_time,
                                    };
                                    return Ok(hop);
                                }
                            }
                            _ => (println!("incoming packet {:?}", icmp_packet_in)),
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

/// Run-of-the-mill icmp ipv4 traceroute implementation (for now)
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
        Some(dest_addr) => {
            println!("dest: {:?}", dest_addr);
            Ok({
                match dest_addr.is_ipv4() {
                    true => TraceResult {
                        dest_addr: dest_addr,
                        af: AddressFamily::V4,
                        ttl: 0,
                        ident: rand::random(),
                        seq_num: 0,
                        done: false,
                        timeout: timeout,
                    },
                    false => TraceResult {
                        dest_addr: dest_addr,
                        af: AddressFamily::V6,
                        ttl: 0,
                        ident: rand::random(),
                        seq_num: 0,
                        done: false,
                        timeout: timeout,
                    },
                }
            })
        }
    }
}
