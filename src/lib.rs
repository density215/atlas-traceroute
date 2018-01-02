extern crate dns_lookup;
extern crate pnet;
extern crate rand;
extern crate socket2;
extern crate time;
extern crate hex_slice;

use std::iter::Iterator;

use std::io::{self, Error, ErrorKind};
use std::net::{Ipv6Addr, Ipv4Addr, SocketAddr, SocketAddrV6, SocketAddrV4, ToSocketAddrs};

use time::{Duration, SteadyTime};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmpv6::echo_request::MutableEchoRequestPacket as MutableEchoRequestV6Packet;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::Packet;
use pnet::packet::icmp::checksum;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::icmpv6::MutableIcmpv6Packet;

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

enum IcmpEchoRequest<'a> {
    V4(MutableEchoRequestPacket<'a>),
    V6(MutableEchoRequestV6Packet<'a>)
}

enum IpPacketIn<'p> {
    V4(Ipv4Packet<'p>),
    V6(Ipv6Packet<'p>)
}

impl AddressFamily {
    fn create_socket<'a>(self) -> Socket {
        match self {
            AddressFamily::V4 => {
                Socket::new(Domain::ipv4(), Type::raw(), Some(<Protocol>::icmpv4())).unwrap()
            }
            AddressFamily::V6 => {
                Socket::new(Domain::ipv6(), Type::raw(), Some(<Protocol>::icmpv6())).unwrap()
            }
        }
    }

    fn make_icmp_echo_request_packet<'a>(self, ident: u16, seq_num: u16) -> IcmpEchoRequest<'a> {
        match self {
            AddressFamily::V4 => {
                        let icmp_buffer = vec![00u8; ICMP_HEADER_LEN];
                        let mut echo_request_packet = MutableEchoRequestPacket::owned(icmp_buffer).unwrap();
                        echo_request_packet.set_icmp_type(IcmpTypes::EchoRequest);
                        echo_request_packet.set_identifier(ident);
                        echo_request_packet.set_sequence_number(seq_num);
                        IcmpEchoRequest::V4(echo_request_packet)
            },
            AddressFamily::V6 => {
                        let icmp_buffer = vec![00u8; ICMP_HEADER_LEN];
                        let mut echo_request_packet = MutableEchoRequestV6Packet::owned(icmp_buffer).unwrap();
                        echo_request_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
                        echo_request_packet.set_identifier(ident);
                        echo_request_packet.set_sequence_number(seq_num);
                        IcmpEchoRequest::V6(echo_request_packet)
            }
        }
    }
}

// TODO: make this work. Should retrieve the IP version and return the right package struct.
// pub fn inspect_ip_packet_in(packet_in: IpPacketIn) -> Vec<u8> {
//         match packet_in::get_version() {
//             4 => Ipv4Packet::new(&buf_in).unwrap().payload().to_owned(),
//             6 => Ipv6Packet::new(&buf_in).unwrap().payload().to_owned()
//         }
// }

pub struct TraceResult<'a> {
    addr: SocketAddr,
    af: AddressFamily,
    socket: Socket,
    //protocol: Protocol,
    echo_request_packet: IcmpEchoRequest<'a>,
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

/// Do traceroute
pub fn start<'a, T: ToSocketAddrs>(address: T) -> io::Result<TraceResult<'a>> {
    sync_start_with_timeout(address, Duration::seconds(1))
}

/// Run-of-the-mill icmp ipv4 traceroute implementation (for now)
// Completely synchronous. Every packet that's send will trigger a wait for its return
pub fn sync_start_with_timeout<'a, T: ToSocketAddrs>(
    address: T,
    timeout: Duration,
) -> io::Result<TraceResult<'a>> {
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
        Some(addr) => {
            println!("dest: {:?}", addr);
            Ok({
                match addr.is_ipv4() {
                    true => TraceResult {
                        addr: addr,
                        af: AddressFamily::V4,
                        socket: AddressFamily::V4.create_socket(),
                        echo_request_packet: AddressFamily::V4.make_icmp_echo_request_packet(rand::random(), 0),
                        //protocol: <Protocol>::icmpv4(),
                        ttl: 0,
                        ident: rand::random(),
                        seq_num: 0,
                        done: false,
                        timeout: timeout,
                    },
                    false => TraceResult {
                        addr: addr,
                        af: AddressFamily::V6,
                        socket: AddressFamily::V6.create_socket(),
                        echo_request_packet: AddressFamily::V6.make_icmp_echo_request_packet(rand::random(), 0),
                        //protocol: <Protocol>::icmpv6(),
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

impl Iterator for TraceResult<'static> {
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

impl TraceResult<'static> {
    fn find_next_hop(&mut self) -> io::Result<TraceHop> {
        let src = <SockAddr>::from(SocketAddrV6::new(
            Ipv6Addr::new(0x2001,0x470,0x1f15,0xf8d,0xa65e,0x60ff,0xfec2,0xc373),
            SRC_BASE_PORT,
            0,
            0x0,
        ));
        //let src = <SockAddr>::from(SocketAddrV4::new(Ipv4Addr::new(192,168,178,147), SRC_BASE_PORT));
        println!("src: {:?}", src);
        self.socket.bind(&src).unwrap();
        println!("{:?}", self.socket);

        loop {
            let packet_out = make_icmpv6_echo_request(self.ident, self.seq_num);
            self.seq_num += 1;

            println!("hophost: {:?}", self.addr);
            self.ttl += 1;
            //println!("ttl: {:?}", self.socket.ttl());
            //try!(self.socket.set_ttl(self.ttl));
            try!(self.socket.set_ipv6_unicast_hops(self.ttl));
            println!("hops: {:?}", self.socket.ipv6_unicast_hops());
            println!("setting read time out");
            try!(
                self.socket
                    .set_read_timeout(Some(self.timeout.to_std().unwrap()))
            );

            let wrote = try!(
                self.socket
                    .send_to(&packet_out.packet(), &<SockAddr>::from(self.addr))
            );
            assert_eq!(wrote, packet_out.packet().len());
            let start_time = SteadyTime::now();

            // After deadline passes, restart the loop to advance the TTL and resend.
            while SteadyTime::now() < start_time + self.timeout {
                let (packet_len, sender);
                let mut buf_in = vec![0; MAX_PACKET_SIZE];
                match self.socket.recv_from(buf_in.as_mut_slice()) {
                    Err(ref err) if err.kind() == ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                    Ok((len, s)) => {
                        packet_len = len;
                        sender = s;
                        println!("length: {}", len);
                    }
                }

                // The IP packet that wraps the incoming ICMP message.
                let ip_packet_in = Ipv6Packet::new(&buf_in).unwrap().payload().to_owned();

                //println!("{:?}", ip_packet_in);
                //println!("{:?}", buf_in);
                // The ICMP packet hopefully inside the payload of the IP packet
                let icmp_packet_in = Icmpv6Packet::new(&buf_in).unwrap();
                //println!("payload#1: {:?}", icmp_packet_in);

                match icmp_packet_in.get_icmpv6_type() {
                    Icmpv6Types::EchoReply => {
                        println!("Echo reply in: {:?}", icmp_packet_in);
                        println!("icmp payload: {:02x}", icmp_packet_in.payload().as_hex());
                        //let icmp_echo_reply = EchoReplyPacket::new(&icmp_packet_in.payload()).unwrap();
                        //println!("echo reply {:?}", icmp_echo_reply);
                        let icmp_echo_reply = &icmp_packet_in;
                        if icmp_echo_reply.get_identifier() == packet_out.get_identifier()
                            && icmp_echo_reply.get_sequence_number()
                                == packet_out.get_sequence_number()
                        {
                            //println!("echo reply; end now");
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
                    },
                    Icmpv6Types::DestinationUnreachable => println!("dest unreachable; end now"),
                    Icmpv6Types::TimeExceeded => {
                        println!("time exceeded: {:02x}",icmp_packet_in.payload().as_hex());
                        // `Time Exceeded` packages do not have a identifier or sequence number
                        // They do return up to 576 bytes of the original IP packet
                        // So that's where we identify the packet to belong to this `packet_out`.
                        if self.ttl == 255 {
                            self.done = true;
                            return Err(Error::new(ErrorKind::TimedOut, "too many hops"));
                        }
                        // let icmp_time_exceeded = TimeExceededPacket::new(&icmp_packet_in.payload())
                        //     .unwrap()
                        //     .payload()
                        //     .to_owned();
                        let wrapped_ip_packet = Ipv6Packet::new(&icmp_packet_in.payload()).unwrap();
                        println!("unwrap ip: {:?}", wrapped_ip_packet);
                        // We don't have any ICMP data right now
                        // So we're only using the last 4 bytes in the payload to compare.
                        if wrapped_ip_packet.payload()[4..8] == packet_out.packet()[4..8] {
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
                }
            }
        }
    }
}

/// Returns an ICMP Echo Request IP payload with the given identifier and sequence number
fn make_icmp_echo_request<'p>(ident: u16, seq_num: u16) -> MutableEchoRequestPacket<'p> {
    let icmp_buffer = vec![00u8; ICMP_HEADER_LEN];
    let mut echo_request_packet = MutableEchoRequestPacket::owned(icmp_buffer).unwrap();

    // No routers reply to this. Whatever
    // ping_packet.set_icmp_type(IcmpTypes::Traceroute);

    echo_request_packet.set_identifier(ident);
    echo_request_packet.set_sequence_number(seq_num);

    // For unknown reasons MutableEchoRequestPacket sets type to IcmpType(0) (which is "EchoReply"),
    // whereas it should be IcmpType(8)
    // Using EchoReply will result in traceroute never getting a "Echo Reply" from the
    // terminal router.
    echo_request_packet.set_icmp_type(IcmpTypes::EchoRequest);

    // checksum needs to be set automatically
    // failing to set will have the traceroute until exhaustion
    let p_checksum = checksum(&IcmpPacket::new(&echo_request_packet.packet()).unwrap());
    echo_request_packet.set_checksum(p_checksum);

    println!("outgoing packet {:?}", echo_request_packet);
    echo_request_packet
}

fn make_icmpv6_echo_request<'p>(ident: u16, seq_num: u16) -> MutableIcmpv6Packet<'p> {
    let icmp_buffer = vec![00u8; ICMP_HEADER_LEN];
    let mut echo_request_packet = MutableIcmpv6Packet::owned(icmp_buffer).unwrap();

    // For unknown reasons MutableEchoRequestPacket sets type to IcmpType(0) (which is "EchoReply"),
    // whereas it should be IcmpType(8)
    // Using EchoReply will result in traceroute never getting a "Echo Reply" from the
    // terminal router.
    echo_request_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);

    echo_request_packet.set_identifier(ident);
    echo_request_packet.set_sequence_number(seq_num);

    // checksum needs to be set automatically
    // failing to set will have the traceroute until exhaustion
    let p_checksum = checksum(&IcmpPacket::new(&echo_request_packet.packet()).unwrap());
    echo_request_packet.set_checksum(p_checksum);

    println!("outgoing packet {:02x}", echo_request_packet.packet().as_hex());
    echo_request_packet
}
