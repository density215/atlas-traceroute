extern crate dns_lookup;
extern crate libc;
extern crate pnet;
extern crate rand;
extern crate socket2;
extern crate time;

use std::iter::Iterator;

use std::io::{self, Error, ErrorKind};
use std::net::{SocketAddr, ToSocketAddrs};

use time::{Duration, SteadyTime};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::Packet;
use pnet::packet::icmp::checksum;
use pnet::packet::ipv4::Ipv4Packet;

use dns_lookup::lookup_addr;

const MAX_PACKET_SIZE: usize = 4096 + 128;
const ICMP_HEADER_LEN: usize = 8;

pub struct TraceResult {
    addr: SocketAddr,
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
pub fn start<T: ToSocketAddrs>(address: T) -> io::Result<TraceResult> {
    sync_start_with_timeout(address, Duration::seconds(1))
}

/// Run-of-the-mill icmp ipv4 traceroute implementation (for now)
// Completely synchronous. Every packet that's send will trigger a wait for its return
pub fn sync_start_with_timeout<T: ToSocketAddrs>(
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
        Some(addr) => Ok(TraceResult {
            addr: addr,
            ttl: 0,
            ident: rand::random(),
            seq_num: 0,
            done: false,
            timeout: timeout,
        }),
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

impl TraceResult {
    fn find_next_hop(&mut self) -> io::Result<TraceHop> {
        let socket = try!(Socket::new(
            Domain::ipv4(),
            Type::raw(),
            Some(Protocol::icmpv4())
        ));

        loop {
            let packet_out = make_icmp_echo_request(self.ident, self.seq_num);
            self.seq_num += 1;

            self.ttl += 1;
            try!(socket.set_ttl(self.ttl));
            try!(socket.set_read_timeout(Some(self.timeout.to_std().unwrap())));

            let wrote = try!(socket.send_to(&packet_out.packet(), &<SockAddr>::from(self.addr)));
            assert_eq!(wrote, packet_out.packet().len());
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
                        //println!("length: {}", bytes);
                    }
                }

                // The IP packet that wraps the incoming ICMP message.
                let ip_packet_in = Ipv4Packet::new(&buf_in).unwrap().payload().to_owned();

                // The ICMP packet hopefully inside the payload of the IP packet
                let icmp_packet_in = IcmpPacket::new(&ip_packet_in).unwrap();

                match icmp_packet_in.get_icmp_type() {
                    IcmpTypes::EchoReply => {
                        let icmp_echo_reply = EchoReplyPacket::new(&ip_packet_in).unwrap();
                        //println!("echo reply {:?}", icmp_echo_reply);
                        if icmp_echo_reply.get_identifier() == packet_out.get_identifier()
                            && icmp_echo_reply.get_sequence_number()
                                == packet_out.get_sequence_number()
                        {
                            //println!("echo reply; end now");
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
                    IcmpTypes::DestinationUnreachable => println!("dest unreachable; end now"),
                    IcmpTypes::TimeExceeded => {
                        // `Time Exceeded` packages do not have a identifier or sequence number
                        // They do return up to 576 bytes of the original IP packet
                        // So that's where we identify the packet to belong to this `packet_out`.
                        if self.ttl == 255 {
                            self.done = true;
                            return Err(Error::new(ErrorKind::TimedOut, "too many hops"));
                        }
                        let icmp_time_exceeded = TimeExceededPacket::new(&ip_packet_in)
                            .unwrap()
                            .payload()
                            .to_owned();
                        let wrapped_ip_packet = Ipv4Packet::new(&icmp_time_exceeded).unwrap();

                        // We don't have any ICMP data right now
                        // So we're only using the last 4 bytes in the payload to compare.
                        if wrapped_ip_packet.payload()[4..8] == packet_out.packet()[4..8] {
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

    //println!("outgoing packet {:?}", echo_request_packet);
    echo_request_packet
}
