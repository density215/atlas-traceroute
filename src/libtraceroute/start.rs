use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};

use pnet::datalink::NetworkInterface;
use socket2::*;
use time::Duration;

use crate::libtraceroute::iterators::TraceHopsIterator;
use crate::rawsocket::async_std::RawSocket;

// The outgoing is socket is always of type ICMP,
// which is strictly not necessary for UDP or TCP (you can set ttl on
// their own sockets). Since we already need the privileges for the
// incoming socket we're going to do it the easy way.
// Note that the outgoing PROTOCOL needs to be set to the corresponding
// packet type, otherwise the checksums will be botched and packets will
// not return.
pub fn create_socket_out(proto: &TraceProtocol, src_addr: IpAddr) -> Socket {
    let af = src_addr;
    let protocol = match proto {
        TraceProtocol::ICMP => match af {
            IpAddr::V4(_) => Some(<Protocol>::icmpv4()),
            IpAddr::V6(_) => Some(<Protocol>::icmpv6()),
        },
        TraceProtocol::UDP => Some(<Protocol>::udp()),
        TraceProtocol::TCP => Some(<Protocol>::tcp()),
    };

    let sock_type = Type::raw();

    let socket_out = match src_addr {
        IpAddr::V4(_) => Socket::new(Domain::ipv4(), sock_type, protocol).unwrap(),
        IpAddr::V6(_) => Socket::new(Domain::ipv6(), sock_type, protocol).unwrap(),
    };

    socket_out.set_reuse_address(true).unwrap();
    // disable nagle's algo
    // Nagle's is only for TCP socket connections,
    // so not raw sockets.
    // match proto {
    //     TraceProtocol::TCP => {
    //         socket_out.set_nodelay(true).unwrap();
    //     }
    //     _ => {}
    // };
    socket_out
}

#[derive(Debug)]
pub struct TraceRoute<'a> {
    // pub spec: &'a TraceRouteSpec,
    pub start_src_addr: IpAddr,
    pub start_dst_addr: IpAddr,
    pub start_time: Option<i64>,
    pub trace_hops: TraceHopsIterator<'a>,
}

// The fields in the `trace_hops` iterator can be inspected by
// the consumer of the iterator as it iterates, however
// the fields outside of the `result` field
// will be mutated while the iterator is consumed!
impl<'a> TraceRoute<'a> {
    pub fn new(
        spec: TraceRouteSpec,
        start_src_addr: SocketAddr,
        start_dst_addr: SocketAddr,
        socket_in: &'a RawSocket,
        socket_out: Socket,
        ident_collection: &'a Vec<u16>,
    ) -> TraceRoute<'a> {
        let start_ttl = spec.start_ttl;
        TraceRoute {
            // spec: spec,
            start_src_addr: start_src_addr.ip(),
            start_dst_addr: start_dst_addr.ip(),
            // Do not the current timestamp as start_time here, since the iterator is lazy,
            // so None indicates that the iterator has not been run and no attemtps have been
            // made to send packets.
            start_time: None,
            trace_hops: TraceHopsIterator::new(
                spec,
                // src_addr & dst_addr are NOT the same as start_*_addr
                // from the TraceRoute struct.
                // This one contains the port that may be increased
                // per hop (classic traceroutes).
                start_src_addr,
                start_dst_addr,
                socket_in,
                socket_out,
                start_ttl,
                rand::random(),
                start_ttl,
                ident_collection,
            ),
        }
    }
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
    pub public_ip: Option<IpAddr>,
    pub verbose: bool,
}

#[derive(Debug, Copy, Clone)]
pub enum TraceProtocol {
    ICMP,
    UDP,
    TCP,
}

#[derive(Debug, Clone, Copy)]
pub enum AddressFamily {
    V4,
    V6,
}

pub fn get_sock_addr<'a>(af: &AddressFamily, port: u16) -> SocketAddr {
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

    SocketAddr::new(interface, port)
}

/// Run-of-the-mill icmp ipv4/ipv6 traceroute implementation (for now)
// Completely synchronous. Every packet that's send will trigger a wait for its return
pub fn sync_start_with_timeout<'a>(
    spec: TraceRouteSpec,
    src_addr: SocketAddr,
    dst_addr: SocketAddr,
    socket_in: &'a RawSocket,
    ident_collection: &'a Vec<u16>,
) -> io::Result<TraceRoute<'a>> {
    match Duration::seconds(spec.timeout).num_microseconds() {
        None => return Err(Error::new(ErrorKind::InvalidInput, "Timeout too large")),
        Some(0) => return Err(Error::new(ErrorKind::InvalidInput, "Timeout too small")),
        _ => (),
    };
    println!("timestamp: {:?}", time::get_time().sec);
    let socket_out = create_socket_out(&spec.proto, src_addr.ip());
    let traceroute = TraceRoute::new(
        spec,
        src_addr,
        dst_addr,
        &socket_in,
        socket_out,
        &ident_collection,
    );

    Ok(traceroute)
}
