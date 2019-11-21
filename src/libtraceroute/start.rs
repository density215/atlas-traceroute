use pnet::datalink::NetworkInterface;

use crate::libtraceroute::iterators::{TraceHopsIterator, DST_BASE_PORT, SRC_BASE_PORT};
use socket2::*;
use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use time::Duration;

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
    pub spec: &'a TraceRouteSpec,
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
        spec: &TraceRouteSpec,
        start_src_addr: SocketAddr,
        start_dst_addr: SocketAddr,
        socket_in: Socket,
        socket_out: Socket,
    ) -> TraceRoute {
        TraceRoute {
            spec: spec,
            start_src_addr: start_src_addr.ip(),
            start_dst_addr: start_dst_addr.ip(),
            // Do not the current timestamp as start_time here, since the iterator is lazy,
            // so None indicates that the iterator has not been run and no attemtps have been
            // made to send packets.
            start_time: None,
            trace_hops: TraceHopsIterator {
                spec: spec,
                // src_addr & dst_addr are NOT the same as start_*_addr
                // from the TraceRoute struct.
                // This one contains the port that may be increased
                // per hop (classic traceroutes).
                src_addr: start_src_addr,
                dst_addr: start_dst_addr,
                ttl: spec.start_ttl,
                ident: rand::random(),
                seq_num: spec.start_ttl,
                done: false,
                result: Vec::new(),
                socket_in: socket_in,
                socket_out: socket_out,
            },
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
    pub public_ip: Option<String>,
    pub verbose: bool,
}

#[derive(Debug)]
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

    SocketAddr::new(interface, 0)
}

/// Run-of-the-mill icmp ipv4/ipv6 traceroute implementation (for now)
// Completely synchronous. Every packet that's send will trigger a wait for its return
pub fn sync_start_with_timeout<'a, T: ToSocketAddrs>(
    address: T,
    spec: &'a TraceRouteSpec,
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

    let socket_out = create_socket_out(&spec.proto, src_addr.ip());
    let traceroute = TraceRoute::new(spec, src_addr, dst_addr, socket_in, socket_out);

    Ok(traceroute)
}
