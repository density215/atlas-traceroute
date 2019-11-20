use crate::libtraceroute::route::*;
use socket2::*;
use std::io::{self, Error, ErrorKind};
use std::net::{SocketAddr, ToSocketAddrs};
use time::Duration;

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
