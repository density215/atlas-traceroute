/*
 * Copyright (c) 2013 RIPE NCC <atlas@ripe.net>
 * Licensed under GPLv2 or later, see file LICENSE in this tarball for details.
 * Standalone version of the event-based traceroute. 
 */
//config:config EVTRACEROUTE
//config:       bool "evtraceroute"
//config:       default n
//config:       help
//config:               standalone version of event-driven traceroute

//applet:IF_EVTRACEROUTE(APPLET(evtraceroute, BB_DIR_BIN, BB_SUID_DROP))

//kbuild:lib-$(CONFIG_EVTRACEROUTE) += evtraceroute.o

//usage:#define evtraceroute_trivial_usage
//usage:       "-[46FIrTU] [-a <paris mod>] [-c <count>] [-f <hop>]"
//usage: "\n    [-g <gap>] [-m <hop>] [-p <port>] [-w <ms>] [-z <ms>] [-A <string>]"
//usage: "\n    [-O <file>] [-S <size>] [-H <hbh size>] [-D <dest. opt. size>]"
//usage:#define evtraceroute_full_usage "\n"
//usage:     "\n       -4                      Use IPv4 (default)"
//usage:     "\n       -6                      Use IPv6"
//usage:     "\n       -F                      Don't fragment"
//usage:     "\n       -I                      Use ICMP"
//usage:     "\n       -r                      Name resolution during each run"
//usage:     "\n       -T                      Use TCP"
//usage:     "\n       -U                      Use UDP (default)"
//usage:     "\n       -a <paris modulus>      Enables Paris-traceroute"
//usage:     "\n       -c <count>              #packets per hop"
//usage:     "\n       -f <hop>                Starting hop"
//usage:     "\n       -g <gap>                Gap limit"
//usage:     "\n       -m <hop>                Max hops"
//usage:     "\n       -p <port>               Destination port"
//usage:     "\n       -w <timeout>            No reply timeout (ms)"
//usage:     "\n       -z <timeout>            Dup timeout (ms)"
//usage:     "\n       -A <string>             Atlas measurement ID"
//usage:     "\n       -D <size>               Add IPv6 Destination Option this size"
//usage:     "\n       -H <size>               Add IPv6 Hop-by-hop Option this size"
//usage:     "\n       -O <file>               Name of output file"
//usage:     "\n       -S <size>               Size of packet"


#[macro_use]

extern crate structopt;
extern crate serde;
extern crate serde_json;
extern crate traceroute;

use std::env;
use std::num::ParseIntError;
use std::io::PathBuf;

enum af {
    V4,
    V6
}

fn parse_af(af: &af) -> Result<traceroute::AddressFamily, ParseIntError> {
    match af {
        V4 => traceroute::AddressFamily::V4,
        V6 => AddressFamily::V6,
        _ => ParseIntError
    }
}

#[derive(Debug, StructOpt)]
#[structopt(name = "atlas-traceroute", about = "Perfom a RIPE Atlas compliant traceroute.")]
struct TraceRouteSpec {
    /// Use IPv4 (default)
    #[structopt(short="4",parse(try_from_str = "parse_af"))]
    V4: af, // af: AddressFamily ,src_addr: SockAddr,
    /// Use IPv6
    #[structopt(short="6",parse(try_from_str = "parse_af"))]
    V6: af, // af: AddressFamily,
    /// Don't fragment
    F: bool, // NOT IMPLEMENTED
    /// Use ICMP protocol for outgoing packet
    I: bool, // proto: TraceProtocol::ICMP,
    /// Name resolution during each run
    r: bool, // NOT IMPLEMENTED
    /// Use UDP protocol for outgoing packet
    U: bool, // proto: TraceProtocol::UDP,
    /// Use TCP protocol for outgoing packet (SYN packet)
    T: bool, // proto: TraceProtocol::TCP,
    /// Enable Paris traceroute
    a: bool, // -a <paris modulus> NOT IMPLEMENTED
    /// packets per hop
    c: u8, // DEFAULT_TRT_COUNT
    /// starting hop
    f: u8, // START_TTL
    /// Gap limit
    g: u8, // NOT IMPLEMENTED
    /// Max hops
    m: u8, // max hops DEFAULT_MAX_HOPS
    /// Destination port
    p: u16, // dst_addr
    /// No Reply Timeout (ms)
    w: u16, // timeout
    /// Duplicate timeout (ms)
    z: u16, // NOT IMPLEMENTED
    /// Atlas Measurement ID
    A: u16, // ident
    /// Add IPv6 Destination Option this size
    D: u8, // NOT IMPLEMENTED,
    /// Add IPv6 Hop-by-hop Option this size"
    H: u8,
    /// Name of output file 
    #[structopt(parse(from_os_str))]
    O: Option<PathBuf>,
    /// Size of packet
    S: u8, // NOT IMPLEMENTED
    /// Destination address or hostname
    dst_addr: String, //to SocketAddr,
}

fn main() {
    println!("type: traceroute");
    let mut args = env::args();
    let ip: String = args.nth(1).unwrap() + ":0";
    let addr: &str = &ip;

    println!("dst_name: {}", env::args().nth(1).unwrap());

    // TODO: no improvement at all,
    // in fact swallows the error message while still panicing.
    match traceroute::start(addr) {
        Ok(t) => {
            for result in t {
                match &result {
                    Err(e) => {
                        println!("{}", e);
                    }
                    Ok(r) => { println!("{}", serde_json::to_string_pretty(r).unwrap()) },
                }
                // println!("{}", serde_json::to_string_pretty(&result).unwrap());
            }
        }
        Err(err) => {
            println!("{}", err);
        }
    };

    // for result in traceroute::start(addr).unwrap() {
    //     println!("{}", serde_json::to_string_pretty(&result).unwrap());

    //     println!("{:?}", result_ip.hop);
    //     for hop in result_ip.result {
    //         //let hop = result_ip; // .unwrap();
    //         match hop {
    //             // Ok(hop) => println!(
    //             //     "{} {} ({}) {}B {:?}",
    //             //     hop.ttl,
    //             //     hop.hop_name,
    //             //     hop.host.ip(),
    //             //     hop.size,
    //             //     hop.rtt
    //             // ),
    //             Ok(hop) => println!("{:?}", serde_json::to_string(&hop).unwrap()),
    //             Err(err) => println!("{:?}", serde_json::to_string(&err).unwrap()),
    //         }
}
// println!("--")
//     // println!(
//     //     "{} {} ({}) {}B {}ms",
//     //     hop.ttl,
//     //     hop.hop_name,
//     //     hop.host.ip(),
//     //     hop.size,
//     //     hop.rtt.num_microseconds().unwrap() as f64 / 1000.0
//     // );
//     //println!("{:?}", hop);
//     // }
// }
