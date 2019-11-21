#[macro_use]
use structopt;

// use serde;
use serde_json;

// use std::env;
use std::path::PathBuf;
// use std::str::FromStr;
use structopt::StructOpt;

use traceroute::libtraceroute::start::{
    sync_start_with_timeout, AddressFamily, TraceProtocol, TraceRouteSpec,
};

// use trac::d::*;

// „I prefer zeroes on the loose
// to those lined up behind a cipher.‟
// Wisława Szymborska - “Possibilities”

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

// TODO: ALL println! need to be replaced by io::stdout with
// proper error handling (no .unwrap()), because the rust
// wlll panic if stdout goes away and we're writing to stdout.
// And this is way more common than you'd think ( | head does this!)
const DEFAULT_TRACE_PROTOCOL: TraceProtocol = TraceProtocol::ICMP;
const DEFAULT_TCP_DEST_PORT: u16 = 0x5000; // port 0x50 (80) is the actual UI default in Atlas.
const DEFAULT_PACKETS_PER_HOP: u8 = 3;
const DEFAULT_PACKET_IN_TIMEOUT: i64 = 1;
const DEFAULT_PARIS_ID: u8 = 0x0F;
const DEFAULT_START_TTL: u16 = 0; // yeah,yeah, wasting a byte here, but we're going to sum this with DST_BASE_PORT
const DEFAULT_MAX_HOPS: u16 = 255; // max hops to hopperdehop

#[derive(Debug, StructOpt)]
#[structopt(
    name = "atlas-traceroute",
    about = "Perfom a RIPE Atlas compliant traceroute."
)]
struct TraceRouteOpt {
    /// Use IPv4 (default)
    // #[structopt(short = "4", parse(try_from_str = "parse_af"))]
    // v4: Option<AddressFamily>, // af: AddressFamily ,src_addr: SockAddr,
    #[structopt(short = "4")]
    v4: bool,
    /// Use IPv6
    // #[structopt(short = "6", parse(try_from_str = "parse_af"))]
    // v6: Option<AddressFamily>, // af: AddressFamily,
    #[structopt(short = "6")]
    v6: bool,
    // Don't fragment
    // F: bool, // NOT IMPLEMENTED
    /// Use ICMP protocol for outgoing packet
    #[structopt(short = "I")]
    proto_icmp: bool, // proto: TraceProtocol::ICMP,
    // Name resolution during each run
    // r: bool, // NOT IMPLEMENTED
    /// Use UDP protocol for outgoing packet
    #[structopt(short = "U")]
    proto_udp: bool, // proto: TraceProtocol::UDP,
    /// Use TCP protocol for outgoing packet (SYN packet)
    #[structopt(short = "T")]
    proto_tcp: bool, // proto: TraceProtocol::TCP,
    /// Enable Paris traceroute, with optional paris id
    #[structopt(short = "a", long = "paris", name = "enable paris traceroute")]
    paris: Option<Option<u8>>, // DEFAULT_PARIS_ID
    /// packets per hop
    #[structopt(short = "c", long = "trt_count", name = "packets per hop")]
    packets_per_hop: Option<u8>, // DEFAULT_TRT_COUNT
    /// starting hop
    #[structopt(short = "f", name = "start ttl")]
    start_ttl: Option<u16>, // START_TTL
    // Gap limit
    // g: u8, // NOT IMPLEMENTED
    /// Max hops
    #[structopt(short = "m", long = "max_hops", name = "maximum number of hops")]
    max_hops: Option<u16>, // max hops DEFAULT_MAX_HOPS
    /// Destination port
    #[structopt(short = "p", long = "port", name = "destination port")]
    tcp_dest_port: Option<u16>, // dst_addr
    /// No Reply Timeout (ms)
    #[structopt(short = "w", long = "timeout", name = "timeout")]
    timeout: Option<i64>, // timeout
    // Duplicate timeout (ms)
    // z: u16, // NOT IMPLEMENTED
    /// Atlas Measurement ID
    #[structopt(short = "A", long = "uuid", name = "RIPE Atlas unique identifier")]
    A: Option<String>, // ident
    // Add IPv6 Destination Option this size
    // D: u8, // NOT IMPLEMENTED,
    // Add IPv6 Hop-by-hop Option this size"
    // H: u8,
    /// Name of output file
    #[structopt(short = "O", parse(from_os_str))]
    O: Option<PathBuf>,
    // Size of packet
    // S: u8, // NOT IMPLEMENTED
    /// Destination address or hostname
    #[structopt(name = "destination address")]
    dst_addr: String, //to SocketAddr,
    /// Public IP address of the interface used (in case of NAT) to use in checksum calculation
    #[structopt(short = "i", long = "publicip", name = "public ip address")]
    // -- this traceroute implementation specific options (not in atlas probes) --
    public_ip: Option<String>,
    #[structopt(short = "v", long = "verbose", name = "print packets breakdown")]
    verbose: bool,
}

fn main() {
    println!("type: traceroute");
    let opt = TraceRouteOpt::from_args();
    println!("{:?}", opt);
    // let mut args = env::args();
    let ip: String = opt.dst_addr + ":0";
    let addr: &str = &ip;

    let af: Result<Option<AddressFamily>, &str> = match (opt.v4, opt.v6) {
        (true, false) => Ok(Some(AddressFamily::V4)),
        (false, true) => Ok(Some(AddressFamily::V6)),
        (false, false) => Ok(None),
        _ => Err("cannot specify both address families"),
    };

    let proto: Result<TraceProtocol, &str> = match (opt.proto_icmp, opt.proto_udp, opt.proto_tcp) {
        (true, false, false) => Ok(TraceProtocol::ICMP),
        (false, true, false) => Ok(TraceProtocol::UDP),
        (false, false, true) => Ok(TraceProtocol::TCP),
        (false, false, false) => Ok(DEFAULT_TRACE_PROTOCOL),
        _ => Err("cannot specify more than one protocol"),
    };

    let spec = TraceRouteSpec {
        proto: proto.unwrap(),
        af: af.unwrap(),
        start_ttl: match opt.start_ttl {
            Some(sl) => sl,
            None => DEFAULT_START_TTL,
        },
        max_hops: match opt.max_hops {
            Some(mh) => mh,
            None => DEFAULT_MAX_HOPS,
        },
        packets_per_hop: match opt.packets_per_hop {
            Some(pph) => pph,
            None => DEFAULT_PACKETS_PER_HOP,
        },
        paris: match opt.paris {
            Some(paris_id) => Some(paris_id.unwrap_or(DEFAULT_PARIS_ID)),
            None => None,
        },
        tcp_dest_port: match opt.tcp_dest_port {
            Some(p) => p,
            None => DEFAULT_TCP_DEST_PORT,
        },
        timeout: match opt.timeout {
            Some(t) => t,
            None => DEFAULT_PACKET_IN_TIMEOUT,
        },
        uuid: "ATLAS-TRACE-EX".to_string(),
        public_ip: opt.public_ip,
        verbose: opt.verbose,
    };
    // println!("dst_name: {}", env::args().nth(1).unwrap());

    // TODO: no improvement at all,
    // in fact swallows the error message while still panicing.
    match sync_start_with_timeout(addr, &spec) {
        Ok(mut traceroute) => {
            traceroute.start_time = Some(time::get_time().sec);
            println!("traceroute meta: {:?}", traceroute);
            for result in traceroute.trace_hops {
                match &result {
                    Err(e) => {
                        println!("{:?}", e);
                    }
                    Ok(r) => {
                        println!("{}", serde_json::to_string_pretty(r).unwrap());
                        if spec.verbose {
                            println!("END HOP {}", r.hop);
                            println!("==============");
                            println!("");
                        };
                    }
                }
            }
        }
        Err(err) => {
            println!("{}", err);
        }
    };
}
