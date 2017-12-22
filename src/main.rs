extern crate traceroute;

use std::env;

fn main() {
    let mut args = env::args();
    let ip: String = args.nth(1).unwrap() + ":0";
    let addr: &str = &ip;
    for result_ip in traceroute::start(addr).unwrap() {
        let hop = result_ip.unwrap();
        println!(
            "{} {} ({}) {}ms",
            hop.ttl,
            hop.host_name,
            hop.host.ip(),
            hop.rtt.num_microseconds().unwrap() as f64 / 1000.0
        );
        //println!("{:?}", hop);
    }
}
