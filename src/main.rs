extern crate traceroute;

use std::env;

fn main() {
    println!("type: traceroute");
    let mut args = env::args();
    let ip: String = args.nth(1).unwrap() + ":0";
    let addr: &str = &ip;
    println!("dst_name: {}", env::args().nth(1).unwrap());
    for result_ip in traceroute::start(addr).unwrap() {
        let hop = result_ip.unwrap();
        println!(
            "{} {} ({}) {}B {}ms",
            hop.ttl,
            hop.hop_name,
            hop.host.ip(),
            hop.size,
            hop.rtt.num_microseconds().unwrap() as f64 / 1000.0
        );
        //println!("{:?}", hop);
    }
}
