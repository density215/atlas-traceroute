# atlas-traceroute

Re-implentation in Rust of the traceroute command as run by the [RIPE Atlas](https://atlas.ripe.net) Probes.

This re-implentation wants to be the following things:
- Fully compliant with the specs of the traceroutes that are ran by the RIPE Atlas probes,
  meaning being able to run ICMP, UDP and TCP in ipv4/ipv6 with all options.
- A Stand-alone CLI tool. Just run traceroute <OPTIONS> <IP-ADDRESS OR HOSTNAME>.
- As cross-platform as possible. Should at leat run on OSX, Linux and win32. Any BSDs would be great.
- Use as many (rest) APIs as possible to enrich the traceroute, e.g. location data for hop hosts, AS allocations of hop hosts, etc.

Right now, it's not more than a implentation of a ICMPv4 traceroute with hostname lookup for all hophosts.

# installation

I am not supplying binaries for any platforms anytime soon. 
So you'll have to have an up-to-date Rust installation, probably set up with `rustup`.

Then you could run it with `sudo cargo run -- <IP_ADDRESS_OR_HOSTNAME>` or build it with `cargo build` and then use the binray in `target/debug`. 
