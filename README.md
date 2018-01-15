# Atlas-traceroute

Re-implentation in Rust of the traceroute command as run by the [RIPE Atlas](https://atlas.ripe.net) Probes.

This re-implentation has the following objectives:
- Fully compliant with the specs of the traceroutes that are ran by the RIPE Atlas probes,
  meaning being able to run ICMP, UDP and TCP in ipv4/ipv6 with all options.
- RIPE Atlas compliant JSON output.
- A Stand-alone CLI tool. Just run traceroute <OPTIONS> <IP-ADDRESS OR HOSTNAME>.
- As cross-platform as possible. Should at leat run on OSX, Linux and win32. Any BSDs would be great.
- Use as many (rest) APIs as possible to enrich the traceroute, e.g. location data for hop hosts, AS allocations of hop hosts, etc.
- Offer async, concurrent packet tx/rx, as well as async dns lookups.
- Run simultaneous dual-stack traceroutes.

implemented features right now:

- ICMP type
- dual-stack IPv4/6
- hostname lookups
- interface auto-detection

everything untested. everything still runs synchronised.

# Installation

I am not supplying binaries for any platforms anytime soon. 
So you'll have to have an up-to-date Rust installation, probably set up with `rustup`.

Relies on rust-nightly (`rustup install nightly` and `rustup default nightly`).
Relies on upstream changes in the crates libc, socket2 and pnet. I will make a PR for those once I've made tests for the changes.
