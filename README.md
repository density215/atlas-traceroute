# Treso

A modern, cross-platform traceroute library and CLI.

Treso has the following objectives:

- A Stand-alone CLI tool _and_ a library with a clear API.
- As cross-platform as possible. Runs and is tested on MacOs, Linux and Win32.
- Runs the full matrix of ICMP, UDP and TCP in ipv4/ipv6 with all options.
- Paris and 'Classic' traceroute.
- JSON output and classic, unstructured output.
- Use as many (rest) APIs as possible to enrich the traceroute, e.g. location data for hop hosts, AS allocations of hop hosts, etc.
- Offer both sync and async packet packet tx/rx, as well as async dns lookups.
- Run simultaneous dual-stack traceroutes.
- "RIPE Atlas compatibility mode" that accepts the same options as the RIPE Atlas probe traceroute, as well as the same JSON output schema.

Implemented features right now:

- ICMP/UDP/TCP type
- dual-stack IPv4/6
- hostname lookups
- classic and paris traceroute for all combinations of protocols and IP versions
- interface auto-detection
- CLI tooling with most options implemented

# Installation

Installation right now is from source only. You'll have to have an up-to-date Rust installation, probably set up with `rustup`.

Relies on rust-nightly (`rustup install nightly` and `rustup default nightly`).
Relies on some changes in crate pnet and mio (for the async traceroutes).

- Install Rust (https://rustup.rs/)
- Clone this Repo with `git clone`
- cd inside the repo
- Use nightly: `rustup override set nightly` (if you want nightly only in this repo).
- Clone the modified version of libpnet with `git clone https://github.com/density215/libpnet`
- Build a release with `cargo build --release`. The binary will be `target/release/traceroute`. Make sure you chown it to root and set suid bit on it `chmod +s traceroute` to be able to use raw sockets.
- For development you an use `cargo run -- <OPTION GO HERE>`. Probably you will have to either run this as root or prepend `cargo` with `sudo`. In either case you will have to install rust as root.
