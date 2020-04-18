use byteorder;
use hex_slice;
use pnet;

use std::io::{Error, ErrorKind};
use std::net::{IpAddr, SocketAddr};

use pnet::packet::icmp::destination_unreachable::DestinationUnreachablePacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Packet, Icmpv6Types};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::ipv4_checksum as tcp_ipv4_checksum;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::udp::ipv4_checksum;
use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::Packet;

// only used for debug printing packets
use byteorder::{ByteOrder, NetworkEndian};
use hex_slice::AsHex;

use crate::libtraceroute::debug::debug_print_packet_in;
use crate::libtraceroute::iterators::*;
use crate::libtraceroute::start::TraceProtocol;

pub fn static_unwrap_payload_ip_packet_in(
    buf_in: &[u8],
    src_addr: SocketAddr,
    verbose: bool,
) -> (IcmpPacketIn, u8) {
    if verbose {
        match &buf_in[0] {
            0x45 => {
                println!("src addr source packet: {:?}", &buf_in[12..16]);
                println!("dst addr source packet: {:?}", &buf_in[16..20]);
            }
            _ => {
                println!("src addr source packet: {:02x}", &buf_in[32..48].as_hex());
                println!("dst addr source packet: {:02x}", &buf_in[16..32].as_hex());
            }
        };
    };

    let ttl_in: u8;
    match src_addr {
        SocketAddr::V4(_) => {
            let pack = Ipv4Packet::owned(buf_in.to_owned()).unwrap();
            ttl_in = pack.get_ttl();
            (IcmpPacketIn::V4(pack), ttl_in)
        }
        // IPv6 holds IP header of incoming packet in ancillary data, so
        // we unpack the ICMPv6 packet directly here.
        SocketAddr::V6(_) => {
            let icmp_pack = Icmpv6Packet::owned(buf_in.to_owned()).unwrap();
            let ip_pack = Ipv6Packet::owned(buf_in.to_owned()).unwrap();
            (IcmpPacketIn::V6(icmp_pack), ip_pack.get_hop_limit())
        }
    }
}

fn static_analyse_icmp_packet_in(
    wrapped_ip_packet: &[u8],
    icmp_packet_in: &[u8],
    packet_out: &[u8],
    proto: TraceProtocol,
    public_ip: Option<IpAddr>,
    paris: Option<u8>,
    verbose: bool,
) -> Result<Option<u8>, Error> {
    // We don't have any ICMP header data right now
    // So we're only using the last 4 bytes in the payload to compare.
    // println!("wrapped ip packet: {:02x}", wrapped_ip_packet[..32].as_hex());

    // in TCP we witness that reflected packets are sometimes cutoff after 12 bytes,
    // and filled with zeros up till 4176 bytes (or less).
    // Another situation is that their length might be less than 12 bytes
    // sent out by us as a packet.
    // So we're taking *up to* 12 bytes of the reflected packet.
    // println!("{:02x}",wrapped_ip_packet[..packet_out.len()].as_hex());
    let wrapped_ip_snip: &[u8] = match packet_out.len() {
        l if l > 12 => &wrapped_ip_packet[..12],
        _ => &wrapped_ip_packet[..packet_out.len()],
    };
    // UDP paris traceroutes have to rely on the checksum of the udp header to match up the
    // hop number of the packet sent and the icmp packet received. However if our
    // machine is behind a NAT, then the router performning NAT will very likely rewrite
    // the UDP checksum of the outhoing packet to match the src IP address of the public ip
    // address, hence the --publicip option.
    // This process has no knowledge of the public ip address, so we have to rewrite
    // the expected IP packet to have the checksum reflect the public address as set by
    // the user.
    // Note that we're also checking if the incoming packet matches with our original
    // created outgoing packet, in case the user inappropriately set the public_ip property
    // in the spec. (like there's no NAT after all, or the public ip address is wrong).
    // Also note that this *only* applies to UDP paris traceroutes and even then only
    // if you want to sent packets in async/burst mode. In sync mode we sent one packet
    // and wait for the timeout per hop and matching the source ports in the udp header
    // is enough.
    let pub_ip = match public_ip {
        Some(ipip) => match ipip {
            IpAddr::V4(ip) => Some(ip),
            _ => panic!("wtf, this is not an ipv4 address!"),
        },
        None => None,
    };

    let expected_packet = match proto {
        TraceProtocol::UDP => {
            let mut udp_packet = MutableUdpPacket::owned(packet_out.to_vec()).unwrap();
            match &pub_ip {
                Some(public_ip) => {
                    // let mut udp_packet = MutableUdpPacket::owned(packet_out.to_vec()).unwrap();
                    udp_packet.set_checksum(ipv4_checksum(
                        &udp_packet.to_immutable(),
                        // the public ip address used in NAT
                        // &<std::net::Ipv4Addr>::new(83,160,104,137),
                        // the IP of the if to send this packet out (no NAT)
                        // &<std::net::Ipv4Addr>::from_str(public_ip).unwrap(),
                        &public_ip,
                        // the dst of the traceroute
                        &<std::net::Ipv4Addr>::new(
                            icmp_packet_in[24],
                            icmp_packet_in[25],
                            icmp_packet_in[26],
                            icmp_packet_in[27],
                        ),
                    ));
                    udp_packet.packet().to_owned()
                }
                _ => packet_out.to_owned(),
            }
        }
        TraceProtocol::TCP => {
            let mut tcp_packet = MutableTcpPacket::owned(packet_out.to_vec()).unwrap();
            let pub_ip = match public_ip {
                Some(IpAddr::V4(ip)) => Some(ip),
                _ => None,
            };

            match &pub_ip {
                Some(public_ip) => {
                    // let mut udp_packet = MutableUdpPacket::owned(packet_out.to_vec()).unwrap();
                    tcp_packet.set_checksum(tcp_ipv4_checksum(
                        &tcp_packet.to_immutable(),
                        // the public ip address used in NAT
                        // &<std::net::Ipv4Addr>::new(83,160,104,137),
                        // the IP of the if to send this packet out (no NAT)
                        // &<std::net::Ipv4Addr>::from_str(public_ip).unwrap(),
                        public_ip,
                        // the dst of the traceroute
                        &<std::net::Ipv4Addr>::new(
                            icmp_packet_in[24],
                            icmp_packet_in[25],
                            icmp_packet_in[26],
                            icmp_packet_in[27],
                        ),
                    ));
                    if verbose {
                        println!("checksum rewritten using dst_addr {:?}", &public_ip);
                    };
                    tcp_packet.packet().to_owned()
                }
                _ => packet_out.to_owned(),
            }
        }
        _ => packet_out.to_owned(),
    };

    if verbose {
        debug_print_packet_in(&proto, &icmp_packet_in, &packet_out, &expected_packet);
    };

    match &proto {
        &TraceProtocol::ICMP if wrapped_ip_packet[4..8] == packet_out[4..8] => Ok(None),
        /* Some routers may return all of the udp packet we sent, so including the
         * payload.
         */
        &TraceProtocol::ICMP
            if wrapped_ip_packet[0..2] == packet_out[0..2]
            // rough estimation, this assumes first byte of dst_port does not change.
                && wrapped_ip_packet[4..5] == packet_out[4..5] =>
        {
            if verbose {
                println!("😐 OTHER HOP (hop number {:?})", &wrapped_ip_packet[7]);
            };
            Ok(Some(wrapped_ip_packet[7]))
        }
        &TraceProtocol::UDP
            if wrapped_ip_packet.to_vec() == expected_packet || wrapped_ip_packet == packet_out =>
        {
            if verbose {
                println!("😍 PERFECT MATCH (checksum, payload)");
            };
            Ok(None)
        }
        /* This should be the 'normal' situation, where 8 bytes from the udp packet
         * we sent are returned, i.e. the udp header
         */
        &TraceProtocol::UDP
            if wrapped_ip_packet[..8] == expected_packet[..8]
                || wrapped_ip_packet[..8] == packet_out[..8] =>
        {
            if verbose {
                println!("😁 CHECKSUM MATCH (no payload)");
            };
            Ok(None)
        }
        // this from the atlas traceroute probes implentation:
        /* Unfortunately, cheap home routers may
         * forget to restore the checksum field
         * when they are doing NAT. Ignore the
         * sequence number if it seems wrong.
         */
        &TraceProtocol::UDP
            if wrapped_ip_packet[9..10] == expected_packet[9..10]
                || wrapped_ip_packet[9..10] == packet_out[9..10] =>
        {
            if verbose {
                println!("😐 PAYLOAD AND SRC PORT MATCH ONLY (no checksum)");
            };
            Ok(None)
        }
        // tnis might be a hop from an earlier probe, so then
        // dst_port should be higher than or equal to the udp base port
        // (a constant for now), but lower than UDP_BASE_PORT + this hopnr
        &TraceProtocol::UDP
            if paris.is_none()
                && NetworkEndian::read_u16(&wrapped_ip_packet[2..4]) >= DST_BASE_PORT
                && NetworkEndian::read_u16(&wrapped_ip_packet[2..4]) <= DST_BASE_PORT + 0xff =>
        {
            println!("wrong hopno! earlier hop");
            Ok(Some(wrapped_ip_packet[7]))
        }
        // check to see if the source ports on the packet out and the reflected packet
        // match up. This is for classic sync traceroute only.
        &TraceProtocol::UDP
            if wrapped_ip_packet[2..4] == expected_packet[2..4]
                || wrapped_ip_packet[2..4] == packet_out[2..4] =>
        {
            if verbose {
                println!("😐 SRC PORT MATCH ONLY (no payload, no checksum)");
                println!("icmp packet in: {:02x}", icmp_packet_in[..64].as_hex());
                println!(
                    "returned packet snip: {:02x}",
                    icmp_packet_in[28..36].as_hex()
                );
            }
            Ok(None)
        }
        &TraceProtocol::TCP
            if wrapped_ip_packet[..22] == expected_packet[..22]
                || wrapped_ip_packet[..22] == packet_out[..22] =>
        {
            if verbose {
                println!("😍 PACKETS MATCHED");
            }
            Ok(None)
        }
        &TraceProtocol::TCP if wrapped_ip_packet[4..8] == expected_packet[4..8] => {
            if verbose {
                println!("😁 SRC PORT AND SEQUENCE NUMBER MATCHED");
            }
            Ok(None)
        }
        &TraceProtocol::TCP
            if wrapped_ip_packet[16..18] == expected_packet[16..18]
                || wrapped_ip_packet[16..18] == packet_out[16..18] =>
        {
            if verbose {
                println!("😁 SRC PORT AND CHECKSUM MATCH (no sequence number, no payload)");
            };
            Ok(None)
        }
        // see the above comment about cutting off of reflected ip packets
        &TraceProtocol::TCP if wrapped_ip_snip == &expected_packet[..wrapped_ip_snip.len()] => {
            if verbose {
                println!(
                    "😐 SRC AND DST PORT MATCH ONLY (no sequence number, no checksum, no payload)"
                );
            }
            Ok(None)
        }
        &TraceProtocol::TCP if icmp_packet_in[28..30] == expected_packet[..2] => {
            if verbose {
                println!("😐 OTHER HOP (hop number {:?})", &icmp_packet_in[35]);
            }
            Ok(None)
        }
        _ => {
            if verbose {
                println!("😠 UNIDENTIFIED INCOMING PACKET");
                print!("packet out {:?}: {:02x}", &proto, &packet_out.as_hex());
                print!(" -> ");
                println!("icmp payload: {:02x}", &wrapped_ip_packet[..64].as_hex());
                println!(
                    "64b of icmp in packet: {:02x}",
                    &icmp_packet_in[..64].as_hex()
                );
                println!(
                    "packet in byte 28 -> ${:02x}",
                    &icmp_packet_in[28..64].as_hex()
                );
            };
            Err(Error::new(
                ErrorKind::InvalidData,
                "invalid TimeExceeded packet",
            ))
        }
    }
}

pub fn static_analyse_v4_payload(
    packet_out: &[u8],
    // icmp_packet_in: &IcmpPacket,
    // ip_payload: &[u8],
    ip_packet_in: pnet::packet::ipv4::Ipv4Packet,
    ident_collection: &Vec<u16>,
    // seq_num: u16,
    // max_hops: u16,
    // ttl: u16,
    proto: TraceProtocol,
    public_ip: Option<IpAddr>,
    paris: Option<u8>,
    verbose: bool,
) -> (Result<Option<u8>, Error>, bool) {
    let ip_payload = ip_packet_in.payload();
    let icmp_packet_in = IcmpPacket::new(&ip_packet_in.payload()).unwrap();

    match icmp_packet_in.get_icmp_type() {
        IcmpTypes::TimeExceeded => {
            // This is where intermediate packets with TTL set to lower than the number of hops
            // to the final server should be answered as.
            //
            // `Time Exceeded` packages do not have a identifier or sequence number
            // They do return up to 576 bytes of the original IP packet
            // So that's where we identify the packet to belong to this `packet_out`.

            // It's not up to this function anymore to decide whether the ttl is incorrect
            // that only works for sync traceroutes.
            // if ttl == max_hops {
            //     // self.done = true;
            //     return (Err(Error::new(ErrorKind::TimedOut, "too many hops")), true);
            // }
            let icmp_time_exceeded = TimeExceededPacket::new(ip_payload)
                .unwrap()
                .payload()
                .to_owned();
            let wrapped_ip_packet = Ipv4Packet::new(&icmp_time_exceeded).unwrap();

            // We don't have any ICMP data right now
            // So we're only using the last 4 bytes in the payload to compare.
            (
                static_analyse_icmp_packet_in(
                    wrapped_ip_packet.payload(),
                    &icmp_packet_in.packet(),
                    packet_out,
                    proto,
                    public_ip,
                    paris,
                    verbose,
                ),
                false,
            )
        }

        // If the outgoing packet was icmp then the final
        // packages from the requested server should come as ICMP type Echo Reply
        IcmpTypes::EchoReply => {
            let icmp_echo_reply = EchoReplyPacket::new(&ip_payload).unwrap();
            if verbose {
                println!(
                    "{:?} -> {:?}",
                    icmp_echo_reply.get_identifier(),
                    ident_collection
                );
            }
            if ident_collection.contains(&icmp_echo_reply.get_identifier())
            // && icmp_echo_reply.get_sequence_number() <= max_hops
            {
                // self.done = true;
                (Ok(Some(icmp_packet_in.packet()[7] as u8)), true)
            } else {
                (Err(Error::new(ErrorKind::InvalidData, "invalid ")), false)
            }
        }

        // UDP and TCP packets that were sent out should get these as the final answer,
        // that is, only if the requested server does not listen on the destination port!
        IcmpTypes::DestinationUnreachable => {
            // self.done = true;

            let dest_unreachable = DestinationUnreachablePacket::new(&ip_payload)
                .unwrap()
                .payload()
                .to_owned();
            let wrapped_ip_packet = Ipv4Packet::new(&dest_unreachable).unwrap();
            //println!("{:02x}", wrapped_ip_packet.packet().as_hex());
            (
                static_analyse_icmp_packet_in(
                    wrapped_ip_packet.payload(),
                    &icmp_packet_in.packet(),
                    packet_out,
                    proto,
                    public_ip,
                    paris,
                    verbose,
                ),
                true,
            )
        }
        _ => {
            if verbose {
                println!("unknown : {:02x}", &ip_payload.as_hex());
            };
            (
                Err(Error::new(
                    ErrorKind::Other,
                    "unidentified packet type - ipv4",
                )),
                false,
            )
        }
    }
}

pub fn static_analyse_v6_payload(
    packet_out: &[u8],
    icmp_packet_in: &Icmpv6Packet,
    ident: u16,
    seq_num: u16,
    ident_collection: &Vec<u16>,
    max_hops: u16,
    ttl: u16,
    proto: TraceProtocol,
    public_ip: Option<IpAddr>,
    paris: Option<u8>,
    verbose: bool,
) -> (Result<Option<u8>, Error>, bool) {
    match icmp_packet_in.get_icmpv6_type() {
        Icmpv6Types::EchoReply => {
            //println!("icmp payload: {:02x}", icmp_packet_in.payload().as_hex());
            if icmp_packet_in.get_identifier() == ident
                && icmp_packet_in.get_sequence_number() == seq_num
            {
                // self.done = true;
                (Ok(None), true)
            } else {
                //println!("seq: {:?}", icmp_packet_in.get_sequence_number());
                (Err(Error::new(ErrorKind::InvalidData, "invalid ")), false)
            }
        }
        Icmpv6Types::DestinationUnreachable => (
            Err(Error::new(
                ErrorKind::AddrNotAvailable,
                "destination unreachable",
            )),
            false,
        ),
        Icmpv6Types::TimeExceeded => {
            //println!("time exceeded: {:02x}", icmp_packet_in.payload().as_hex());
            // `Time Exceeded` packages do not have a identifier or sequence number
            // They do return up to 576 bytes of the original IP packet
            // So that's where we identify the packet to belong to this `packet_out`.
            if ttl == max_hops {
                // self.done = true;
                return (Err(Error::new(ErrorKind::TimedOut, "too many hops")), true);
            }
            let wrapped_ip_packet = Ipv6Packet::new(&icmp_packet_in.payload()).unwrap();

            (
                static_analyse_icmp_packet_in(
                    wrapped_ip_packet.payload(),
                    &icmp_packet_in.packet(),
                    packet_out,
                    proto,
                    public_ip,
                    paris,
                    verbose,
                ),
                false,
            )
        }
        _ => {
            if verbose {
                println!("unknown : {:?}", icmp_packet_in.get_icmpv6_type());
                println!(
                    "64b of icmp packet in : {:02x}",
                    &icmp_packet_in.payload()[..64].as_hex()
                );
            };
            (
                Err(Error::new(
                    ErrorKind::Other,
                    "unidentified packet type - ipv6",
                )),
                false,
            )
        }
    }
}
