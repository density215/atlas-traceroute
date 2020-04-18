use crate::libtraceroute::iterators::*;
use byteorder::ByteOrder;
use hex_slice::AsHex;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::{checksum, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::{Icmpv6Types, MutableIcmpv6Packet};
use pnet::packet::tcp::ipv4_checksum as tcp_ipv4_checksum;
use pnet::packet::tcp::TcpFlags::SYN;
use pnet::packet::tcp::{ipv6_checksum as tcp_ipv6_checksum, MutableTcpPacket, TcpPacket};
use pnet::packet::udp::{ipv4_checksum, ipv6_checksum};
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};

use pnet::packet::Packet;
use std::net::{IpAddr, SocketAddr};

pub enum PacketType<'a> {
    UDP(UdpPacket<'a>),
    TCP(TcpPacket<'a>),
}

impl<'a> PacketType<'a> {
    pub fn checksum_for_af(&self, &src_ipaddr: &IpAddr, &dst_ipaddr: &IpAddr) -> u16 {
        match &self {
            PacketType::UDP(p) => match &src_ipaddr {
                IpAddr::V4(src_ip) => {
                    if let IpAddr::V4(dst_ip) = dst_ipaddr {
                        ipv4_checksum(&p, &src_ip, &dst_ip)
                    } else {
                        panic!("wrong ip address type, combination of ipv4 and ipv6");
                    }
                }
                IpAddr::V6(src_ip) => {
                    if let IpAddr::V6(dst_ip) = dst_ipaddr {
                        ipv6_checksum(&p, &src_ip, &dst_ip)
                    } else {
                        panic!("wrong ip address type, combination of ipv4 and ipv6");
                    }
                }
            },
            PacketType::TCP(p) => match &src_ipaddr {
                IpAddr::V4(src_ip) => {
                    if let IpAddr::V4(dst_ip) = dst_ipaddr {
                        tcp_ipv4_checksum(&p, &src_ip, &dst_ip)
                    } else {
                        panic!("wrong ip address type, combination of ipv4 and ipv6");
                    }
                }
                IpAddr::V6(src_ip) => {
                    if let IpAddr::V6(dst_ip) = dst_ipaddr {
                        tcp_ipv6_checksum(&p, &src_ip, &dst_ip)
                    } else {
                        panic!("wrong ip address type, combination of ipv4 and ipv6");
                    }
                }
            },
        }
    }
}

pub fn make_icmp_packet_out(src_addr: &SocketAddr, ident: u16, seq_num: u16) -> Vec<u8> {
    match src_addr {
        &SocketAddr::V4(_) => {
            let icmp_buffer = vec![00u8; ICMP_HEADER_LEN];
            let mut echo_request_packet = MutableEchoRequestPacket::owned(icmp_buffer).unwrap();
            echo_request_packet.set_icmp_type(IcmpTypes::EchoRequest);
            echo_request_packet.set_identifier(ident);
            echo_request_packet.set_sequence_number(seq_num);
            // checksum needs to be set automatically
            // failing to set will have the traceroute run until exhaustion
            let p_checksum = checksum(&IcmpPacket::new(&echo_request_packet.packet()).unwrap());
            echo_request_packet.set_checksum(p_checksum);
            echo_request_packet.packet().to_owned()
        }
        &SocketAddr::V6(_) => {
            let icmp_buffer = vec![00u8; ICMP_HEADER_LEN];
            let mut echo_request_packet = MutableIcmpv6Packet::owned(icmp_buffer).unwrap();
            echo_request_packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
            echo_request_packet.set_identifier(ident);
            echo_request_packet.set_sequence_number(seq_num);
            echo_request_packet.packet().to_owned()
        }
    }
}

pub fn make_udp_packet_out(
    src_addr: &SocketAddr,
    dst_addr: &SocketAddr,
    seq_num: u16,
    paris: Option<u8>,
    verbose: bool,
) -> Vec<u8> {
    let udp_buffer = vec![0x00; UDP_HEADER_LEN + 0x02];
    let mut udp_packet = MutableUdpPacket::owned(udp_buffer).unwrap();
    udp_packet.set_source(SRC_BASE_PORT);
    let src_ip: IpAddr = src_addr.ip();
    let dst_ip: IpAddr = dst_addr.ip();

    match paris {
        // 'classic' traceroute
        // uses the dst_port to fingerprint returning ICMP packets.
        // So for each hop the dst_port is increased with one,
        // so we can differentiate between them. easy.
        None => {
            udp_packet.set_destination(seq_num + DST_BASE_PORT);
        }
        // paris traceroute
        // paris traceroute tries to keep the five
        // tos, proto, src_addr, dst_addr, src_port, dst_port as
        // invariants between hops for UDP (TCP and ICMP traceroutes work diffrerently).
        // So this rules out the dst_port trick that 'classic' uses.
        // As an alternative strategy paris traceroute tries to vary the
        // checksum field between hops, thus using it as an identifier for a hop.
        // As a consequence the payload needs to be calculated to fit the desired checksum.
        //
        // Since I have no desire to reimplement the UDP checksum from scratch, let alone
        // implement the reverse algorithm (yeah, I know, not hard, one's complement and carry bit, yada, yada),
        // I've decided to first calculate a temporary checksum with the payload set to zero.
        // Then I can calculate by how much
        // the payload needs to increased to offset to the desired the checksum.
        // This is actually pretty easy, because if the pauyload is increased by 0x01,
        // the checksum goes down by 0x01...
        Some(_paris_id) => {
            udp_packet.set_destination(DST_BASE_PORT);
            udp_packet.set_length(0x00);
            udp_packet.set_payload(&vec![0x00; 2]);
            let temp_checksum = PacketType::UDP(udp_packet.to_immutable())
                .checksum_for_af(&src_ip, &dst_ip)
                - 0x0a
                - seq_num;
            if verbose {
                println!("paris traceroute (id): {:?}", paris.unwrap());
                println!("temp checksum (udp payload): {:02x}", temp_checksum);
            }
            udp_packet.set_payload(&temp_checksum.to_be_bytes());
        }
    }
    udp_packet.set_source(SRC_BASE_PORT);
    udp_packet.set_length(0x0a);
    let udp_checksum = PacketType::UDP(udp_packet.to_immutable()).checksum_for_af(&src_ip, &dst_ip);
    udp_packet.set_checksum(udp_checksum);
    if verbose {
        println!("udp checksum: {:02x}", udp_checksum);
    }
    udp_packet.packet().to_owned()
}

pub fn make_tcp_packet_out(
    src_addr: &SocketAddr,
    dst_addr: &SocketAddr,
    seq_num: u16,
    ident: u16,
    paris: Option<u8>,
    tcp_dest_port: u16,
    verbose: bool,
) -> Vec<u8> {
    let tcp_buffer: Vec<u8>;
    let src_ip: &IpAddr = &src_addr.ip();
    let dst_ip: &IpAddr = &dst_addr.ip();

    match src_addr {
        SocketAddr::V4(_) => {
            tcp_buffer = vec![00u8; TCP_HEADER_LEN];
        }
        SocketAddr::V6(_) => {
            tcp_buffer = vec![00u8; 22];
        }
    }
    let mut tcp_packet = MutableTcpPacket::owned(tcp_buffer).unwrap();
    let payload = &mut [00u8; 2];
    byteorder::NetworkEndian::write_u16(payload, ident);
    tcp_packet.set_sequence(seq_num.into());
    tcp_packet.set_payload(payload);
    // this seems to be a viable minimum (20 bytes of header length; ask wireshark)
    tcp_packet.set_data_offset(5);
    tcp_packet.set_flags(SYN);
    tcp_packet.set_source(SRC_BASE_PORT);

    // Same paris traceroute story applies to TCP
    match paris {
        None => {
            println!("classic traceroute");
            tcp_packet.set_destination(seq_num + tcp_dest_port);
        }
        Some(_paris_id) => {
            tcp_packet.set_destination(tcp_dest_port);
            tcp_packet.set_payload(&vec![0x00; 2]);
            let temp_checksum = PacketType::TCP(tcp_packet.to_immutable())
                .checksum_for_af(src_ip, dst_ip)
                - 0x0a
                - seq_num;
            if verbose {
                println!("paris traceroute (id): {:?}", paris.unwrap());
                println!("temp checksum (udp payload): {:02x}", temp_checksum);
            }
            tcp_packet.set_payload(&temp_checksum.to_be_bytes());
        }
    }

    let tcp_checksum = PacketType::TCP(TcpPacket::new(&tcp_packet.packet()).unwrap())
        .checksum_for_af(src_ip, dst_ip);
    tcp_packet.set_checksum(tcp_checksum);
    if verbose {
        println!("tcp checksum: {:02x}", tcp_checksum);
        println!("packet created: {:02x}", &tcp_packet.packet().as_hex());
        println!("src used in checksum: {:?}", src_ip);
        println!("dst used in checksum: {:?}", dst_ip);
    }
    tcp_packet.packet().to_owned()
}
