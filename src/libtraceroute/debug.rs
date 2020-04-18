use hex_slice::AsHex;

use super::start::TraceProtocol;

// impl fmt::Debug for HopDuration {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         let HopDuration(d) = self;
//         write!(f, "{}µs", d.num_microseconds().unwrap())
//     }
// }

pub fn debug_print_packet_in(
    proto: &TraceProtocol,
    packet: &[u8],
    packet_out: &[u8],
    expected_udp_packet: &[u8],
) {
    println!("-------------------------");
    println!("outgoing packet");
    println!("-------------------------");
    match &proto {
        TraceProtocol::UDP => {
            println!("udp packet out: {:02x}", &packet_out.as_hex());
            println!("expected udp packet: {:02x}", &expected_udp_packet.as_hex());
        }
        TraceProtocol::TCP => {
            println!("tcp packet header out: {:02x}", &packet_out[..20].as_hex());
            println!("tcp payload out: {:02x}", &packet_out[20..].as_hex());
            println!(
                "expected tcp header: {:02x}",
                &expected_udp_packet[..20].as_hex()
            );
            println!(
                "expected tcp payload: {:02x}",
                &expected_udp_packet[20..].as_hex()
            );
        }
        TraceProtocol::ICMP => {
            println!("icmp packet out: {:02x}", &packet_out.as_hex());
            println!(
                "expected icmp payload: {:02x} (should be the same)",
                &expected_udp_packet.as_hex()
            );
        }
    }
    println!("-------------------------");
    println!("incoming packet breakdown");
    println!("-------------------------");
    println!("icmp header: {:02x}", &packet[..8].as_hex());
    println!("icmp body");
    println!("---------");
    match &packet[8] {
        0x45 => {
            println!("ip header: {:02x}", &packet[8..28].as_hex());
            println!("src addr: {:?}", &packet[20..24]);
            println!("dst addr: {:?}", &packet[24..28]);
        }
        _ => {
            println!("ip header: {:02x}", &packet[8..48].as_hex());
            println!("src addr:  {:02x}", &packet[16..32].as_hex());
            println!("dst addr: {:02x}", &packet[32..48].as_hex());
        }
    };
    println!("ip payload");
    println!("----------");
    match &proto {
        TraceProtocol::UDP => {
            println!("udp header: {:02x}", &packet[28..36].as_hex());
            println!("udp payload: {:02x}", &packet[36..38].as_hex());
        }
        TraceProtocol::TCP => {
            println!("tcp header: {:02x}", &packet[28..48].as_hex());
            println!("tcp payload: {:02x}", &packet[48..64].as_hex());
        }
        TraceProtocol::ICMP => {
            println!("encapsulated icmp packet: {:02x}", &packet[28..48].as_hex());
        }
    }
    println!(
        "128 and beyond (mpls labels): {:02x}",
        &packet[136..148].as_hex()
    );
    println!("-----------");
}
