pub mod log {
    use fern::{
        colors::{Color, ColoredLevelConfig},
        Dispatch, InitError,
    };
    use humantime;
    use std::time::SystemTime;

    pub fn setup() -> Result<(), InitError> {
        let colors_line = ColoredLevelConfig::new()
            .info(Color::White)
            .warn(Color::Yellow)
            .error(Color::Red)
            .debug(Color::Blue)
            .trace(Color::Magenta);

        let colors_level = colors_line.info(Color::Green);
        Dispatch::new()
            .format(move |out, message, record| {
                out.finish(format_args!(
                    "{color_line}[{date} {level} {color_line}] {message}\x1B[0m",
                    color_line = format_args!(
                        "\x1B[{}m",
                        colors_line.get_color(&record.level()).to_fg_str()
                    ),
                    date = humantime::format_rfc3339_seconds(SystemTime::now()),
                    level = colors_level.color(record.level()),
                    message = message,
                ));
            })
            .level(log::LevelFilter::Debug)
            .chain(std::io::stdout())
            .apply()?;
        Ok(())
    }
}

pub mod format_packets {
    use net_sift::parsers::{
        definitions::LayeredData,
        ethernet_frame::{EthernetFrame, EthernetFrameHeader},
        icmp, ipv4, ipv6, tcp, udp,
    };

    /// Formats the different layers of an Ethernet frame for logging.
    ///
    /// Parses and formats an Ethernet frame to a human-readable string representation.
    /// This includes Ethernet, IP (both IPv4 and IPv6), and transport layer (TCP/UDP/ICMP) data.
    ///
    /// # Arguments
    /// * `frame` - An `EthernetFrame` struct representing the captured frame.
    ///
    /// # Returns
    /// Returns a `String` with the formatted output of each layer in the Ethernet frame.
    pub fn format_packets(frame: EthernetFrame) -> String {
        let EthernetFrame {
            header,
            data: ethernet_frame_data,
        } = frame;

        let ipv4_packet = parse_ipv4(&ethernet_frame_data);
        let ipv6_packet = parse_ipv6(&ethernet_frame_data);

        let mut transport_msg = String::new();
        let mut ip_msg = String::new();

        let mut output = format_ether_frame(&header);

        if let Some(ipv4) = ipv4_packet {
            transport_msg = format_transports(&ipv4.data);
            ip_msg = format_ipv4(ipv4);
        } else if let Some(ipv6) = ipv6_packet {
            transport_msg = format_transports(&ipv6.data);
            ip_msg = format_ipv6(ipv6);
        }

        output.push_str(&format!(" | {} | {}", ip_msg, transport_msg));
        output
    }

    /// Parses IPv4 data from the given `LayeredData`
    fn parse_ipv4(layered_data: &LayeredData) -> Option<&ipv4::Ipv4Packet> {
        match layered_data {
            LayeredData::Ipv4Data(d) => Some(d),
            _ => None,
        }
    }

    /// Parses IPv6 data from the given `LayeredData`.
    fn parse_ipv6(layered_data: &LayeredData) -> Option<&ipv6::Ipv6Packet> {
        match layered_data {
            LayeredData::Ipv6Data(d) => Some(d),
            _ => None,
        }
    }

    /// Formats transport layer data from the given `LayeredData`.
    fn format_transports(layered_data: &LayeredData) -> String {
        match layered_data {
            LayeredData::TcpData(data) => format_tcp(data),
            LayeredData::UdpData(data) => format_udp(data),
            LayeredData::IcmpData(data) => format_icmp(data),
            _ => String::new(),
        }
    }

    /// Formats an Ethernet frame header.
    fn format_ether_frame(header: &EthernetFrameHeader) -> String {
        format!(
            "Ethernet: Src {:?}, Dest {:?}, Prot {:?}",
            header.mac_destination.to_string(),
            header.mac_source.to_string(),
            header.ether_type,
        )
    }

    fn format_ipv4(ipv4_packet: &ipv4::Ipv4Packet) -> String {
        format!(
            "IPv4: Ver {}, Src {}, Dest {}, Prot {:?}, TTL {}",
            ipv4_packet.header.version,
            ipv4_packet.header.source_address,
            ipv4_packet.header.destination_address,
            ipv4_packet.header.protocol,
            ipv4_packet.header.time_to_live
        )
    }

    fn format_ipv6(ipv6_packet: &ipv6::Ipv6Packet) -> String {
        format!(
            "IPV6: Ver: {} Src: {} Dest: {} Next: {:?}",
            ipv6_packet.header.version,
            ipv6_packet.header.source_address,
            ipv6_packet.header.destination_address,
            ipv6_packet.header.next_header
        )
    }

    fn format_tcp(tcp_segment: &tcp::TcpSegment) -> String {
        format!(
            "TCP: Src Port: {} Dest Port: {} Seq: {} Syn: {} Ack: {}",
            tcp_segment.header.source_port,
            tcp_segment.header.destination_port,
            tcp_segment.header.sequence_number,
            tcp_segment.header.flags.syn,
            tcp_segment.header.flags.ack
        )
    }

    fn format_udp(udp_datagram: &udp::UdpDatagram) -> String {
        format!(
            "UDP: Src Port {}, Dest Port {}",
            udp_datagram.header.source_port, udp_datagram.header.destination_port
        )
    }

    fn format_icmp(icmp_packet: &icmp::IcmpPacket) -> String {
        format!(
            "ICMP: Type: {} Code: {}  Checksum: {}",
            icmp_packet.header.icmp_type, icmp_packet.header.icmp_code, icmp_packet.header.checksum
        )
    }
}
