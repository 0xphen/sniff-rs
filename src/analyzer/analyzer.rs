use log::{debug, error, info, trace, warn};
use net_sift::parsers::{
    definitions::{DeepParser, LayeredData},
    ethernet_frame::EthernetFrame,
};
use pcap::{Activated, Active, Capture, Device, Error as PcapError, Packet, Savefile};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::{channel, Sender},
    thread,
};

use super::{
    definitions::ReadPacketResult, error::AnalyzerError, format_packets::format_packets,
    pcap_interface::*,
};

pub struct Analyzer;

impl Analyzer {
    /// Captures network packets and saves them to a .pcap file.
    ///
    /// This function captures packets from a specified network interface and
    /// saves them to a file. It stops capturing after reaching a defined limit
    /// of packets.
    ///
    /// # Arguments
    /// * `path` - The directory path where the .pcap file will be saved.
    /// * `file_name` - The name of the .pcap file.
    /// * `limit` - The maximum number of packets to capture.
    /// * `interface_name` - The name of the network interface to capture packets from.
    ///
    /// # Remarks
    /// The function will terminate early and log an error if it encounters issues
    /// such as an invalid path, failure in opening the capture handle, or errors
    /// in reading packets.
    pub fn basic_capture(path: &str, file_name: &str, limit: usize, interface_name: &str) {
        // Find the device
        let device = match PcapInterface::find_device(interface_name) {
            Ok(d) => d,
            Err(err) => {
                error!("{:?}", err.to_string());
                return;
            }
        };

        // Check if the path exists and is a directory
        let path = Path::new(path);
        if !path.exists() || !path.is_dir() {
            error!("Path does not exist or is not a directory");
            return;
        }

        // Open a capture handle
        let capture_handle = match PcapInterface::capture_handle(device) {
            Ok(c) => c,
            Err(err) => {
                error!("{:?}", err.to_string());
                return;
            }
        };

        // Create or open the .pcap file
        let new_path = path.join(format!("{}.pcap", file_name));
        let mut pcap_file = match capture_handle.savefile(new_path.clone()) {
            Ok(f) => f,
            Err(err) => {
                error!("{:?}", err.to_string());
                return;
            }
        };

        Self::par_basic_capture(capture_handle, pcap_file, new_path, limit);
    }

    fn par_basic_capture<T: Activated + 'static>(
        capture_handle: Capture<T>,
        mut pcap_file: Savefile,
        new_path: PathBuf,
        limit: usize,
    ) {
        // Setup for reading packets
        let (send_packets, recv_packets) = channel::<ReadPacketResult>();

        // Spawn a thread to read packets
        thread::spawn(move || {
            PcapInterface::read_packets(capture_handle, send_packets);
        });

        // Process packets
        let mut total_packets = 0;
        while let Ok(message) = recv_packets.recv() {
            match message {
                ReadPacketResult::Success(message) => {
                    let packet = Packet::new(&message.0, &message.1);

                    pcap_file.write(&packet);
                    Self::parse_packets(&message.1, "CAPTURE");
                    total_packets += 1;

                    if total_packets >= limit {
                        info!("Saved {} packets to file {:?}", total_packets, new_path);
                        break;
                    }
                }
                ReadPacketResult::Error(e) => error!("Error: {:?}\n", e),
            }
        }
    }

    pub fn show_default_interface() {
        match PcapInterface::default_interface() {
            Ok(Some(device)) => info!("Default interface: {}", device.name),
            Ok(None) => info!("No interface found"),
            Err(e) => error!("Failed to find default interface {:?}", e.to_string()),
        }
    }

    pub fn list_interfaces() {
        match PcapInterface::devices() {
            Ok(interfaces) => info!("{:?}", interfaces),
            Err(e) => error!("Failed to list interfaces {:}", e.to_string()),
        }
    }

    fn parse_packets(packets: &[u8], mode: &str) {
        let ethernet_frame = EthernetFrame::from_bytes(packets, false);

        match ethernet_frame {
            Ok(frame) => {
                let layered_data = frame.parse_next_layer();

                // The parsing of network packets begins with the Ethernet frame, which is the
                // foundational layer. Other enum variants representing different layers or
                // types of data are not considered at this stage.
                if let Ok(LayeredData::EthernetFrameData(frame)) = layered_data {
                    let mut log_msg = format_packets(frame);
                    log_msg.push_str(&format!(" | {} bytes", packets.len()));
                    info!("{}: {} | {} bytes\n", mode, log_msg, packets.len());
                }
            }
            Err(e) => error!("Error parsing packet {:?}", e.to_string()),
        }
    }
}
