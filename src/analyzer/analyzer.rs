use log::{error, info};
use net_sift::parsers::{
    definitions::{DeepParser, LayeredData},
    ethernet_frame::EthernetFrame,
};
use pcap::{Activated, Capture, Packet, Savefile};
use std::{
    path::{Path, PathBuf},
    sync::mpsc::channel,
    thread,
};

use super::{definitions::ReadPacketResult, pcap_interface::PcapInterface};
use crate::logger::format_packets::format_packets;

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
    pub fn basic_capture(path: &str, file_name: &str, limit: usize, interface: &str) {
        // Find the device
        let device = match PcapInterface::find_device(interface) {
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
        let pcap_file = match capture_handle.savefile(new_path.clone()) {
            Ok(f) => f,
            Err(err) => {
                error!("{:?}", err.to_string());
                return;
            }
        };

        Self::capture_and_process_packets(capture_handle, pcap_file, new_path, limit);
    }

    /// Captures network packets and writes them to a file.
    ///
    /// The function captures packets in a separate thread and processes them
    /// in the main thread, writing each packet to a file and performing custom
    /// packet parsing. Capturing stops when the limit is reached or an error occurs.
    ///
    /// # Arguments
    /// * `capture_handle` - A handle to the packet capture device/interface.
    /// * `pcap_file` - File object to save the captured packets.
    /// * `new_path` - Path to the file where packets will be saved.
    /// * `limit` - The maximum number of packets to capture and process.
    fn capture_and_process_packets<T: Activated + 'static>(
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

    /// Captures live network packets on the specified interface.
    /// The function locates the specified network interface and opens a capture handle
    /// for it. Upon successful acquisition of the capture handle, it initiates the
    /// streaming of captured packets. If any error occurs during device finding or
    /// handle creation, the error is logged and the function returns early.
    ///
    /// # Arguments
    /// * `interface` - The name of the network interface to capture packets from.
    pub fn live_capture(interface: &str) {
        // Find the device
        let device = match PcapInterface::find_device(interface) {
            Ok(d) => d,
            Err(err) => {
                error!("{:?}", err.to_string());
                return;
            }
        };

        // Open a capture handle
        let capture_handle = match PcapInterface::capture_handle(device) {
            Ok(c) => c,
            Err(err) => {
                error!("{:?}", err.to_string());
                return;
            }
        };

        Self::stream(capture_handle);
    }

    /// Streams and processes network packets from a capture handle.
    ///
    /// # Arguments
    /// * `capture_handle` - A handle for capturing packets, compliant with `Activated` and `'static`.
    ///
    /// The function sets up a channel for packet communication and spawns a new thread
    /// to read packets using the provided `capture_handle`. Packets read are sent over the
    /// channel to the main thread for processing. The main thread continuously receives
    /// packets and processes them until an error occurs or there are no more packets.

    fn stream<T: Activated + 'static>(capture_handle: Capture<T>) {
        let (send_packets, recv_packets) = channel::<ReadPacketResult>();

        thread::spawn(move || {
            PcapInterface::read_packets(capture_handle, send_packets);
        });

        while let Ok(message) = recv_packets.recv() {
            match message {
                ReadPacketResult::Success(message) => {
                    Self::parse_packets(&message.1, "LIVE");
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
            Ok(interfaces) => {
                let interfaces = interfaces
                    .into_iter()
                    .map(|interface| interface.name)
                    .collect::<Vec<String>>();

                info!("{:?}", interfaces)
            }
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
