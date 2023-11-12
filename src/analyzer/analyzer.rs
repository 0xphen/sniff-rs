use log::{debug, error, info, trace, warn};
use net_sift::parsers::ethernet_frame::EthernetFrame;
use pcap::{Activated, Active, Capture, Device, Error as PcapError, Packet};
use std::{
    path::Path,
    sync::mpsc::{channel, Sender},
    thread,
};

use super::{definitions::ReadPacketResult, error::AnalyzerError, format_packets::format_packets};

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
        let device = match Self::find_device(interface_name) {
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
        let capture_handle = match Self::capture_handle(device) {
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

        // Setup for reading packets
        let (send_packets, recv_packets) = channel::<ReadPacketResult>();

        // Spawn a thread to read packets
        thread::spawn(move || {
            Self::read_packets(capture_handle, send_packets);
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
                ReadPacketResult::Error(e) => error!("Error: {:?}", e),
            }
        }
    }

    /// Finds a network device by its name.
    ///
    /// This function searches through the list of available network interfaces
    /// and returns the one that matches the specified name. If no matching
    /// device is found, it returns an `AnalyzerError`.
    ///
    /// # Arguments
    /// * `name` - The name of the network device to find.
    ///
    /// # Returns
    /// `Result<Device, AnalyzerError>` - A result that is either:
    /// * `Ok(Device)` - The found network device.
    /// * `Err(AnalyzerError)` - An error if the device is not found or if
    ///    there's an issue listing the interfaces.
    ///
    /// # Example
    /// ```
    /// let device = find_device("eth0");
    /// match device {
    ///     Ok(device) => println!("Found device: {:?}", device),
    ///     Err(e) => println!("Error: {:?}", e),
    /// }
    /// ```
    fn find_device(name: &str) -> Result<Device, AnalyzerError> {
        let devices = Self::interfaces().map_err(|_e| AnalyzerError::DeviceLookupFailed)?;

        let device = devices.iter().find(|d| d.name == name);

        match device {
            Some(d) => Ok(d.clone()),
            None => Err(AnalyzerError::NoInterfaceFound),
        }
    }

    /// Retrieve up the default network interface
    fn default_interface() -> Result<Option<Device>, PcapError> {
        Device::lookup()
    }

    /// Retrieve all network interfaces
    fn interfaces() -> Result<Vec<Device>, PcapError> {
        Device::list()
    }

    /// Displays the default network interface.
    ///
    /// This function looks up the default network device and logs its name.
    /// It handles and logs different outcomes: finding the default device,
    /// finding no device, or encountering an error during the lookup.
    ///
    /// # Examples
    /// ```
    /// show_default_interface();
    /// // Possible outputs:
    /// // "Default interface: eth0"
    /// // "No interface found"
    /// // "Failed to find default device <error details>"
    /// ``
    pub fn show_default_interface() {
        match Self::default_interface() {
            Ok(Some(device)) => info!("Default interface: {}", device.name),
            Ok(None) => info!("No interface found"),
            Err(e) => error!("Failed to find default interface {:?}", e.to_string()),
        }
    }

    pub fn list_interfaces() {
        match Self::interfaces() {
            Ok(interfaces) => info!("{:?}", interfaces),
            Err(e) => error!("Failed to list interfaces {:}", e.to_string()),
        }
    }

    /// Creates a packet capture handle for the given network device.
    ///
    /// This function attempts to create and initialize a packet capture handle
    /// for the provided network device. It configures the device in non-promiscuous mode
    /// and sets up the handle for capturing packets.
    ///
    /// # Arguments
    /// * `device` - A `Device` object representing the network interface for packet capture.
    ///
    /// # Returns
    /// * `Ok(Capture<Active>)` if the capture handle is successfully created and opened.
    /// * `Err(InterfaceError)` if there are issues creating or opening the capture handle.
    ///
    /// # Errors
    /// * `InterfaceError::FailedToCreateCaptureHandle` if the capture handle cannot be created.
    /// * `InterfaceError::FailedToOpenCaptureHandle` if the capture handle cannot be opened.
    fn capture_handle(device: Device) -> Result<Capture<Active>, AnalyzerError> {
        let capture_handle = Capture::from_device(device)
            .map_err(AnalyzerError::FailedToCreateCaptureHandle)?
            .promisc(false)
            // .snaplen(65535)
            .open()
            .map_err(AnalyzerError::FailedToOpenCaptureHandle)?;

        Ok(capture_handle)
    }

    fn parse_packets(packets: &[u8], mode: &str) {
        let ethernet_frame = EthernetFrame::from_bytes(packets, false);

        match ethernet_frame {
            Ok(data) => {
                // let EthernetFrame { header, data } = data;
                let log_msg = format_packets(data);
                // println!("log_msg:: {}", log_msg);
                // info!("{}: {} | {} bytes", mode, log_msg, packets.len());
            }
            Err(e) => error!("Error parsing packet {:?}", e.to_string()),
        }
    }

    /// Continuously reads packets from the given capture handle and sends the results.
    ///
    /// This function takes a mutable capture handle and a sender channel. It enters
    /// a loop where it reads packets using the capture handle. Each packet, or an error
    /// if one occurs, is sent to the receiver associated with the provided sender channel.
    ///
    /// # Arguments
    /// * `capture_handle`: A mutable capture handle of type `T` where `T` is Activated.
    ///     It is used to capture packets from the network.
    /// * `sender`: A channel sender for sending the results of packet reading.
    ///
    /// # Behavior
    /// The function keeps reading packets in a loop until an error occurs.
    /// For each packet read:
    /// - If successful, sends `ReadPacketResult::Success` containing the packet's header
    ///   and data.
    /// - If an error occurs during sending, sends `ReadPacketResult::Error` and exits the loop.
    fn read_packets<T: Activated>(
        mut capture_handle: Capture<T>,
        sender: Sender<ReadPacketResult>,
    ) {
        while let Ok(packet) = capture_handle.next_packet() {
            let send_result = sender.send(ReadPacketResult::Success((
                *packet.header,
                packet.data.to_vec(),
            )));

            if let Err(e) = send_result {
                let _ = sender.send(ReadPacketResult::Error(e.to_string()));
                break;
            }
        }
    }
}
