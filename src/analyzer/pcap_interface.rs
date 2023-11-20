use super::{definitions::ReadPacketResult, error::AnalyzerError};
use pcap::{Activated, Active, Capture, Device, Error as PcapError, Packet};

use std::sync::mpsc::Sender;

pub struct PcapInterface;

impl PcapInterface {
    /// Retrieve up the default network interface
    pub fn default_interface() -> Result<Option<Device>, PcapError> {
        Device::lookup()
    }

    /// Retrieve all network interfaces
    pub fn devices() -> Result<Vec<Device>, PcapError> {
        Device::list()
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
    pub fn find_device(name: &str) -> Result<Device, AnalyzerError> {
        let devices = Self::devices().map_err(|_e| AnalyzerError::DeviceLookupFailed)?;
        let device = devices.into_iter().find(|d| d.name == name);

        match device {
            Some(d) => Ok(d),
            None => Err(AnalyzerError::NoInterfaceFound),
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
    pub fn capture_handle(device: Device) -> Result<Capture<Active>, AnalyzerError> {
        let capture_handle = Capture::from_device(device)
            .map_err(AnalyzerError::FailedToCreateCaptureHandle)?
            .promisc(false)
            .open()
            .map_err(AnalyzerError::FailedToOpenCaptureHandle)?;

        Ok(capture_handle)
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
    pub fn read_packets<T: Activated>(
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

#[cfg(test)]
mod tests {
    use super::*;
}
