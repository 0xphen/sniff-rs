use crate::analyzer::error::InterfaceError;

use pcap::{Activated, Active, Capture, Device, PacketHeader};

#[derive(Debug, Clone)]
/// A network interface, it encapsulates a pcap's device
pub struct Interface;

impl Interface {
    /// Returns the default device
    pub fn default_device() -> Result<Device, InterfaceError> {
        // If there's an error during the lookup, we transform it into our custom error type.
        let device = Device::lookup()
            .map_err(|err| InterfaceError::FailedToListDefaultInterface(err))?
            .ok_or(InterfaceError::DefaultDeviceNotFound)?;

        Ok(device)
    }

    /// Returns a vector of devices
    pub fn list_interfaces() -> Result<Vec<Device>, InterfaceError> {
        let devices = Device::list().map_err(|err| InterfaceError::FailedToListInterfaces(err))?;

        Ok(devices)
    }

    /// Sets up a packet capture on the specified device with the given snapshot length (snaplen).
    ///
    /// # Parameters
    /// - `device`: The device on which to set up the packet capture.
    /// - `snaplen`: The maximum length of a packet to capture.
    ///
    /// # Returns
    /// A `Result` with the capture handle if successful, or an `InterfaceError` if there's an issue.
    pub fn capture_handle(device: Device, snaplen: i32) -> Result<Capture<Active>, InterfaceError> {
        let mut capture_handle = Capture::from_device(device)
            .map_err(|err| InterfaceError::FailedToCreateCaptureHandle(err))?
            .promisc(false)
            .snaplen(snaplen)
            .open()
            .map_err(|err| InterfaceError::FailedToOpenCaptureHandle(err))?;

        Ok(capture_handle)
    }

    /// Continuously reads and prints packets from the provided capture handle.
    ///
    /// The function reads packets using the `next_packet()` method of the capture handle.
    /// Each successfully read packet is printed to the standard output using its `Debug` representation.
    /// The function will loop indefinitely, reading and printing packets, until an error occurs
    /// when trying to retrieve the next packet.
    ///
    /// # Parameters
    ///
    /// * `capture_handle`: An activated capture handle used to read packets. The handle's associated type
    ///   must implement the `Activated` trait.
    ///
    /// # Examples
    ///
    /// ```rust
    /// // Assuming necessary imports and setup.∏
    /// let device = Device::lookup().unwrap();
    /// let capture_handle = Capture::from_device(device).unwrap().open().unwrap();
    /// read_packets(capture_handle);
    /// ```
    ///
    /// # Panics
    ///
    /// This function does not explicitly panic, but underlying methods or functions it calls might.
    /// Refer to the documentation of the `next_packet()` method for potential panics.
    ///
    /// # Note
    ///
    /// The function exits the loop and returns once an error occurs in `next_packet()`. If continuous
    /// packet reading with error resilience is needed, consider adding additional error handling.
    pub fn read_packets<T: Activated>(mut capture_handle: Capture<T>) {
        while let Ok(packet) = capture_handle.next_packet() {
            println!("PACKER: {:?}", packet.data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn can_get_default_device() {
        let default_device = Interface::default_device();

        assert!(default_device.is_ok());
    }

    #[test]
    fn can_get_list_of_devices() {
        let devices = Interface::list_interfaces();
        assert!(devices.unwrap().len() > 0);
    }
}
