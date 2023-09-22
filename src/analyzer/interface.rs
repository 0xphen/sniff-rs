use crate::analyzer::error::InterfaceError;

use pcap::Device;

#[derive(Debug, Clone)]
/// A network interface, it encapsulates a pcap's device
pub struct Interface;

impl Interface {
    pub fn list_interfaces() -> Result<Vec<Device>, InterfaceError> {
        let devices = Device::list()
            .map_err(|err| InterfaceError::FailedToListInterfaces(err.to_string()))?;

        Ok(devices)
    }
}
