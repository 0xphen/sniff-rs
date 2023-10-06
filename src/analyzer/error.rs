use pcap::Error;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum InterfaceError {
    #[error("Failed to list interfaces: {0}")]
    FailedToListInterfaces(#[source] Error),

    #[error("Failed to list default interface : {0}")]
    FailedToListDefaultInterface(#[source] Error),

    #[error("Failed to list default interface")]
    DefaultDeviceNotFound,

    #[error("Failed to create capture handle : {0}")]
    FailedToCreateCaptureHandle(#[source] Error),

    #[error("Failed to open capture handle : {0}")]
    FailedToOpenCaptureHandle(#[source] Error),
}
