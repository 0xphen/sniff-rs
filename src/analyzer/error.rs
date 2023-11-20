use net_sift::parsers::errors::ParserError;
use pcap::Error as PcapError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AnalyzerError {
    #[error("Failed to list interfaces")]
    DeviceLookupFailed,

    #[error("No interface found")]
    NoInterfaceFound,

    #[error("Failed to capture device handle")]
    FailedToGetCaptureHandle,

    #[error("Failed to parse packets")]
    FailedToParsePackets,

    #[error("Failed to create capture handle : {0}")]
    FailedToCreateCaptureHandle(#[source] PcapError),

    #[error("Failed to open capture handle : {0}")]
    FailedToOpenCaptureHandle(#[source] PcapError),
}

impl From<ParserError> for AnalyzerError {
    fn from(err: ParserError) -> Self {
        match err {
            _ => panic!("Other errors"),
        }
    }
}
