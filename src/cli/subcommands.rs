use clap::{Parser, ValueEnum};
use derive_builder::Builder;

#[derive(Debug, Clone, Parser, Builder)]
#[clap(about = "List default or all interfaces on a network")]
pub struct InterfacesArgs {
    #[clap(value_enum)]
    pub list_option: List,
}

#[derive(Debug, Clone, PartialEq, ValueEnum)]
pub enum List {
    All,
    Default,
}

#[derive(Debug, Clone, Parser, Builder)]
#[clap(about = "Capture network packets and save in a .pcap file")]
pub struct BasicCaptureArgs {
    /// The directory where the packets will be saved
    #[clap(required = true)]
    #[clap(long = "dir", short = 'd')]
    pub dir_name: String,

    /// The name of the .pcap file
    #[clap(required = true)]
    #[clap(long = "file", short = 'f')]
    pub file_name: String,

    /// The number of packets to be captured
    #[clap(required = true)]
    #[clap(long, short)]
    pub size: usize,

    /// The interface to capture packets
    // #[clap(required = true)]
    #[clap(long, short)]
    pub interface: String,
}
