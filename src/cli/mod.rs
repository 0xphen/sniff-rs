pub mod subcommands;

use crate::analyzer::{analyzer::Analyzer, pcap_interface::PcapInterface};
use clap::{Parser, Subcommand};
use subcommands::*;

#[derive(Debug, Parser)]
#[clap(
    name = "wyre",
    author = "0xphen",
    version
)]
struct Arguments {
    #[clap(subcommand)]
    sub: Subcommands,
}

#[derive(Debug, Subcommand)]
#[clap(
    about = "Sniff is a network packet analyzer",
    after_help = "For more information, read the README: https://github.com/0xphen/sniff-rs#sniff-rs"
)]
#[allow(clippy::large_enum_variant)]
enum Subcommands {
    #[clap(
        name = "interfaces",
        about = "List default or all interfaces on a network"
    )]
    Interfaces(InterfacesArgs),

    #[clap(
        name = "capture",
        about = "Capture network packets and save in a .pcap file"
    )]
    BasicCapture(BasicCaptureArgs),
    #[clap(name = "stream", about = "Captures and live streams network packets")]
    LiveStream(LiveStreamArgs),
}

pub fn run() {
    let args = Arguments::parse();
    match args.sub {
        Subcommands::Interfaces(interface_args) => {
            if interface_args.list_option == List::All {
                Analyzer::list_interfaces();
            } else {
                Analyzer::show_default_interface();
            }
        }
        Subcommands::BasicCapture(mut capture_args) => {
            // if the user has not specified an interface, use the default
            if capture_args.interface.as_str() == "" {
                match PcapInterface::default_interface() {
                    Ok(Some(device)) => capture_args.interface = device.name,
                    _ => panic!("Device not specified. Unable to get default device."),
                }
            }

            Analyzer::basic_capture(
                &capture_args.dir_name,
                &capture_args.file_name,
                capture_args.size,
                &capture_args.interface,
            );
        }
        Subcommands::LiveStream(args) => {
            Analyzer::live_capture(&args.interface);
        }
    }
}