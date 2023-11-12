use clap::{Arg, ArgAction, Command};

/// Builds the command line interface for.
pub fn build_command() -> Command {
    Command::new("sniff")
        .subcommand(
            Command::new("dump")
                .about("Dump packets in a .pcap file for further analysis")
                .arg(
                    Arg::new("interface")
                        .short('i')
                        .long("interface")
                        .required(true)
                        .help("The interface to capture network packets from"),
                )
                .arg(
                    Arg::new("dir")
                        .short('d')
                        .long("dir")
                        .required(true)
                        .help("The directory where the file will be saved"),
                )
                .arg(
                    Arg::new("file")
                        .short('f')
                        .long("file")
                        .required(true)
                        .help("The file name"),
                )
                .arg(
                    Arg::new("count")
                        .short('c')
                        .long("count")
                        .default_value("100")
                        .required(false)
                        .help("The number of packets to save"),
                ),
        )
        .subcommand(
            Command::new("interfaces")
                .about("List all interfaces.")
                .arg(
                    Arg::new("all")
                        .short('a')
                        .long("all")
                        .required(true)
                        .action(ArgAction::SetTrue)
                        .conflicts_with("default")
                        .help("Boolean flag to show all interfaces"),
                )
                .arg(
                    Arg::new("default")
                        .short('d')
                        .long("default")
                        .required(true)
                        .action(ArgAction::SetTrue)
                        .conflicts_with("all")
                        .help("Boolean flag to show default interface"),
                ),
        )
}
