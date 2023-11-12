mod analyzer;
mod utils;

use analyzer::analyzer::Analyzer;
use utils::{cli, logger};

fn main() {
    logger::setup_logger().expect("failed to initialize logging.");

    Analyzer::basic_capture("./", "test", 500, "en0");
    // let matches = cli::build_command().get_matches();
    // match matches.subcommand() {
    //     Some(("interfaces", sub_matches)) => {
    //         let all = *sub_matches.get_one::<bool>("all").unwrap_or(&false);
    //         let default = *sub_matches.get_one::<bool>("default").unwrap_or(&false);

    //         if all {
    //             let interfaces = Interface::list_interfaces();
    //             info!("{:?}", interfaces);
    //         } else if default {
    //             let device_name = Interface::default_device().unwrap();
    //             info!("{}", device_name);
    //         }
    //     }
    //     _ => {
    //         // Handle other cases or show an error message or help
    //         println!("No valid subcommand was used. Use --help for more information.");
    //     }
    // }
}
