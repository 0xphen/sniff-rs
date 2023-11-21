mod analyzer;
mod cli;
mod utils;

use utils::logger;

fn main() {
    logger::setup_logger().expect("failed to initialize logging.");
    cli::run();
}
