mod analyzer;
mod cli;
mod logger;

fn main() {
    logger::log::setup().expect("failed to initialize logger.");
    cli::run();
}
