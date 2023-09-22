mod analyzer;
mod command;

use analyzer::interface::Interface;

fn main() {
    // let interfaces = Interface::list_interfaces().unwrap();
    // println!("Interfaces: {:?}", interfaces);
    command::run();
}
