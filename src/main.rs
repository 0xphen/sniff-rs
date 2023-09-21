mod analyzer;

use analyzer::interface::Interface;

fn main() {
    let interfaces = Interface::list_interfaces().unwrap();
    println!("Interfaces: {:?}", interfaces);
}
