mod analyzer;

use analyzer::interface::Interface;

fn main() {
    let device = Interface::default_device().unwrap();
    println!("Interfaces: {:?}", device);

    let handle = Interface::capture_handle(device, 5000);
    Interface::read_packets(handle.unwrap());
}
