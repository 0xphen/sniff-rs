use crate::analyzer::interface;

use clap::Args;

#[derive(Clone, Debug, Args)]
#[command(arg_required_else_help = false)]
pub struct ListCommand {
    #[arg(short, long)]
    verbose: bool,
}

impl ListCommand {
    pub fn run(self) {
        match interface::Interface::list_interfaces() {
            Ok(interfaces) => println!("{:?}", interfaces),
            Err(e) => panic!("{:?}", e),
        }
    }
}
