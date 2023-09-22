mod list;

pub(crate) use list::ListCommand;

use clap::{Args, Subcommand};

#[derive(Clone, Debug, Subcommand)]
pub enum InterfaceSubCommand {
    List(ListCommand),
}

#[derive(Clone, Debug, Args)]
#[command(arg_required_else_help = true, subcommand_required = true)]
pub struct InterfaceCommand {
    #[command(subcommand)]
    subcommand: InterfaceSubCommand,
}

impl InterfaceCommand {
    pub fn run(self) {
        match self.subcommand {
            InterfaceSubCommand::List(c) => c.run(),
        }
    }
}
