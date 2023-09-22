pub(crate) mod subcommands;

use clap::{Parser, Subcommand};

use subcommands::interface;

#[derive(Clone, Debug, Subcommand)]
pub enum SniffSubCommand {
    Interface(interface::InterfaceCommand),
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
pub struct SniffCommand {
    #[command(subcommand)]
    subcommand: SniffSubCommand,
}

impl SniffCommand {
    pub fn run(self) {
        match self.subcommand {
            SniffSubCommand::Interface(c) => c.run(),
        }
    }
}

pub fn run() {
    let input = std::env::args()
        .map(replace_hyphen_with_stdin)
        .collect::<Vec<_>>();

    println!("INPUT {:?}", input);

    let c = SniffCommand::parse();
    println!("Test One Two: {:?}", c);

    match SniffCommand::try_parse_from(input) {
        Ok(command) => command.run(),
        Err(help) => panic!("Unable to run CLI"),
    }
}

pub(crate) fn replace_hyphen_with_stdin(s: String) -> String {
    let input_stream = std::io::stdin();
    if s.contains("/-") {
        let mut buffer = String::new();
        input_stream
            .read_line(&mut buffer)
            .expect("could not read from standard input");
        let args_from_stdin = buffer
            .trim()
            .split('/')
            .filter(|&s| !s.is_empty())
            .fold("".to_owned(), |acc, s| format!("{acc}/{s}"));

        s.replace("/-", &args_from_stdin)
    } else if s.contains("-/") {
        let mut buffer = String::new();
        input_stream
            .read_line(&mut buffer)
            .expect("could not read from standard input");

        let args_from_stdin = buffer
            .trim()
            .split('/')
            .filter(|&s| !s.is_empty())
            .fold("/".to_owned(), |acc, s| format!("{acc}{s}/"));

        s.replace("-/", &args_from_stdin)
    } else {
        s
    }
}
