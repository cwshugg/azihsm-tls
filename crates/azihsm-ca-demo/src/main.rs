//! Command-line entry point for the AziHSM TLS enrollment demonstration.

use azihsm_ca_demo::cli::{Cli, Command};
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = azihsm_ca_demo::logging::init() {
        eprintln!("{error}");
        std::process::exit(error.exit_code().into());
    }
    azihsm_ca_demo::transcript::private_key_notice();
    let result = match cli.command {
        Command::Create(args) => azihsm_ca_demo::workflow::create(args),
        Command::Retry(args) => azihsm_ca_demo::workflow::retry(args),
        Command::Show(args) => azihsm_ca_demo::workflow::show(args),
        Command::DeleteKey(args) => azihsm_ca_demo::workflow::delete_key(args),
    };
    if let Err(error) = result {
        tracing::error!(event = "command_failed", class = ?error.class());
        eprintln!("{error}");
        std::process::exit(error.exit_code().into());
    }
}
