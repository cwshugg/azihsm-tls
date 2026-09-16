//! Command-line entry point for the AziHSM TLS enrollment demonstration.

use azihsm_ca_demo::cli::Cli;
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = azihsm_ca_demo::logging::init() {
        eprintln!("{error}");
        std::process::exit(error.exit_code().into());
    }
    azihsm_ca_demo::transcript::private_key_notice();
    let result = azihsm_ca_demo::execute(cli.command);
    if let Err(error) = result {
        tracing::error!(event = "command_failed", class = ?error.class());
        eprintln!("{error}");
        std::process::exit(error.exit_code().into());
    }
}
