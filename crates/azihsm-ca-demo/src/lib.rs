//! AziHSM-backed TLS certificate enrollment workflow.

#[cfg(not(windows))]
compile_error!("azihsm-ca-demo is Windows-only");

mod cli;
mod workflow;

use azihsm_ca_client::{Result, init_logging, transcript};
use clap::Parser;
use cli::Command;

fn execute(command: Command) -> Result<()> {
    match command {
        Command::Create(args) => workflow::create(args),
        Command::Retry(args) => workflow::retry(args),
        Command::Show(args) => workflow::show(args),
        Command::DeleteKey(args) => workflow::delete_key(args),
    }
}

/// Parses and executes one complete demo command.
pub fn main_entry() -> Result<()> {
    let cli = cli::Cli::parse();
    init_logging()?;
    transcript::private_key_notice();
    execute(cli.command)
}
