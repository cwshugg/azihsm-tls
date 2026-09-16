//! AziHSM-backed TLS 1.3 framed echo server.

#![cfg_attr(not(windows), allow(dead_code))]

#[cfg(not(windows))]
compile_error!("azihsm-tls-server is Windows-only");

mod cli;
pub mod frame;
mod identity;
pub mod server;
pub mod tls;

use crate::identity::{
    ServerPrepareOptions, delete_server_key, prepare_server_identity, show_server_identity,
};
use azihsm_ca_client::validation::validate_sans;
use azihsm_ca_client::{init_logging, transcript};
use azihsm_ncrypt::{Error, ErrorClass, Result};
use clap::Parser;
use cli::{Cli, Command};
use time::OffsetDateTime;

pub fn main_entry() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    init_logging()?;
    transcript::private_key_notice();
    match cli.command {
        Command::Run(args) => {
            validate_sans(&args.dns, &args.ip)?;
            tracing::info!(
                event = "command_started",
                command = "run",
                message =
                    "Preparing one persistent AziHSM identity before starting the TLS listener."
            );
            let identity = prepare_server_identity(ServerPrepareOptions {
                state_dir: args.state_dir,
                dns: args.dns,
                ips: args.ip,
                ca_url: args.ca_url,
                key_name: args.key_name,
                now: OffsetDateTime::now_utc(),
            })?;
            let config = tls::build_server_config(&identity)?;
            let not_after = identity.not_after;
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()?;
            runtime.block_on(server::run(args.listen, config, not_after))?;
            drop(identity);
            tracing::info!(
                event = "command_completed",
                command = "run",
                message = "The TLS listener and all connection tasks stopped before releasing the AziHSM identity."
            );
        }
        Command::Show(args) => {
            tracing::info!(
                event = "command_started",
                command = "show",
                message = "Showing the public certificate identity and non-exportable AziHSM key reference."
            );
            show_server_identity(&args.state_dir)?;
            tracing::info!(
                event = "command_completed",
                command = "show",
                message =
                    "Finished displaying the public server identity and certificate validity."
            );
        }
        Command::DeleteKey(args) => {
            tracing::info!(
                event = "command_started",
                command = "delete-key",
                message = "Verifying durable identity evidence before irreversibly deleting the exact AziHSM key."
            );
            delete_server_key(&args.state_dir, args.confirm_key_name)?;
            tracing::info!(
                event = "command_completed",
                command = "delete-key",
                message = "The exact server key is deleted after identity-bound confirmation and absence verification."
            );
        }
    }
    Ok(())
}
