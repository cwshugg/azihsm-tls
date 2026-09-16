// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_tls_client::cli::Cli;
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    if let Err(error) = azihsm_tls_client::logging::init() {
        eprintln!("{error}");
        std::process::exit(error.exit_code().into());
    }
    match azihsm_tls_client::client::run(&cli.connect, &cli.ca_root, &cli.server_name, &cli.message)
    {
        Ok(response) => {
            println!("handshake ok; server replied {} bytes", response.len());
            print!("{response}");
        }
        Err(error) => {
            tracing::error!(event = "client_failed", code = ?error.code());
            eprintln!("{error}");
            std::process::exit(error.exit_code().into());
        }
    }
}
