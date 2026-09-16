// Copyright (C) Microsoft Corporation. All rights reserved.

use clap::Parser;
use keytool::cli::{Cli, Command};

fn main() {
    let cli = Cli::parse();
    if let Err(error) = keytool::logging::init() {
        eprintln!("{error}");
        std::process::exit(error.exit_code().into());
    }
    let result = match cli.command {
        Command::Init(args) => keytool::commands::init(&args.name),
        Command::Open(args) => keytool::commands::open(&args.name),
        Command::Public(args) => keytool::commands::public(&args.name),
        Command::Delete(args) => keytool::commands::delete(&args.name),
    };
    if let Err(error) = result {
        tracing::error!(event = "command_failed", class = ?error.class());
        eprintln!("{error}");
        std::process::exit(error.exit_code().into());
    }
}
