// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(windows)]

use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_keytool");

#[test]
fn help_lists_exact_commands() {
    let output = Command::new(EXE)
        .arg("--help")
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in ["init", "open", "public", "delete"] {
        assert!(stdout.contains(command), "missing {command}");
    }
}

#[test]
fn subcommand_help_requires_name_flag() {
    for command in ["init", "open", "public", "delete"] {
        let output = Command::new(EXE)
            .args([command, "--help"])
            .output()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("--name"),
            "{command} help missing --name:\n{stdout}"
        );
    }
}

#[test]
fn invalid_key_name_is_rejected_before_any_provider_call() {
    let output = Command::new(EXE)
        .args(["init", "--name", "bad name"])
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(output.status.code(), Some(2), "clap usage error is exit 2");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.to_ascii_lowercase().contains("key name"));
}

#[test]
fn missing_name_flag_is_a_usage_error() {
    let output = Command::new(EXE)
        .arg("init")
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(output.status.code(), Some(2));
}
