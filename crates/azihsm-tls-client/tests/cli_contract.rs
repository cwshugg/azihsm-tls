// Copyright (C) Microsoft Corporation. All rights reserved.

use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_azihsm-tls-client");

#[test]
fn help_lists_required_flags() {
    let output = Command::new(EXE)
        .arg("--help")
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for flag in ["--connect", "--ca-root", "--server-name", "--message"] {
        assert!(stdout.contains(flag), "missing {flag}");
    }
}

#[test]
fn missing_required_flags_is_a_usage_error() {
    let output = Command::new(EXE)
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn connect_without_port_is_rejected() {
    let output = Command::new(EXE)
        .args([
            "--connect",
            "localhost",
            "--ca-root",
            "root.pem",
            "--server-name",
            "localhost",
        ])
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    assert!(stderr.contains("host:port"));
}

#[test]
fn server_name_with_whitespace_is_rejected() {
    let output = Command::new(EXE)
        .args([
            "--connect",
            "127.0.0.1:8443",
            "--ca-root",
            "root.pem",
            "--server-name",
            "bad name",
        ])
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(output.status.code(), Some(2));
}
