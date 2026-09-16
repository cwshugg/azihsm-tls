//! Black-box CLI contract tests.

#![cfg(windows)]

use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_azihsm-ca");

#[test]
fn help_has_all_accepted_risks_and_truthful_exits() {
    let output = Command::new(EXE)
        .arg("--help")
        .output()
        .unwrap_or_else(|error| panic!("help failed: {error}"));
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap_or_else(|error| panic!("{error}"));
    for risk in azihsm_ca::policy::ACCEPTED_RISKS {
        assert!(text.contains(risk));
    }
    assert!(text.contains("9 reserved"));
}

#[test]
fn invalid_command_returns_usage() {
    let status = Command::new(EXE)
        .arg("unknown")
        .status()
        .unwrap_or_else(|error| panic!("command failed: {error}"));
    assert_eq!(status.code(), Some(2));
}

#[test]
fn invalid_rust_log_is_rejected_without_broad_directive_parsing() {
    let output = Command::new(EXE)
        .args([
            "serve",
            "--state-dir",
            r"C:\nonexistent",
            "--allow-dns",
            "server.example",
        ])
        .env("RUST_LOG", "info,azihsm_ca=trace")
        .output()
        .unwrap_or_else(|error| panic!("command failed: {error}"));
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("RUST_LOG must be one of off, error, warn, info, debug, or trace")
    );
    assert!(output.stdout.is_empty());
}
