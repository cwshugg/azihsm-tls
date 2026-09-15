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
