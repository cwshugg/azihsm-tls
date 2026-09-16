//! CLI and logging contract tests.

#![cfg(windows)]

use std::process::Command;

const EXE: &str = env!("CARGO_BIN_EXE_azihsm-ca-demo");

#[test]
fn help_lists_exact_commands_and_no_rsa_option() {
    let output = Command::new(EXE)
        .arg("--help")
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in ["create", "retry", "show", "delete-key"] {
        assert!(stdout.contains(command), "missing {command}");
    }
    assert!(!stdout.to_ascii_lowercase().contains("rsa"));
}

#[test]
fn subcommand_help_snapshots_required_flags() {
    let cases = [
        (
            "create",
            "Usage: azihsm-ca-demo.exe create [OPTIONS] --output-dir <OUTPUT_DIR> --subject-cn <SUBJECT_CN> --ca-url <CA_URL> --acknowledge-plain-http",
        ),
        (
            "retry",
            "Usage: azihsm-ca-demo.exe retry --output-dir <OUTPUT_DIR> --acknowledge-plain-http",
        ),
        (
            "show",
            "Usage: azihsm-ca-demo.exe show --output-dir <OUTPUT_DIR>",
        ),
        (
            "delete-key",
            "Usage: azihsm-ca-demo.exe delete-key --output-dir <OUTPUT_DIR> --confirm-key-name <CONFIRM_KEY_NAME>",
        ),
    ];
    for (command, expected) in cases {
        let output = Command::new(EXE)
            .args([command, "--help"])
            .output()
            .unwrap_or_else(|error| panic!("{error}"));
        assert!(output.status.success());
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(expected),
            "{command} help changed:\n{stdout}"
        );
    }
}

#[test]
fn invalid_rust_log_exits_two_without_stdout() {
    let output = Command::new(EXE)
        .arg("--help")
        .env("RUST_LOG", "info,crate=debug")
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(
        output.status.code(),
        Some(0),
        "clap help exits before logging"
    );

    let output = Command::new(EXE)
        .args(["show", "--output-dir", "C:\\missing"])
        .env("RUST_LOG", "info,crate=debug")
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
}

#[test]
fn rust_log_off_keeps_private_key_limitation_transcript() {
    let output = Command::new(EXE)
        .args(["show", "--output-dir", "C:\\missing"])
        .env("RUST_LOG", "off")
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(
        "PRIVATE KEY LIMITATION: private key bytes and handles are never exported, available, or printed."
    ));
    assert!(!stdout.contains("event="));
}
