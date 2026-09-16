// Copyright (C) Microsoft Corporation. All rights reserved.

#![cfg(windows)]

use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

const EXE: &str = env!("CARGO_BIN_EXE_keytool");

/// Each subcommand is a separate process, so a successful `open` after `init`
/// proves the named key is reachable cross-process, not just within one handle.
#[test]
#[ignore = "requires a registered AziHSM named-key provider"]
fn init_open_public_delete_named_key_cross_process() {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("{error}"))
        .as_nanos();
    let name = format!("keytool-live-{id:x}");

    let init = run(&["init", "--name", &name]);
    assert!(init.status.success(), "init failed: {}", stderr(&init));
    let init_out = String::from_utf8_lossy(&init.stdout);
    assert!(init_out.contains("created named key"));
    assert!(init_out.contains("public:"));

    let public = run(&["public", "--name", &name]);
    assert!(
        public.status.success(),
        "public failed: {}",
        stderr(&public)
    );
    let hex = String::from_utf8_lossy(&public.stdout);
    let hex = hex.trim();
    assert_eq!(hex.len(), 144, "expected 72-byte ECC public blob as hex");
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));

    let open = run(&["open", "--name", &name]);
    assert!(open.status.success(), "open failed: {}", stderr(&open));
    assert!(String::from_utf8_lossy(&open.stdout).contains("cross-process OK"));

    let delete = run(&["delete", "--name", &name]);
    assert!(
        delete.status.success(),
        "delete failed: {}",
        stderr(&delete)
    );

    // The key must be gone: a second open now fails.
    let reopen = run(&["open", "--name", &name]);
    assert!(!reopen.status.success(), "key should be deleted");
}

/// A second `init` on an existing name must be refused, not silently overwrite.
#[test]
#[ignore = "requires a registered AziHSM named-key provider"]
fn init_twice_is_refused_as_already_initialized() {
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("{error}"))
        .as_nanos();
    let name = format!("keytool-dup-{id:x}");

    let first = run(&["init", "--name", &name]);
    assert!(first.status.success(), "init failed: {}", stderr(&first));

    let second = run(&["init", "--name", &name]);
    // ErrorClass::AlreadyInitialized maps to exit code 10.
    assert_eq!(
        second.status.code(),
        Some(10),
        "duplicate init: {}",
        stderr(&second)
    );

    let delete = run(&["delete", "--name", &name]);
    assert!(
        delete.status.success(),
        "cleanup failed: {}",
        stderr(&delete)
    );
}

fn run(args: &[&str]) -> Output {
    Command::new(EXE)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("{error}"))
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
