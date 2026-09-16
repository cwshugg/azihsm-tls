// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_tls_client::client::run;
use azihsm_tls_client::error::ExitCode;
use std::path::Path;

#[test]
fn missing_ca_root_file_is_io_error() {
    let error = run(
        "127.0.0.1:9",
        Path::new("this-file-does-not-exist.pem"),
        "localhost",
        "hi",
    )
    .expect_err("missing CA root must fail");
    assert_eq!(error.code(), ExitCode::Io);
}

#[test]
fn empty_ca_root_file_is_trust_error() {
    let path = std::env::temp_dir().join(format!("tls-client-empty-{}.pem", std::process::id()));
    std::fs::write(&path, b"").expect("write temp file");
    let error = run("127.0.0.1:9", &path, "localhost", "hi").expect_err("empty CA root must fail");
    let _ = std::fs::remove_file(&path);
    assert_eq!(error.code(), ExitCode::Trust);
}

#[test]
fn non_certificate_ca_root_is_trust_error() {
    let path = std::env::temp_dir().join(format!("tls-client-junk-{}.pem", std::process::id()));
    std::fs::write(&path, b"not a certificate").expect("write temp file");
    let error = run("127.0.0.1:9", &path, "localhost", "hi").expect_err("junk CA root must fail");
    let _ = std::fs::remove_file(&path);
    assert_eq!(error.code(), ExitCode::Trust);
}
