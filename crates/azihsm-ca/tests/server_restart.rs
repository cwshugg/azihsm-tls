//! Live HTTP issuance and restart persistence using a uniquely owned named key.

#![cfg(windows)]

use azihsm_ca::policy::PROVIDER_NAME;
use azihsm_ca::win::ncrypt::AziProvider;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use windows_sys::Win32::Security::Cryptography::NCryptDeleteKey;

const EXE: &str = env!("CARGO_BIN_EXE_azihsm-ca");

#[test]
#[ignore = "requires registered mock provider and certreq"]
fn enrollment_survives_server_restart() {
    if env::var("AZIHSM_LIVE_TEST").as_deref() != Ok("mock") {
        panic!("BLOCKED: set AZIHSM_LIVE_TEST=mock");
    }
    let id = format!(
        "{:x}",
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_else(|error| panic!("{error}"))
            .as_nanos()
    );
    let key_name = format!("azihsm-ca-http-{id}");
    let root = env::current_dir()
        .unwrap_or_else(|error| panic!("{error}"))
        .join("target")
        .join(format!("server-restart-{id}"));
    fs::create_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));
    let state = root.join("state");
    run(&[
        "init",
        "--state-dir",
        text(&state),
        "--provider",
        PROVIDER_NAME,
        "--key-name",
        &key_name,
        "--root-valid-days",
        "30",
    ]);
    let inf = root.join("request.inf");
    let csr = root.join("request.der");
    fs::write(
        &inf,
        "[Version]\r\nSignature=\"$Windows NT$\"\r\n[NewRequest]\r\nSubject=\"CN=server.demo.internal\"\r\nExportable=FALSE\r\nMachineKeySet=FALSE\r\nProviderName=\"Microsoft Software Key Storage Provider\"\r\nKeyAlgorithm=ECDSA_P256\r\nKeySpec=0\r\nHashAlgorithm=SHA256\r\nRequestType=PKCS10\r\nSuppressDefaults=TRUE\r\nSMIME=FALSE\r\n[Extensions]\r\n2.5.29.17=\"{text}\"\r\n_continue_=\"DNS=server.demo.internal\"\r\n",
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let status = Command::new("certreq.exe")
        .args(["-new", "-f", "-q", "-binary", text(&inf), text(&csr)])
        .status()
        .unwrap_or_else(|error| panic!("BLOCKED: certreq unavailable: {error}"));
    assert!(status.success(), "BLOCKED: certreq failed with {status}");
    let csr_bytes = fs::read(&csr).unwrap_or_else(|error| panic!("{error}"));
    azihsm_ca::csr::parse(&csr_bytes).unwrap_or_else(|error| panic!("CSR parse failed: {error}"));
    let port = 18080 + (u16::from_le_bytes([id.as_bytes()[0], id.as_bytes()[1]]) % 1000);
    let mut server = start_server(&state, port);
    wait_ready(port);
    let key = "0123456789abcdef0123456789abcdef";
    let first = post(port, key, &csr_bytes);
    assert!(first.starts_with(b"HTTP/1.1 201"));
    let first_body = body(&first).to_vec();
    stop(&mut server);
    let mut restarted = start_server(&state, port);
    wait_ready(port);
    let replay = post(port, key, &csr_bytes);
    assert!(replay.starts_with(b"HTTP/1.1 200"));
    assert_eq!(body(&replay), first_body);
    let incomplete = state
        .join("issuances")
        .join("ffffffffffffffffffffffffffffffff");
    azihsm_ca::state::create_protected_dir(&incomplete)
        .unwrap_or_else(|error| panic!("state mutation failed: {error}"));
    wait_status(port, "/readyz", 503);
    assert!(get(port, "/livez").starts_with(b"HTTP/1.1 200"));
    assert!(get(port, "/v1/ca").starts_with(b"HTTP/1.1 503"));
    fs::remove_dir(&incomplete).unwrap_or_else(|error| panic!("{error}"));
    wait_ready(port);
    stop(&mut restarted);
    let provider = AziProvider::open_named(PROVIDER_NAME).unwrap_or_else(|error| panic!("{error}"));
    let mut key = provider
        .open_key(&key_name)
        .unwrap_or_else(|status| panic!("key reopen failed: 0x{:08x}", status as u32));
    // SAFETY: this test exclusively owns the collision-resistant name.
    let delete = unsafe { NCryptDeleteKey(key.key.0, 0) };
    assert!(delete >= 0, "key delete failed: 0x{:08x}", delete as u32);
    key.key.disarm();
    fs::remove_dir_all(&root).unwrap_or_else(|error| panic!("{error}"));
    println!(
        "PASS: HTTP 201, restart, HTTP 200 byte-identical replay, runtime fail-closed readiness and recovery, checked key cleanup"
    );
}

fn start_server(state: &std::path::Path, port: u16) -> Child {
    Command::new(EXE)
        .args([
            "serve",
            "--state-dir",
            text(state),
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--allow-dns",
            "server.demo.internal",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("server start failed: {error}"))
}

fn wait_ready(port: u16) {
    wait_status(port, "/readyz", 200);
}

fn wait_status(port: u16, path: &str, status: u16) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let response = get(port, path);
        if response.starts_with(format!("HTTP/1.1 {status}").as_bytes()) {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("{path} did not return {status}");
}

fn get(port: u16, path: &str) -> Vec<u8> {
    let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) else {
        return Vec::new();
    };
    write!(stream, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .unwrap_or_else(|error| panic!("{error}"));
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .unwrap_or_else(|error| panic!("{error}"));
    response
}

fn post(port: u16, key: &str, csr: &[u8]) -> Vec<u8> {
    let mut stream =
        TcpStream::connect(("127.0.0.1", port)).unwrap_or_else(|error| panic!("{error}"));
    write!(
        stream,
        "POST /v1/certificates HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/pkcs10\r\nIdempotency-Key: {key}\r\nContent-Length: {}\r\n\r\n",
        csr.len()
    )
    .unwrap_or_else(|error| panic!("{error}"));
    stream
        .write_all(csr)
        .unwrap_or_else(|error| panic!("{error}"));
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .unwrap_or_else(|error| panic!("{error}"));
    response
}

fn body(response: &[u8]) -> &[u8] {
    let position = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("response has no header terminator"));
    &response[position + 4..]
}

fn stop(child: &mut Child) {
    child.kill().unwrap_or_else(|error| panic!("{error}"));
    child.wait().unwrap_or_else(|error| panic!("{error}"));
}

fn run(arguments: &[&str]) {
    let status = Command::new(EXE)
        .args(arguments)
        .status()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(status.success(), "command failed with {status}");
}

fn text(path: &std::path::Path) -> &str {
    path.to_str()
        .unwrap_or_else(|| panic!("test path is not Unicode"))
}
