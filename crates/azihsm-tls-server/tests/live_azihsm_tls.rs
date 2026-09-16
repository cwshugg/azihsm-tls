//! Operator-gated live CA enrollment and AziHSM-backed rustls handshake.

#![cfg(windows)]

use rustls::client::Resumption;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::env;
use std::fs;
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

const EXE: &str = env!("CARGO_BIN_EXE_azihsm-tls-server");

#[test]
#[ignore = "requires the registered AziHSM provider and a live compatible CA"]
fn live_enrollment_handshake_cache_outage_and_delete() {
    let ca_url = env::var("AZIHSM_TLS_SERVER_LIVE_CA_URL")
        .unwrap_or_else(|_| panic!("BLOCKED: set AZIHSM_TLS_SERVER_LIVE_CA_URL"));
    let upstream = ca_url
        .strip_prefix("http://")
        .unwrap_or_else(|| panic!("live CA URL must use http://"))
        .parse()
        .unwrap_or_else(|error| panic!("live CA URL must contain a socket address: {error}"));
    let (proxy_port, stop_proxy, proxy) = start_proxy(upstream);
    let proxied_ca_url = format!("http://127.0.0.1:{proxy_port}");
    let id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|error| panic!("{error}"))
        .as_nanos();
    let state = env::current_dir()
        .unwrap_or_else(|error| panic!("{error}"))
        .join("target")
        .join(format!("tls-server-live-{id:x}"));
    fs::create_dir_all(
        state
            .parent()
            .unwrap_or_else(|| panic!("state has no parent")),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let key_name = format!("azihsm-tls-server-live-{id:x}");
    let port = reserve_port();
    let mut child = Command::new(EXE)
        .args([
            "run",
            "--state-dir",
            text(&state),
            "--listen",
            &format!("127.0.0.1:{port}"),
            "--dns",
            "server.demo.internal",
            "--ca-url",
            &proxied_ca_url,
            "--acknowledge-plain-http",
            "--key-name",
            &key_name,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("{error}"));
    wait_for(&state.join("root.der"));
    assert_locked(Command::new(EXE).args([
        "delete-key",
        "--state-dir",
        text(&state),
        "--confirm-key-name",
        &key_name,
    ]));
    let demo = std::path::Path::new(EXE)
        .parent()
        .unwrap_or_else(|| panic!("server executable has no parent"))
        .join("azihsm-ca-demo.exe");
    assert_locked(Command::new(&demo).args(["show", "--output-dir", text(&state)]));
    assert_locked(Command::new(&demo).args([
        "delete-key",
        "--output-dir",
        text(&state),
        "--confirm-key-name",
        &key_name,
    ]));
    let root = fs::read(state.join("root.der")).unwrap_or_else(|error| panic!("{error}"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap_or_else(|error| panic!("{error}"));
    runtime.block_on(exchange(port, root));
    child.kill().unwrap_or_else(|error| panic!("{error}"));
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("{error}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.matches("certificate_verify_sign_completed").count(),
        1
    );
    let released = Command::new(&demo)
        .args(["show", "--output-dir", text(&state)])
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(
        released.status.success(),
        "demo did not recover after server lock release: {}",
        String::from_utf8_lossy(&released.stderr)
    );
    stop_proxy.store(true, Ordering::SeqCst);
    let _ = std::net::TcpStream::connect(("127.0.0.1", proxy_port));
    proxy.join().unwrap_or_else(|_| panic!("proxy failed"));

    let second_port = reserve_port();
    let mut child = Command::new(EXE)
        .args([
            "run",
            "--state-dir",
            text(&state),
            "--listen",
            &format!("127.0.0.1:{second_port}"),
            "--dns",
            "server.demo.internal",
            "--ca-url",
            &proxied_ca_url,
            "--acknowledge-plain-http",
            "--key-name",
            &key_name,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|error| panic!("{error}"));
    runtime.block_on(exchange(
        second_port,
        fs::read(state.join("root.der")).unwrap_or_else(|error| panic!("{error}")),
    ));
    child.kill().unwrap_or_else(|error| panic!("{error}"));
    let output = child
        .wait_with_output()
        .unwrap_or_else(|error| panic!("{error}"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("renewal_availability_fallback"));
    assert_eq!(
        stdout.matches("certificate_verify_sign_completed").count(),
        1
    );

    let protocol = start_protocol_server(proxy_port);
    let failed = Command::new(EXE)
        .args([
            "run",
            "--state-dir",
            text(&state),
            "--listen",
            &format!("127.0.0.1:{}", reserve_port()),
            "--dns",
            "server.demo.internal",
            "--ca-url",
            &proxied_ca_url,
            "--acknowledge-plain-http",
            "--key-name",
            &key_name,
        ])
        .output()
        .unwrap_or_else(|error| panic!("{error}"));
    protocol
        .join()
        .unwrap_or_else(|_| panic!("protocol server failed"));
    assert!(!failed.status.success());
    assert!(!String::from_utf8_lossy(&failed.stdout).contains("renewal_availability_fallback"));

    let status = Command::new(EXE)
        .args([
            "delete-key",
            "--state-dir",
            text(&state),
            "--confirm-key-name",
            &key_name,
        ])
        .status()
        .unwrap_or_else(|error| panic!("{error}"));
    assert!(status.success());
    fs::remove_dir_all(state).unwrap_or_else(|error| panic!("{error}"));
}

fn start_protocol_server(port: u16) -> thread::JoinHandle<()> {
    let listener = TcpListener::bind(("127.0.0.1", port)).unwrap_or_else(|error| panic!("{error}"));
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap_or_else(|error| panic!("{error}"));
        let mut request = [0_u8; 4096];
        let _ = std::io::Read::read(&mut stream, &mut request);
        std::io::Write::write_all(
            &mut stream,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1\r\nConnection: close\r\n\r\n{",
        )
        .unwrap_or_else(|error| panic!("{error}"));
    })
}

fn assert_locked(command: &mut Command) {
    let output = command.output().unwrap_or_else(|error| panic!("{error}"));
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("state is locked by another process"));
}

async fn exchange(port: u16, root: Vec<u8>) {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(root))
        .unwrap_or_else(|error| panic!("{error}"));
    let provider = rustls::crypto::ring::default_provider();
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap_or_else(|error| panic!("{error}"))
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.resumption = Resumption::disabled();
    let socket = connect(port).await;
    let name = ServerName::try_from("server.demo.internal")
        .unwrap_or_else(|error| panic!("{error}"))
        .to_owned();
    let mut tls = TlsConnector::from(Arc::new(config))
        .connect(name, socket)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    tls.write_all(&4_u32.to_be_bytes())
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    tls.write_all(b"ping")
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let mut header = [0_u8; 4];
    tls.read_exact(&mut header)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    let mut payload = vec![0_u8; u32::from_be_bytes(header) as usize];
    tls.read_exact(&mut payload)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
    assert_eq!(payload, b"azihsm-tls-server: ping");
}

async fn connect(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server did not listen");
}

fn reserve_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap_or_else(|error| panic!("{error}"))
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"))
        .port()
}

fn start_proxy(upstream: std::net::SocketAddr) -> (u16, Arc<AtomicBool>, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap_or_else(|error| panic!("{error}"));
    listener
        .set_nonblocking(true)
        .unwrap_or_else(|error| panic!("{error}"));
    let port = listener
        .local_addr()
        .unwrap_or_else(|error| panic!("{error}"))
        .port();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !thread_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((client, _)) => {
                    thread::spawn(move || {
                        let server = std::net::TcpStream::connect(upstream)
                            .unwrap_or_else(|error| panic!("{error}"));
                        let mut client_read =
                            client.try_clone().unwrap_or_else(|error| panic!("{error}"));
                        let mut server_write =
                            server.try_clone().unwrap_or_else(|error| panic!("{error}"));
                        let forward = thread::spawn(move || {
                            let _ = std::io::copy(&mut client_read, &mut server_write);
                        });
                        let mut server_read = server;
                        let mut client_write = client;
                        let _ = std::io::copy(&mut server_read, &mut client_write);
                        let _ = forward.join();
                    });
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("{error}"),
            }
        }
    });
    (port, stop, handle)
}

fn wait_for(path: &std::path::Path) {
    for _ in 0..200 {
        if path.exists() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("server state was not prepared");
}

fn text(path: &std::path::Path) -> &str {
    path.to_str()
        .unwrap_or_else(|| panic!("test path is not Unicode"))
}
