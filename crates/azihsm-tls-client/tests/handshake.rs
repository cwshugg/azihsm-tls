// Copyright (C) Microsoft Corporation. All rights reserved.

use azihsm_tls_client::client::run;
use azihsm_tls_client::error::ExitCode;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, SanType,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use time::{Duration, OffsetDateTime};

const SERVER_NAME: &str = "server.test";

struct Chain {
    root_pem: String,
    leaf_der: CertificateDer<'static>,
    leaf_key_der: Vec<u8>,
}

/// Build a self-signed CA root and a `server.test` leaf signed by it.
fn build_chain() -> Chain {
    let now = OffsetDateTime::now_utc();
    let root_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("root key");
    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");

    let mut root_params = CertificateParams::default();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    root_params.not_before = now - Duration::hours(1);
    root_params.not_after = now + Duration::days(1);
    let root = root_params.self_signed(&root_key).expect("self-sign root");

    let mut leaf_params = CertificateParams::default();
    leaf_params.subject_alt_names = vec![SanType::DnsName(SERVER_NAME.try_into().expect("san"))];
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf_params.not_before = now - Duration::hours(1);
    leaf_params.not_after = now + Duration::days(1);
    let leaf = leaf_params
        .signed_by(&leaf_key, &Issuer::from_params(&root_params, &root_key))
        .expect("sign leaf");

    Chain {
        root_pem: root.pem(),
        leaf_der: leaf.der().clone(),
        leaf_key_der: leaf_key.serialize_der(),
    }
}

/// Start a single-shot TLS echo server; returns the bound port.
fn spawn_echo_server(leaf_der: CertificateDer<'static>, leaf_key_der: Vec<u8>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key_der));
    let config =
        ServerConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_safe_default_protocol_versions()
            .expect("versions")
            .with_no_client_auth()
            .with_single_cert(vec![leaf_der], key)
            .expect("server cert");
    let config = Arc::new(config);

    thread::spawn(move || {
        if let Ok((socket, _)) = listener.accept() {
            let _ = serve_once(config, socket);
        }
    });
    port
}

fn serve_once(config: Arc<ServerConfig>, socket: TcpStream) -> std::io::Result<()> {
    let connection = ServerConnection::new(config).expect("server connection");
    let mut tls = StreamOwned::new(connection, socket);
    let mut buffer = [0_u8; 1024];
    let read = tls.read(&mut buffer)?;
    tls.write_all(&buffer[..read])?;
    tls.conn.send_close_notify();
    tls.flush()?;
    Ok(())
}

#[test]
fn valid_server_cert_chains_to_trusted_root() {
    let chain = build_chain();
    let path = std::env::temp_dir().join(format!("tls-client-root-ok-{}.pem", std::process::id()));
    std::fs::write(&path, &chain.root_pem).expect("write root");
    let port = spawn_echo_server(chain.leaf_der, chain.leaf_key_der);

    let response = run(
        &format!("127.0.0.1:{port}"),
        &path,
        SERVER_NAME,
        "ping from client",
    );
    let _ = std::fs::remove_file(&path);
    let response = response.expect("handshake should succeed");
    assert_eq!(response, "ping from client");
}

#[test]
fn untrusted_root_is_rejected() {
    let served = build_chain();
    let other = build_chain();
    // Client trusts a DIFFERENT root than the one that signed the server leaf.
    let path = std::env::temp_dir().join(format!("tls-client-root-bad-{}.pem", std::process::id()));
    std::fs::write(&path, &other.root_pem).expect("write root");
    let port = spawn_echo_server(served.leaf_der, served.leaf_key_der);

    let result = run(&format!("127.0.0.1:{port}"), &path, SERVER_NAME, "ping");
    let _ = std::fs::remove_file(&path);
    let error = result.expect_err("untrusted server must be rejected");
    assert_eq!(error.code(), ExitCode::Trust);
}
