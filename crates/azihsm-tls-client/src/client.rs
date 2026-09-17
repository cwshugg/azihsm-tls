// Copyright (C) Microsoft Corporation. All rights reserved.

use crate::error::{Error, ExitCode, Result};
use rustls::pki_types::ServerName;
use rustls::{ClientConnection, RootCertStore, StreamOwned};
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::sync::Arc;

// Bounds a server-declared frame length: azihsm-tls-server caps requests at
// 1 MiB, so a response (request plus prefix) always fits well within 2 MiB.
const MAX_FRAME: usize = 2 * 1024 * 1024;

/// Connect to `connect` (host:port), validate the server strictly against the
/// certificates in `ca_root`, send `message`, and return the server's reply.
pub fn run(connect: &str, ca_root: &Path, server_name: &str, message: &str) -> Result<String> {
    let roots = load_roots(ca_root)?;
    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_safe_default_protocol_versions()
    .map_err(|error| Error::new(ExitCode::Tls, format!("protocol setup failed: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();

    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| Error::new(ExitCode::Usage, "server name is not a valid DNS name or IP"))?;
    let connection = ClientConnection::new(Arc::new(config), name)
        .map_err(|error| Error::new(ExitCode::Tls, format!("client setup failed: {error}")))?;

    let socket = TcpStream::connect(connect).map_err(|error| {
        Error::new(
            ExitCode::Io,
            format!("connect to {connect} failed: {error}"),
        )
    })?;
    let mut tls = StreamOwned::new(connection, socket);

    write_frame(&mut tls, message.as_bytes())?;
    let response = read_frame(&mut tls)?;
    // Close cleanly so the server sees a graceful shutdown, not an unexpected EOF.
    tls.conn.send_close_notify();
    let _ = tls.flush();
    Ok(String::from_utf8_lossy(&response).into_owned())
}

/// Send one length-prefixed frame: a 4-byte big-endian length then the payload,
/// matching the `azihsm-tls-server` wire protocol.
fn write_frame(tls: &mut impl Write, payload: &[u8]) -> Result<()> {
    let length = u32::try_from(payload.len())
        .map_err(|_| Error::new(ExitCode::Usage, "message is larger than 4 GiB"))?;
    tls.write_all(&length.to_be_bytes())
        .map_err(|error| classify_io("write", error))?;
    tls.write_all(payload)
        .map_err(|error| classify_io("write", error))?;
    tls.flush().map_err(|error| classify_io("flush", error))?;
    Ok(())
}

/// Read one length-prefixed frame and return its payload.
fn read_frame(tls: &mut impl Read) -> Result<Vec<u8>> {
    let mut header = [0_u8; 4];
    tls.read_exact(&mut header)
        .map_err(|error| classify_io("read", error))?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_FRAME {
        return Err(Error::new(
            ExitCode::Io,
            format!("response frame of {length} bytes exceeds the {MAX_FRAME} byte limit"),
        ));
    }
    let mut payload = vec![0_u8; length];
    tls.read_exact(&mut payload)
        .map_err(|error| classify_io("read", error))?;
    Ok(payload)
}

fn load_roots(ca_root: &Path) -> Result<RootCertStore> {
    let pem = std::fs::read(ca_root).map_err(|error| {
        Error::new(ExitCode::Io, format!("read {}: {error}", ca_root.display()))
    })?;
    let mut reader = BufReader::new(&pem[..]);
    let mut roots = RootCertStore::empty();
    let mut added = 0_usize;
    for entry in rustls_pemfile::certs(&mut reader) {
        let cert = entry
            .map_err(|error| Error::new(ExitCode::Trust, format!("parse CA root: {error}")))?;
        roots
            .add(cert)
            .map_err(|error| Error::new(ExitCode::Trust, format!("add CA root: {error}")))?;
        added += 1;
    }
    if added == 0 {
        return Err(Error::new(
            ExitCode::Trust,
            "CA root file contains no certificates",
        ));
    }
    Ok(roots)
}

/// A TLS validation failure surfaces as an I/O error whose source is a
/// `rustls::Error`; map those to the Trust class, everything else to Io.
fn classify_io(operation: &str, error: std::io::Error) -> Error {
    if let Some(inner) = error
        .get_ref()
        .and_then(|e| e.downcast_ref::<rustls::Error>())
    {
        return Error::new(ExitCode::Trust, format!("{operation}: {inner}"));
    }
    Error::new(ExitCode::Io, format!("{operation}: {error}"))
}
