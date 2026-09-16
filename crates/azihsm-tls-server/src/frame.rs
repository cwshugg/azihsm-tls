//! Bounded framed-message protocol and deterministic content transcript.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_REQUEST: usize = 1_048_576;
pub const PREFIX: &[u8; 19] = b"azihsm-tls-server: ";
pub const MAX_RESPONSE: usize = MAX_REQUEST + PREFIX.len();

#[derive(Debug, PartialEq, Eq)]
pub enum ReadFrame {
    Eof,
    Payload(Vec<u8>),
}

pub async fn read_frame(reader: &mut (impl AsyncRead + Unpin)) -> io::Result<ReadFrame> {
    let mut header = [0_u8; 4];
    if reader.read(&mut header[..1]).await? == 0 {
        return Ok(ReadFrame::Eof);
    }
    reader.read_exact(&mut header[1..]).await?;
    let length = u32::from_be_bytes(header) as usize;
    if length > MAX_REQUEST {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "declared frame exceeds 1 MiB",
        ));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(ReadFrame::Payload(payload))
}

pub async fn write_response(
    writer: &mut (impl AsyncWrite + Unpin),
    request: &[u8],
) -> io::Result<()> {
    let length = PREFIX.len() + request.len();
    writer.write_all(&(length as u32).to_be_bytes()).await?;
    writer.write_all(PREFIX).await?;
    writer.write_all(request).await?;
    writer.flush().await
}

pub fn transcript(connection_id: u64, sequence: u64, direction: &str, bytes: &[u8]) {
    print!(
        "{}",
        render_transcript(connection_id, sequence, direction, bytes)
    );
}

fn render_transcript(connection_id: u64, sequence: u64, direction: &str, bytes: &[u8]) -> String {
    let (encoding, body) = match std::str::from_utf8(bytes) {
        Ok(text) => ("utf8", std::borrow::Cow::Borrowed(text)),
        Err(_) => ("base64", std::borrow::Cow::Owned(STANDARD.encode(bytes))),
    };
    format!(
        "=== TLS MESSAGE ===\nConnection-ID: {connection_id}\nFrame-Sequence: {sequence}\n\
         Direction: {direction}\nByte-Length: {}\nMessage-Encoding: {encoding}\nBody:\n{body}\n\
         === END TLS MESSAGE ===\n",
        bytes.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn zero_multiple_and_maximum_frames_round_trip() {
        let (mut writer, mut reader) = duplex(MAX_REQUEST + 64);
        writer
            .write_all(&0_u32.to_be_bytes())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            read_frame(&mut reader)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            ReadFrame::Payload(Vec::new())
        );
        let payload = vec![7_u8; MAX_REQUEST];
        writer
            .write_all(&(MAX_REQUEST as u32).to_be_bytes())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        writer
            .write_all(&payload)
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            read_frame(&mut reader)
                .await
                .unwrap_or_else(|error| panic!("{error}")),
            ReadFrame::Payload(payload)
        );
    }

    #[tokio::test]
    async fn oversized_and_partial_frames_fail() {
        let (mut writer, mut reader) = duplex(16);
        writer
            .write_all(&((MAX_REQUEST + 1) as u32).to_be_bytes())
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(
            read_frame(&mut reader)
                .await
                .expect_err("oversized frame must fail")
                .kind(),
            io::ErrorKind::InvalidData
        );
        let (mut writer, mut reader) = duplex(16);
        writer
            .write_all(&[0, 0])
            .await
            .unwrap_or_else(|error| panic!("{error}"));
        drop(writer);
        assert!(read_frame(&mut reader).await.is_err());
    }

    #[test]
    fn response_bounds_are_exact() {
        assert_eq!(PREFIX.len(), 19);
        assert_eq!(MAX_RESPONSE, 1_048_595);
        assert_eq!(MAX_RESPONSE + 4, 1_048_599);
        assert_eq!(STANDARD.encode(vec![0_u8; MAX_REQUEST]).len(), 1_398_104);
    }

    #[test]
    fn transcript_is_complete_utf8_or_padded_base64() {
        assert_eq!(
            render_transcript(7, 2, "received", b"hello"),
            "=== TLS MESSAGE ===\nConnection-ID: 7\nFrame-Sequence: 2\n\
             Direction: received\nByte-Length: 5\nMessage-Encoding: utf8\nBody:\nhello\n\
             === END TLS MESSAGE ===\n"
        );
        let rendered = render_transcript(8, 3, "sent", &[0xff, 0x00]);
        assert!(rendered.contains("Message-Encoding: base64\nBody:\n/wA=\n"));
        assert!(!rendered.contains("PRIVATE KEY"));
    }
}
