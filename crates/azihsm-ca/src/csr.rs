//! Strict bounded PKCS#10 DER parsing, SAN policy, and proof-of-possession verification.

use crate::cert::der::ecdsa_der_to_raw;
use crate::cli::ServeArgs;
use crate::error::{Error, ErrorClass, Result};
use crate::state::hex;
use crate::win::bcrypt::{hash_sha256, import_public};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr::null_mut;
use windows_sys::Win32::Security::Cryptography::{
    CERT_PUBLIC_KEY_INFO, CRYPT_ALGORITHM_IDENTIFIER, CRYPT_BIT_BLOB, CRYPT_INTEGER_BLOB,
    CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY, CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB,
    CryptVerifyCertificateSignatureEx, X509_ASN_ENCODING,
};

const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
const OID_SAN: &[u8] = &[0x55, 0x1d, 0x11];
const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedCsr {
    pub public_blob: [u8; 72],
    pub spki_der: Vec<u8>,
    pub spki_sha256: String,
    pub dns_sans: Vec<String>,
    pub ip_sans: Vec<IpAddr>,
}

pub fn parse_and_authorize(input: &[u8], policy: &ServeArgs) -> Result<ParsedCsr> {
    let parsed = parse(input)?;
    if parsed
        .dns_sans
        .iter()
        .any(|name| !policy.allow_dns.contains(name))
        || parsed
            .ip_sans
            .iter()
            .any(|address| !policy.allow_ip.contains(address))
    {
        return Err(Error::new(ErrorClass::Precondition, "san_not_authorized"));
    }
    Ok(parsed)
}

pub fn parse(input: &[u8]) -> Result<ParsedCsr> {
    if input.is_empty() || input.len() > 16_384 {
        return malformed("CSR size is outside policy");
    }
    let outer = one(input, 0x30)?;
    if outer.full.len() != input.len() {
        return malformed("CSR has trailing data");
    }
    let mut cursor = Cursor::new(outer.value);
    let cri = cursor.take(0x30)?;
    let algorithm = cursor.take(0x30)?;
    let signature = cursor.take(0x03)?;
    cursor.finish()?;
    validate_algorithm(algorithm.value)?;
    if signature.value.first() != Some(&0) {
        return malformed("CSR signature BIT STRING is malformed");
    }
    let signature_raw = ecdsa_der_to_raw(&signature.value[1..])
        .map_err(|_| Error::new(ErrorClass::Validation, "malformed_csr"))?;

    let mut cri_cursor = Cursor::new(cri.value);
    let version = cri_cursor.take(0x02)?;
    if version.value != [0] {
        return unsupported("CSR version must be zero");
    }
    let subject = cri_cursor.take(0x30)?;
    if subject.full.len() > 4096 {
        return Err(Error::new(ErrorClass::Validation, "malformed_subject"));
    }
    validate_subject(subject.value)?;
    let spki = cri_cursor.take(0x30)?;
    let attributes = cri_cursor.take(0xa0)?;
    cri_cursor.finish()?;
    let public_blob = parse_spki(spki.value)?;
    let (dns_sans, ip_sans) = parse_attributes(attributes.value)?;
    if dns_sans.is_empty() && ip_sans.is_empty() {
        return Err(Error::new(ErrorClass::Precondition, "san_required"));
    }
    if dns_sans.len() + ip_sans.len() > 16 {
        return unsupported("too many SAN entries");
    }
    let digest = hash_sha256(cri.full)?;
    let verifier = import_public(&public_blob)?;
    verifier.verify(&digest, &signature_raw)?;
    verify_with_crypt32(input, spki.value)?;
    Ok(ParsedCsr {
        public_blob,
        spki_der: spki.full.to_vec(),
        spki_sha256: hex(&hash_sha256(spki.full)?),
        dns_sans,
        ip_sans,
    })
}

fn validate_algorithm(value: &[u8]) -> Result<()> {
    let mut cursor = Cursor::new(value);
    let oid = cursor.take(0x06)?;
    cursor.finish()?;
    if oid.value != OID_ECDSA_SHA256 {
        return unsupported("CSR signature algorithm must be parameterless ECDSA-SHA256");
    }
    Ok(())
}

fn validate_subject(value: &[u8]) -> Result<()> {
    let mut cursor = Cursor::new(value);
    let mut rdns = 0;
    while !cursor.done() {
        rdns += 1;
        if rdns > 64 {
            return Err(Error::new(ErrorClass::Validation, "malformed_subject"));
        }
        let set = cursor.take(0x31)?;
        let mut set_cursor = Cursor::new(set.value);
        let mut attributes = 0;
        while !set_cursor.done() {
            attributes += 1;
            if attributes > 16 {
                return Err(Error::new(ErrorClass::Validation, "malformed_subject"));
            }
            let attribute = set_cursor.take(0x30)?;
            let mut attribute_cursor = Cursor::new(attribute.value);
            attribute_cursor.take(0x06)?;
            let value = attribute_cursor.take_any()?;
            if value.value.len() > 1024 {
                return Err(Error::new(ErrorClass::Validation, "malformed_subject"));
            }
            attribute_cursor.finish()?;
        }
    }
    Ok(())
}

fn parse_spki(value: &[u8]) -> Result<[u8; 72]> {
    let mut cursor = Cursor::new(value);
    let algorithm = cursor.take(0x30)?;
    let point = cursor.take(0x03)?;
    cursor.finish()?;
    let mut alg_cursor = Cursor::new(algorithm.value);
    if alg_cursor.take(0x06)?.value != OID_EC_PUBLIC_KEY || alg_cursor.take(0x06)?.value != OID_P256
    {
        return unsupported("CSR key must be uncompressed P-256");
    }
    alg_cursor.finish()?;
    if point.value.len() != 66 || point.value[0] != 0 || point.value[1] != 4 {
        return unsupported("CSR P-256 point is malformed");
    }
    let mut blob = [0; 72];
    blob[0..4].copy_from_slice(&0x3153_4345_u32.to_le_bytes());
    blob[4..8].copy_from_slice(&32_u32.to_le_bytes());
    blob[8..].copy_from_slice(&point.value[2..]);
    Ok(blob)
}

fn parse_attributes(value: &[u8]) -> Result<(Vec<String>, Vec<IpAddr>)> {
    if value.is_empty() {
        return Err(Error::new(ErrorClass::Precondition, "san_required"));
    }
    let mut cursor = Cursor::new(value);
    let attribute = cursor.take(0x30)?;
    if !cursor.done() {
        return unsupported("only one extensionRequest attribute is supported");
    }
    let mut attribute_cursor = Cursor::new(attribute.value);
    if attribute_cursor.take(0x06)?.value != OID_EXTENSION_REQUEST {
        return unsupported("only extensionRequest is supported");
    }
    let values = attribute_cursor.take(0x31)?;
    attribute_cursor.finish()?;
    let mut values_cursor = Cursor::new(values.value);
    let extensions = values_cursor.take(0x30)?;
    values_cursor.finish()?;
    let mut extensions_cursor = Cursor::new(extensions.value);
    let mut san = None;
    let mut saw_key_usage = false;
    while !extensions_cursor.done() {
        let extension = extensions_cursor.take(0x30)?;
        let mut extension_cursor = Cursor::new(extension.value);
        let oid = extension_cursor.take(0x06)?;
        let critical = if extension_cursor.peek() == Some(0x01) {
            extension_cursor.take(0x01)?.value == [0xff]
        } else {
            false
        };
        let octets = extension_cursor.take(0x04)?;
        extension_cursor.finish()?;
        if oid.value == OID_SAN {
            if san.replace(octets.value).is_some() {
                return unsupported("duplicate SAN extension");
            }
        } else if oid.value == OID_KEY_USAGE {
            if saw_key_usage || !critical || octets.value != [0x03, 0x02, 0x07, 0x80] {
                return unsupported("requested key usage must be critical digitalSignature only");
            }
            saw_key_usage = true;
        } else {
            return unsupported("unsupported requested extension");
        }
    }
    let san = san.ok_or_else(|| Error::new(ErrorClass::Precondition, "san_required"))?;
    parse_general_names(san)
}

fn parse_general_names(value: &[u8]) -> Result<(Vec<String>, Vec<IpAddr>)> {
    let sequence = one(value, 0x30)?;
    if sequence.full.len() != value.len() {
        return malformed("SAN extension has trailing data");
    }
    let mut cursor = Cursor::new(sequence.value);
    let mut dns = Vec::new();
    let mut ips = Vec::new();
    while !cursor.done() {
        match cursor.peek() {
            Some(0x82) => {
                let name = cursor.take(0x82)?;
                let text = std::str::from_utf8(name.value)
                    .map_err(|_| Error::new(ErrorClass::Precondition, "unsupported_csr_profile"))?;
                crate::cli::validate_dns(text)
                    .map_err(|_| Error::new(ErrorClass::Precondition, "unsupported_csr_profile"))?;
                if dns.iter().any(|existing| existing == text) {
                    return unsupported("duplicate DNS SAN");
                }
                dns.push(text.to_owned());
            }
            Some(0x87) => {
                let address = cursor.take(0x87)?;
                let parsed = match address.value.len() {
                    4 => IpAddr::V4(Ipv4Addr::new(
                        address.value[0],
                        address.value[1],
                        address.value[2],
                        address.value[3],
                    )),
                    16 => {
                        let bytes: [u8; 16] = address
                            .value
                            .try_into()
                            .map_err(|_| malformed_error("invalid IPv6 SAN"))?;
                        IpAddr::V6(Ipv6Addr::from(bytes))
                    }
                    _ => return unsupported("IP SAN must contain 4 or 16 bytes"),
                };
                if parsed.is_unspecified() || parsed.is_multicast() || ips.contains(&parsed) {
                    return unsupported("invalid or duplicate IP SAN");
                }
                ips.push(parsed);
            }
            _ => return unsupported("unsupported SAN type"),
        }
    }
    Ok((dns, ips))
}

fn verify_with_crypt32(input: &[u8], spki_value: &[u8]) -> Result<()> {
    let mut spki_cursor = Cursor::new(spki_value);
    let algorithm = spki_cursor.take(0x30)?;
    let point = spki_cursor.take(0x03)?;
    let mut alg_cursor = Cursor::new(algorithm.value);
    let _ = alg_cursor.take(0x06)?;
    let curve = alg_cursor.take(0x06)?;
    let mut oid = b"1.2.840.10045.2.1\0".to_vec();
    let mut curve_der = curve.full.to_vec();
    let mut point_bytes = point.value[1..].to_vec();
    let mut public = CERT_PUBLIC_KEY_INFO {
        Algorithm: CRYPT_ALGORITHM_IDENTIFIER {
            pszObjId: oid.as_mut_ptr(),
            Parameters: CRYPT_INTEGER_BLOB {
                cbData: curve_der.len() as u32,
                pbData: curve_der.as_mut_ptr(),
            },
        },
        PublicKey: CRYPT_BIT_BLOB {
            cbData: point_bytes.len() as u32,
            pbData: point_bytes.as_mut_ptr(),
            cUnusedBits: 0,
        },
    };
    let mut blob = CRYPT_INTEGER_BLOB {
        cbData: input.len() as u32,
        pbData: input.as_ptr().cast_mut(),
    };
    // SAFETY: the complete CSR blob and public-key graph remain live for this call.
    let ok = unsafe {
        CryptVerifyCertificateSignatureEx(
            0,
            X509_ASN_ENCODING,
            CRYPT_VERIFY_CERT_SIGN_SUBJECT_BLOB,
            (&mut blob as *mut CRYPT_INTEGER_BLOB).cast(),
            CRYPT_VERIFY_CERT_SIGN_ISSUER_PUBKEY,
            (&mut public as *mut CERT_PUBLIC_KEY_INFO).cast(),
            0,
            null_mut(),
        )
    };
    if ok == 0 {
        return malformed("Crypt32 rejected CSR proof of possession");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct Tlv<'a> {
    full: &'a [u8],
    value: &'a [u8],
}

fn one(input: &[u8], expected: u8) -> Result<Tlv<'_>> {
    parse_tlv(input, 0, expected).map(|(value, _)| value)
}

fn parse_tlv(input: &[u8], offset: usize, expected: u8) -> Result<(Tlv<'_>, usize)> {
    if input.get(offset).copied() != Some(expected) {
        return malformed("unexpected DER tag");
    }
    let first = *input
        .get(offset + 1)
        .ok_or_else(|| malformed_error("missing DER length"))?;
    let (length, header) = if first < 128 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            return malformed("invalid DER length");
        }
        let bytes = input
            .get(offset + 2..offset + 2 + count)
            .ok_or_else(|| malformed_error("truncated DER length"))?;
        if bytes[0] == 0 {
            return malformed("non-minimal DER length");
        }
        let length = bytes
            .iter()
            .fold(0usize, |total, byte| (total << 8) | *byte as usize);
        if length < 128 {
            return malformed("non-minimal DER length");
        }
        (length, 2 + count)
    };
    let start = offset
        .checked_add(header)
        .ok_or_else(|| malformed_error("DER overflow"))?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| malformed_error("DER overflow"))?;
    let full = input
        .get(offset..end)
        .ok_or_else(|| malformed_error("truncated DER value"))?;
    Ok((
        Tlv {
            full,
            value: &input[start..end],
        },
        end,
    ))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, tag: u8) -> Result<Tlv<'a>> {
        let (value, end) = parse_tlv(self.bytes, self.offset, tag)?;
        self.offset = end;
        Ok(value)
    }

    fn take_any(&mut self) -> Result<Tlv<'a>> {
        let tag = *self
            .bytes
            .get(self.offset)
            .ok_or_else(|| malformed_error("missing DER value"))?;
        self.take(tag)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }

    fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }

    fn finish(&self) -> Result<()> {
        if self.done() {
            Ok(())
        } else {
            malformed("DER object has trailing fields")
        }
    }
}

fn malformed_error(message: &str) -> Error {
    Error::new(ErrorClass::Validation, format!("malformed_csr: {message}"))
}

fn malformed<T>(message: &str) -> Result<T> {
    Err(malformed_error(message))
}

fn unsupported<T>(message: &str) -> Result<T> {
    Err(Error::new(
        ErrorClass::Precondition,
        format!("unsupported_csr_profile: {message}"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_trailing_and_non_der_input() {
        assert!(parse(&[0x30, 0x00, 0x00]).is_err());
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn dns_policy_is_exact() {
        assert!(crate::cli::validate_dns("server.demo.internal").is_ok());
        assert!(crate::cli::validate_dns("*.demo.internal").is_err());
        assert!(crate::cli::validate_dns("Server.demo.internal").is_err());
    }
}
