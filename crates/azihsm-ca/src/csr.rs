//! Strict PKCS #10 parsing and proof-of-possession using x509-parser and ring.

use crate::cli::ServeArgs;
use crate::crypto::hash_sha256;
use crate::error::{Error, ErrorClass, Result};
use crate::state::hex;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use x509_parser::cri_attributes::ParsedCriAttribute;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509CertificationRequest};

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
        return Err(Error::new(ErrorClass::Precondition, "san_not_allowed"));
    }
    Ok(parsed)
}

pub fn parse(input: &[u8]) -> Result<ParsedCsr> {
    if input.is_empty() || input.len() > 16_384 {
        return malformed("CSR size is outside policy");
    }
    let (remainder, csr) = X509CertificationRequest::from_der(input)
        .map_err(|error| malformed_error(&error.to_string()))?;
    if !remainder.is_empty() || csr.as_raw().len() != input.len() {
        return malformed("CSR has trailing bytes");
    }
    let info = &csr.certification_request_info;
    if info.version.0 != 0 || info.subject.as_raw().len() > 4096 {
        return unsupported("CSR version or subject is outside policy");
    }
    if info.subject.iter_rdn().count() > 64
        || info.subject.iter_rdn().any(|rdn| rdn.iter().count() > 16)
    {
        return unsupported("CSR subject exceeds structural bounds");
    }
    let algorithm = &info.subject_pki.algorithm;
    if algorithm.algorithm.to_id_string() != "1.2.840.10045.2.1"
        || algorithm
            .parameters
            .as_ref()
            .map(|parameter| parameter.as_oid().map(|oid| oid.to_id_string()))
            .transpose()
            .ok()
            .flatten()
            .as_deref()
            != Some("1.2.840.10045.3.1.7")
    {
        return unsupported("CSR key must be P-256");
    }
    let point = info.subject_pki.subject_public_key.data.as_ref();
    if info.subject_pki.subject_public_key.unused_bits != 0 || point.len() != 65 || point[0] != 4 {
        return unsupported("CSR public point is malformed");
    }
    if csr.signature_algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.2"
        || csr.signature_algorithm.parameters.is_some()
        || csr.signature_value.unused_bits != 0
        || !nonzero_canonical_ecdsa(csr.signature_value.data.as_ref())
    {
        return malformed("CSR signature algorithm is not parameterless ECDSA-SHA256");
    }

    fn nonzero_canonical_ecdsa(signature: &[u8]) -> bool {
        if signature.len() < 8
            || signature[0] != 0x30
            || usize::from(signature[1]) + 2 != signature.len()
        {
            return false;
        }
        let mut offset = 2;
        for _ in 0..2 {
            if signature.get(offset) != Some(&0x02) {
                return false;
            }
            let length = match signature.get(offset + 1) {
                Some(length) if *length > 0 => usize::from(*length),
                _ => return false,
            };
            let Some(integer) = signature.get(offset + 2..offset + 2 + length) else {
                return false;
            };
            if integer[0] & 0x80 != 0
                || integer.iter().all(|byte| *byte == 0)
                || (integer.len() > 1 && integer[0] == 0 && integer[1] & 0x80 == 0)
            {
                return false;
            }
            offset += 2 + length;
        }
        offset == signature.len()
    }
    csr.verify_signature()
        .map_err(|error| malformed_error(&error.to_string()))?;
    let attributes = info
        .attributes_map()
        .map_err(|error| unsupported_error(&error.to_string()))?;
    if attributes.len() != 1 {
        return unsupported("exactly one extensionRequest attribute is required");
    }
    let attribute = info
        .attributes()
        .first()
        .ok_or_else(|| unsupported_error("extensionRequest is missing"))?;
    let request = match attribute.parsed_attribute() {
        ParsedCriAttribute::ExtensionRequest(request) => request,
        _ => return unsupported("unsupported CSR attribute"),
    };
    if request.extensions.len() != 1 {
        return unsupported("exactly one SAN extension is required");
    }
    let extension = &request.extensions[0];
    let san = match extension.parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => san,
        _ => return unsupported("only Subject Alternative Name may be requested"),
    };
    let mut dns = BTreeSet::new();
    let mut ips = BTreeSet::new();
    for name in &san.general_names {
        match name {
            GeneralName::DNSName(name) => {
                crate::cli::validate_dns(name).map_err(|_| unsupported_error("invalid DNS SAN"))?;
                if !dns.insert((*name).to_owned()) {
                    return unsupported("duplicate DNS SAN");
                }
            }
            GeneralName::IPAddress(bytes) => {
                let address = match bytes.len() {
                    4 => IpAddr::V4(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])),
                    16 => IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(*bytes)
                            .map_err(|_| unsupported_error("invalid IPv6 SAN"))?,
                    )),
                    _ => return unsupported("invalid IP SAN"),
                };
                if address.is_unspecified() || address.is_multicast() || !ips.insert(address) {
                    return unsupported("invalid or duplicate IP SAN");
                }
            }
            _ => return unsupported("unsupported SAN type"),
        }
    }
    if dns.is_empty() && ips.is_empty() || dns.len() + ips.len() > 16 {
        return unsupported("SAN count is outside policy");
    }
    let mut public_blob = [0_u8; 72];
    public_blob[..4].copy_from_slice(&0x3153_4345_u32.to_le_bytes());
    public_blob[4..8].copy_from_slice(&32_u32.to_le_bytes());
    public_blob[8..].copy_from_slice(&point[1..]);
    let spki = info.subject_pki.raw.to_vec();
    Ok(ParsedCsr {
        public_blob,
        spki_sha256: hex(&hash_sha256(&spki)?),
        spki_der: spki,
        dns_sans: dns.into_iter().collect(),
        ip_sans: ips.into_iter().collect(),
    })
}

fn malformed_error(message: &str) -> Error {
    Error::new(ErrorClass::Validation, format!("malformed_csr: {message}"))
}

fn unsupported_error(message: &str) -> Error {
    Error::new(
        ErrorClass::Precondition,
        format!("unsupported_csr_profile: {message}"),
    )
}

fn malformed<T>(message: &str) -> Result<T> {
    Err(malformed_error(message))
}

fn unsupported<T>(message: &str) -> Result<T> {
    Err(unsupported_error(message))
}
