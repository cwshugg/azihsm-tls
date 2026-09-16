//! Exact P-256 PKCS #10 construction and local proof-of-possession validation.

use crate::{Error, ErrorClass, Result};
use azihsm_ncrypt::{AzihsmKey, AzihsmSigningKey, PublicP256Key};
use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use x509_parser::cri_attributes::ParsedCriAttribute;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509CertificationRequest};

pub fn spki_der(public_blob: &[u8; 72]) -> Result<Vec<u8>> {
    use rcgen::PublicKeyData;
    Ok(PublicP256Key::from_blob(public_blob)?.subject_public_key_info())
}

pub fn build(
    key: &AzihsmKey,
    public_blob: &[u8; 72],
    subject_cn: &str,
    dns: &[String],
    ips: &[IpAddr],
) -> Result<Vec<u8>> {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, subject_cn);
    let mut params = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.subject_alt_names = dns
        .iter()
        .map(|name| {
            name.clone()
                .try_into()
                .map(SanType::DnsName)
                .map_err(|_| Error::new(ErrorClass::Validation, "invalid DNS SAN"))
        })
        .chain(
            ips.iter()
                .copied()
                .map(|address| Ok(SanType::IpAddress(address))),
        )
        .collect::<Result<_>>()?;
    let signer = AzihsmSigningKey::new(key, public_blob)?;
    params
        .serialize_request(&signer)
        .map(|request| request.der().to_vec())
        .map_err(|error| {
            signer.take_error().unwrap_or_else(|| {
                Error::new(
                    ErrorClass::Issuance,
                    format!("CSR generation failed: {error}"),
                )
            })
        })
}

pub fn validate(
    input: &[u8],
    expected_spki: &[u8],
    subject_cn: &str,
    dns: &[String],
    ips: &[IpAddr],
) -> Result<()> {
    let (remainder, csr) = X509CertificationRequest::from_der(input)
        .map_err(|_| Error::new(ErrorClass::Validation, "CSR DER is malformed"))?;
    if !remainder.is_empty()
        || csr.certification_request_info.subject_pki.raw != expected_spki
        || csr.signature_algorithm.algorithm.to_id_string() != "1.2.840.10045.4.3.2"
        || csr.signature_algorithm.parameters.is_some()
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "CSR algorithm or public key does not match",
        ));
    }
    csr.verify_signature()
        .map_err(|_| Error::new(ErrorClass::Validation, "CSR proof of possession failed"))?;
    let common_names: Vec<_> = csr
        .certification_request_info
        .subject
        .iter_common_name()
        .filter_map(|attribute| attribute.as_str().ok())
        .collect();
    if common_names != [subject_cn] {
        return Err(Error::new(
            ErrorClass::Validation,
            "CSR subject is not the exact requested CN",
        ));
    }
    let attributes = csr
        .certification_request_info
        .attributes_map()
        .map_err(|_| Error::new(ErrorClass::Validation, "CSR attributes are malformed"))?;
    if attributes.len() != 1 {
        return Err(Error::new(
            ErrorClass::Validation,
            "CSR must contain only one extensionRequest attribute",
        ));
    }
    let attribute = csr
        .certification_request_info
        .attributes()
        .first()
        .ok_or_else(|| Error::new(ErrorClass::Validation, "CSR extensionRequest is missing"))?;
    let request = match attribute.parsed_attribute() {
        ParsedCriAttribute::ExtensionRequest(request) => request,
        _ => {
            return Err(Error::new(
                ErrorClass::Validation,
                "CSR contains an unsupported attribute",
            ));
        }
    };
    if request.extensions.len() != 1 {
        return Err(Error::new(
            ErrorClass::Validation,
            "CSR must request only the SAN extension",
        ));
    }
    let san = match request.extensions[0].parsed_extension() {
        ParsedExtension::SubjectAlternativeName(san) => san,
        _ => {
            return Err(Error::new(
                ErrorClass::Validation,
                "CSR SAN extension is missing",
            ));
        }
    };
    let mut actual_dns = Vec::new();
    let mut actual_ips = Vec::new();
    for name in &san.general_names {
        match name {
            GeneralName::DNSName(name) => actual_dns.push((*name).to_owned()),
            GeneralName::IPAddress(bytes) if bytes.len() == 4 => actual_ips.push(IpAddr::V4(
                Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]),
            )),
            GeneralName::IPAddress(bytes) if bytes.len() == 16 => {
                let array: [u8; 16] = (*bytes)
                    .try_into()
                    .map_err(|_| Error::new(ErrorClass::Validation, "invalid IPv6 SAN"))?;
                actual_ips.push(IpAddr::V6(Ipv6Addr::from(array)));
            }
            _ => return Err(Error::new(ErrorClass::Validation, "unsupported CSR SAN")),
        }
    }
    if actual_dns != dns || actual_ips != ips {
        return Err(Error::new(
            ErrorClass::Validation,
            "CSR SANs differ from immutable request metadata",
        ));
    }
    Ok(())
}
