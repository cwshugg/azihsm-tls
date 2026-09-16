//! Rcgen certificate construction and x509-parser inspection.

use crate::crypto::{hash_sha1, public_point};
use crate::error::{Error, ErrorClass, Result};
use crate::policy::CLOCK_SKEW_SECONDS;
use azihsm_ncrypt::{AzihsmKey, AzihsmSigningKey, PublicP256Key};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyIdMethod, KeyUsagePurpose, SanType, SerialNumber,
};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};
use time::OffsetDateTime;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug, Clone)]
pub struct CertificateBacking {
    params: CertificateParams,
    public_blob: [u8; 72],
    issuer_params: Option<CertificateParams>,
}

impl CertificateBacking {
    pub fn root(
        public_blob: &[u8; 72],
        serial: [u8; 16],
        now: SystemTime,
        valid_days: u16,
    ) -> Result<Self> {
        let mut distinguished_name = DistinguishedName::new();
        distinguished_name.push(DnType::CommonName, crate::policy::ROOT_CN);
        let mut params = CertificateParams::default();
        params.distinguished_name = distinguished_name;
        params.serial_number = Some(SerialNumber::from_slice(
            &serial.into_iter().rev().collect::<Vec<_>>(),
        ));
        params.not_before = offset(
            now.checked_sub(Duration::from_secs(CLOCK_SKEW_SECONDS as u64))
                .ok_or_else(|| Error::new(ErrorClass::Issuance, "root notBefore underflow"))?,
        )?;
        params.not_after = offset(
            now.checked_add(Duration::from_secs(u64::from(valid_days) * 86_400))
                .ok_or_else(|| Error::new(ErrorClass::Issuance, "root notAfter overflow"))?,
        )?;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params.key_identifier_method =
            KeyIdMethod::PreSpecified(hash_sha1(&public_point(public_blob)?)?.to_vec());
        Ok(Self {
            params,
            public_blob: *public_blob,
            issuer_params: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn leaf(
        public_blob: &[u8; 72],
        serial: [u8; 16],
        root_ski: &[u8; 20],
        not_before: SystemTime,
        not_after: SystemTime,
        dns_sans: &[String],
        ip_sans: &[IpAddr],
    ) -> Result<Self> {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.serial_number = Some(SerialNumber::from_slice(
            &serial.into_iter().rev().collect::<Vec<_>>(),
        ));
        params.not_before = offset(not_before)?;
        params.not_after = offset(not_after)?;
        params.subject_alt_names = dns_sans
            .iter()
            .map(|name| {
                name.clone()
                    .try_into()
                    .map(SanType::DnsName)
                    .map_err(|_| Error::new(ErrorClass::Validation, "invalid DNS SAN"))
            })
            .chain(ip_sans.iter().copied().map(|ip| Ok(SanType::IpAddress(ip))))
            .collect::<Result<_>>()?;
        params.is_ca = IsCa::ExplicitNoCa;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.key_identifier_method =
            KeyIdMethod::PreSpecified(hash_sha1(&public_point(public_blob)?)?.to_vec());
        params.use_authority_key_identifier_extension = true;
        let mut issuer_params = CertificateParams::default();
        let mut issuer_name = DistinguishedName::new();
        issuer_name.push(DnType::CommonName, crate::policy::ROOT_CN);
        issuer_params.distinguished_name = issuer_name;
        issuer_params.key_identifier_method = KeyIdMethod::PreSpecified(root_ski.to_vec());
        issuer_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        Ok(Self {
            params,
            public_blob: *public_blob,
            issuer_params: Some(issuer_params),
        })
    }

    pub fn to_be_signed_der(&self) -> Result<Vec<u8>> {
        let der = self.preview()?;
        Ok(parse(&der)?.tbs_certificate.as_ref().to_vec())
    }

    pub fn sign(&self, key: &AzihsmKey) -> Result<Vec<u8>> {
        let signing_key = AzihsmSigningKey::new(key, &key.public_blob()?)?;
        let result = if self.params.is_ca == IsCa::Ca(BasicConstraints::Constrained(0)) {
            self.params.self_signed(&signing_key)
        } else {
            let root_params = self.issuer_params.as_ref().ok_or_else(|| {
                Error::new(ErrorClass::State, "leaf issuer parameters are missing")
            })?;
            let issuer = Issuer::from_params(root_params, &signing_key);
            self.params
                .signed_by(&PublicP256Key::from_blob(&self.public_blob)?, &issuer)
        };
        result
            .map(|certificate| certificate.der().to_vec())
            .map_err(|error| {
                signing_key.take_error().unwrap_or_else(|| {
                    Error::new(
                        ErrorClass::Issuance,
                        format!("rcgen signing failed: {error}"),
                    )
                })
            })
    }

    fn preview(&self) -> Result<Vec<u8>> {
        #[derive(Debug)]
        struct Preview([u8; 65]);
        impl rcgen::PublicKeyData for Preview {
            fn der_bytes(&self) -> &[u8] {
                &self.0
            }
            fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
                &rcgen::PKCS_ECDSA_P256_SHA256
            }
        }
        impl rcgen::SigningKey for Preview {
            fn sign(&self, _: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
                Ok(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
            }
        }
        let preview = Preview(public_point(&self.public_blob)?);
        self.params
            .self_signed(&preview)
            .map(|cert| cert.der().to_vec())
            .map_err(|error| Error::new(ErrorClass::Validation, error.to_string()))
    }
}

fn offset(time: SystemTime) -> Result<OffsetDateTime> {
    Ok(OffsetDateTime::from(time))
}

fn parse(bytes: &[u8]) -> Result<X509Certificate<'_>> {
    let (remainder, certificate) = X509Certificate::from_der(bytes)
        .map_err(|error| Error::new(ErrorClass::Validation, error.to_string()))?;
    if !remainder.is_empty() {
        return Err(Error::new(
            ErrorClass::Validation,
            "certificate has trailing bytes",
        ));
    }
    Ok(certificate)
}

pub fn certificate_tbs(bytes: &[u8]) -> Result<Vec<u8>> {
    Ok(parse(bytes)?.tbs_certificate.as_ref().to_vec())
}

pub fn certificate_not_after(bytes: &[u8]) -> Result<OffsetDateTime> {
    Ok(parse(bytes)?.validity().not_after.to_datetime())
}
