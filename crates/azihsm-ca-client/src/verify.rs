//! Strict root and issued-leaf verification before artifact publication.

use crate::{Error, ErrorClass, Result};
use azihsm_ncrypt::hash_sha1;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::{FromDer, X509Certificate};

const ECDSA_SHA256_OID: &str = "1.2.840.10045.4.3.2";
const EC_PUBLIC_KEY_OID: &str = "1.2.840.10045.2.1";
const P256_OID: &str = "1.2.840.10045.3.1.7";
const ROOT_CN: &str = "AziHSM Demo Root";
const DIGITAL_SIGNATURE_ONLY: u16 = 1 << 0;
const KEY_CERT_SIGN_ONLY: u16 = 1 << 5;

pub fn verify_chain(
    root_der: &[u8],
    leaf_der: &[u8],
    expected_spki: &[u8],
    dns: &[String],
    ips: &[IpAddr],
) -> Result<()> {
    verify_chain_inner(root_der, leaf_der, expected_spki, dns, ips, true)
}

pub fn verify_chain_profile(
    root_der: &[u8],
    leaf_der: &[u8],
    expected_spki: &[u8],
    dns: &[String],
    ips: &[IpAddr],
) -> Result<()> {
    verify_chain_inner(root_der, leaf_der, expected_spki, dns, ips, false)
}

fn verify_chain_inner(
    root_der: &[u8],
    leaf_der: &[u8],
    expected_spki: &[u8],
    dns: &[String],
    ips: &[IpAddr],
    check_current_time: bool,
) -> Result<()> {
    tracing::info!(event = "certificate_verification_started");
    let root = parse(root_der, "root")?;
    let leaf = parse(leaf_der, "leaf")?;
    validate_p256_sha256(&root, "root")?;
    validate_p256_sha256(&leaf, "leaf")?;
    require_extension_set(&root, &["2.5.29.14", "2.5.29.15", "2.5.29.19"], "root")?;
    require_extension_set(
        &leaf,
        &[
            "2.5.29.14",
            "2.5.29.15",
            "2.5.29.17",
            "2.5.29.19",
            "2.5.29.35",
            "2.5.29.37",
        ],
        "leaf",
    )?;
    validate_root_profile(&root, check_current_time)?;
    root.verify_signature(None)
        .map_err(|_| validation("root self-signature is invalid"))?;
    validate_leaf_profile(&leaf, &root, expected_spki, check_current_time)?;
    leaf.verify_signature(Some(&root.tbs_certificate.subject_pki))
        .map_err(|_| validation("leaf certificate signature is invalid"))?;
    verify_sans(&leaf, dns, ips)?;
    tracing::info!(event = "certificate_verification_completed");
    Ok(())
}

fn require_extension_set(
    certificate: &X509Certificate<'_>,
    expected: &[&str],
    label: &str,
) -> Result<()> {
    let actual: BTreeSet<_> = certificate
        .extensions()
        .iter()
        .map(|extension| extension.oid.to_id_string())
        .collect();
    let expected: BTreeSet<_> = expected.iter().map(|value| (*value).to_owned()).collect();
    if certificate.extensions().len() == expected.len() && actual == expected {
        Ok(())
    } else {
        Err(validation(format!("{label} extension set is invalid")))
    }
}

fn validate_root_profile(root: &X509Certificate<'_>, check_current_time: bool) -> Result<()> {
    if root.tbs_certificate.subject != root.tbs_certificate.issuer {
        return Err(validation("root issuer does not equal root subject"));
    }
    if !exact_common_name(&root.tbs_certificate.subject, ROOT_CN) {
        return Err(validation("root subject is invalid"));
    }
    if check_current_time && !root.validity().is_valid() {
        return Err(validation("root validity is invalid"));
    }
    let basic = extension(root, "2.5.29.19")?;
    require_criticality(basic, true, "root basic constraints criticality is invalid")?;
    if !matches!(
        basic.parsed_extension(),
        ParsedExtension::BasicConstraints(value)
            if value.ca && value.path_len_constraint == Some(0)
    ) {
        return Err(validation("root basic constraints are invalid"));
    }
    let usage = extension(root, "2.5.29.15")?;
    require_criticality(usage, true, "root key usage criticality is invalid")?;
    if !matches!(
        usage.parsed_extension(),
        ParsedExtension::KeyUsage(value) if value.flags == KEY_CERT_SIGN_ONLY
    ) {
        return Err(validation("root key usage is invalid"));
    }
    let ski = subject_key_identifier(root)?;
    require_criticality(
        extension(root, "2.5.29.14")?,
        false,
        "root subject key identifier criticality is invalid",
    )?;
    if ski
        != hash_sha1(
            root.tbs_certificate
                .subject_pki
                .subject_public_key
                .data
                .as_ref(),
        )?
    {
        return Err(validation("root subject key identifier is invalid"));
    }
    Ok(())
}

fn validate_leaf_profile(
    leaf: &X509Certificate<'_>,
    root: &X509Certificate<'_>,
    expected_spki: &[u8],
    check_current_time: bool,
) -> Result<()> {
    if leaf.tbs_certificate.issuer != root.tbs_certificate.subject {
        return Err(validation("leaf issuer does not match root subject"));
    }
    if leaf.tbs_certificate.subject.iter_rdn().next().is_some() {
        return Err(validation("leaf subject is invalid"));
    }
    if check_current_time && !leaf.validity().is_valid() {
        return Err(validation("leaf validity is invalid"));
    }
    if leaf.tbs_certificate.subject_pki.raw != expected_spki {
        return Err(validation("leaf SPKI does not match the requested key"));
    }
    let basic = extension(leaf, "2.5.29.19")?;
    require_criticality(basic, true, "leaf basic constraints criticality is invalid")?;
    if !matches!(
        basic.parsed_extension(),
        ParsedExtension::BasicConstraints(value)
            if !value.ca && value.path_len_constraint.is_none()
    ) {
        return Err(validation("leaf basic constraints are invalid"));
    }
    let usage = extension(leaf, "2.5.29.15")?;
    require_criticality(usage, true, "leaf key usage criticality is invalid")?;
    if !matches!(
        usage.parsed_extension(),
        ParsedExtension::KeyUsage(value) if value.flags == DIGITAL_SIGNATURE_ONLY
    ) {
        return Err(validation("leaf key usage is invalid"));
    }
    let eku = extension(leaf, "2.5.29.37")?;
    require_criticality(eku, false, "leaf extended key usage criticality is invalid")?;
    if !matches!(
        eku.parsed_extension(),
        ParsedExtension::ExtendedKeyUsage(value) if only_server_auth(value)
    ) {
        return Err(validation("leaf extended key usage is invalid"));
    }
    require_criticality(
        extension(leaf, "2.5.29.17")?,
        true,
        "leaf SAN criticality is invalid",
    )?;
    let leaf_ski = subject_key_identifier(leaf)?;
    require_criticality(
        extension(leaf, "2.5.29.14")?,
        false,
        "leaf subject key identifier criticality is invalid",
    )?;
    if leaf_ski
        != hash_sha1(
            leaf.tbs_certificate
                .subject_pki
                .subject_public_key
                .data
                .as_ref(),
        )?
    {
        return Err(validation("leaf subject key identifier is invalid"));
    }
    let root_ski = subject_key_identifier(root)?;
    let aki = extension(leaf, "2.5.29.35")?;
    require_criticality(
        aki,
        false,
        "leaf authority key identifier criticality is invalid",
    )?;
    if !matches!(
        aki.parsed_extension(),
        ParsedExtension::AuthorityKeyIdentifier(value)
            if value.key_identifier.as_ref().is_some_and(|identifier| identifier.0 == root_ski)
                && value.authority_cert_issuer.is_none()
                && value.authority_cert_serial.is_none()
    ) {
        return Err(validation("leaf authority key identifier is invalid"));
    }

    Ok(())
}

fn require_criticality(
    extension: &x509_parser::extensions::X509Extension<'_>,
    expected: bool,
    message: &'static str,
) -> Result<()> {
    if extension.critical == expected {
        Ok(())
    } else {
        Err(validation(message))
    }
}

fn extension<'a>(
    certificate: &'a X509Certificate<'a>,
    oid: &str,
) -> Result<&'a x509_parser::extensions::X509Extension<'a>> {
    certificate
        .extensions()
        .iter()
        .find(|extension| extension.oid.to_id_string() == oid)
        .ok_or_else(|| validation("required certificate extension is missing"))
}

fn subject_key_identifier<'a>(certificate: &'a X509Certificate<'a>) -> Result<&'a [u8]> {
    match extension(certificate, "2.5.29.14")?.parsed_extension() {
        ParsedExtension::SubjectKeyIdentifier(identifier) => Ok(identifier.0),
        _ => Err(validation("subject key identifier is malformed")),
    }
}

fn exact_common_name(name: &x509_parser::x509::X509Name<'_>, expected: &str) -> bool {
    let mut rdns = name.iter_rdn();
    let Some(rdn) = rdns.next() else {
        return false;
    };
    if rdns.next().is_some() || rdn.iter().count() != 1 {
        return false;
    }
    name.iter_common_name()
        .filter_map(|attribute| attribute.as_str().ok())
        .eq([expected])
}

fn only_server_auth(usage: &x509_parser::extensions::ExtendedKeyUsage<'_>) -> bool {
    usage.server_auth
        && !usage.any
        && !usage.client_auth
        && !usage.code_signing
        && !usage.email_protection
        && !usage.time_stamping
        && !usage.ocsp_signing
        && usage.other.is_empty()
}

fn validate_p256_sha256(certificate: &X509Certificate<'_>, label: &str) -> Result<()> {
    let spki = &certificate.tbs_certificate.subject_pki;
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameter| parameter.as_oid().ok())
        .map(|oid| oid.to_id_string());
    if certificate.signature_algorithm.algorithm.to_id_string() != ECDSA_SHA256_OID
        || certificate.signature_algorithm.parameters.is_some()
        || certificate
            .tbs_certificate
            .signature
            .algorithm
            .to_id_string()
            != ECDSA_SHA256_OID
        || certificate.tbs_certificate.signature.parameters.is_some()
        || spki.algorithm.algorithm.to_id_string() != EC_PUBLIC_KEY_OID
        || curve.as_deref() != Some(P256_OID)
        || spki.subject_public_key.unused_bits != 0
        || spki.subject_public_key.data.len() != 65
        || spki.subject_public_key.data.first() != Some(&4)
    {
        return Err(validation(format!(
            "{label} certificate is not P-256/SHA-256"
        )));
    }
    Ok(())
}

fn verify_sans(
    leaf: &X509Certificate<'_>,
    expected_dns: &[String],
    expected_ips: &[IpAddr],
) -> Result<()> {
    let san = leaf
        .subject_alternative_name()
        .map_err(|_| validation("leaf SAN extension is malformed"))?
        .ok_or_else(|| validation("leaf SAN extension is missing"))?;
    let mut dns = BTreeSet::new();
    let mut ips = BTreeSet::new();
    for name in &san.value.general_names {
        match name {
            GeneralName::DNSName(name) => {
                dns.insert((*name).to_owned());
            }
            GeneralName::IPAddress(bytes) if bytes.len() == 4 => {
                ips.insert(IpAddr::V4(Ipv4Addr::new(
                    bytes[0], bytes[1], bytes[2], bytes[3],
                )));
            }
            GeneralName::IPAddress(bytes) if bytes.len() == 16 => {
                let value: [u8; 16] = (*bytes)
                    .try_into()
                    .map_err(|_| validation("leaf IPv6 SAN is malformed"))?;
                ips.insert(IpAddr::V6(Ipv6Addr::from(value)));
            }
            _ => return Err(validation("leaf contains an unsupported SAN")),
        }
    }
    if dns != expected_dns.iter().cloned().collect()
        || ips != expected_ips.iter().copied().collect()
        || san.value.general_names.len() != expected_dns.len() + expected_ips.len()
        || dns.len() + ips.len() != expected_dns.len() + expected_ips.len()
    {
        return Err(validation("leaf SANs do not exactly match the request"));
    }
    Ok(())
}

fn parse<'a>(bytes: &'a [u8], label: &str) -> Result<X509Certificate<'a>> {
    let (remainder, certificate) = X509Certificate::from_der(bytes)
        .map_err(|_| validation(format!("{label} certificate DER is malformed")))?;
    if !remainder.is_empty() {
        return Err(validation(format!(
            "{label} certificate has trailing bytes"
        )));
    }
    Ok(certificate)
}

fn validation(message: impl Into<String>) -> Error {
    Error::new(ErrorClass::Validation, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DistinguishedName, DnType,
        ExtendedKeyUsagePurpose, IsCa, Issuer, KeyIdMethod, KeyPair, KeyUsagePurpose,
        PublicKeyData, SanType,
    };
    use time::{Duration, OffsetDateTime};

    #[derive(Clone, Copy)]
    enum Mutation {
        None,
        RootAlgorithm,
        LeafSpkiAlgorithm,
        LeafSignatureAlgorithm,
        RootIssuer,
        LeafIssuer,
        RootMissingExtension,
        LeafMissingExtension,
        RootUnexpectedExtension,
        LeafUnexpectedExtension,
        RootDuplicateExtension,
        LeafDuplicateExtension,
        ExtraRootKeyUsage,
        ExtraLeafKeyUsage,
        UndefinedLeafKeyUsage,
        ExtraLeafExtendedKeyUsage,
        RootPathLength,
        RootCaFalse,
        LeafCa,
        RootBasicConstraintsNotCritical,
        RootKeyUsageNotCritical,
        RootSkiCritical,
        LeafBasicConstraintsNotCritical,
        LeafKeyUsageNotCritical,
        LeafExtendedKeyUsageCritical,
        LeafSanNotCritical,
        LeafSkiCritical,
        LeafAkiCritical,
        RootSubject,
        LeafSubject,
        RootSkiMismatch,
        LeafSkiMismatch,
        LeafAkiMismatch,
        LeafAkiIssuer,
        LeafAkiSerial,
        RootExpired,
        LeafExpired,
        UnsupportedSan,
        DuplicateSan,
        RootSignature,
        LeafSignature,
    }

    #[test]
    fn accepts_exact_ca_profile() {
        let chain = signed_chain(Mutation::None);
        verify_chain(
            &chain.root,
            &chain.leaf,
            &chain.leaf_spki,
            &["server.test".to_owned()],
            &[],
        )
        .unwrap_or_else(|error| panic!("{error}"));
    }

    #[test]
    fn rejects_correctly_signed_profile_variations() {
        for (mutation, expected) in [
            (
                Mutation::RootAlgorithm,
                "Validation: root certificate is not P-256/SHA-256",
            ),
            (
                Mutation::LeafSpkiAlgorithm,
                "Validation: leaf certificate is not P-256/SHA-256",
            ),
            (
                Mutation::LeafSignatureAlgorithm,
                "Validation: leaf certificate is not P-256/SHA-256",
            ),
            (
                Mutation::RootIssuer,
                "Validation: root issuer does not equal root subject",
            ),
            (
                Mutation::LeafIssuer,
                "Validation: leaf issuer does not match root subject",
            ),
            (
                Mutation::RootMissingExtension,
                "Validation: root extension set is invalid",
            ),
            (
                Mutation::LeafMissingExtension,
                "Validation: leaf extension set is invalid",
            ),
            (
                Mutation::RootUnexpectedExtension,
                "Validation: root extension set is invalid",
            ),
            (
                Mutation::LeafUnexpectedExtension,
                "Validation: leaf extension set is invalid",
            ),
            (
                Mutation::RootDuplicateExtension,
                "Validation: root extension set is invalid",
            ),
            (
                Mutation::LeafDuplicateExtension,
                "Validation: leaf extension set is invalid",
            ),
            (
                Mutation::ExtraRootKeyUsage,
                "Validation: root key usage is invalid",
            ),
            (
                Mutation::ExtraLeafKeyUsage,
                "Validation: leaf key usage is invalid",
            ),
            (
                Mutation::ExtraLeafExtendedKeyUsage,
                "Validation: leaf extended key usage is invalid",
            ),
            (
                Mutation::RootPathLength,
                "Validation: root basic constraints are invalid",
            ),
            (
                Mutation::RootCaFalse,
                "Validation: root basic constraints are invalid",
            ),
            (
                Mutation::LeafCa,
                "Validation: leaf basic constraints are invalid",
            ),
            (
                Mutation::RootBasicConstraintsNotCritical,
                "Validation: root basic constraints criticality is invalid",
            ),
            (
                Mutation::RootKeyUsageNotCritical,
                "Validation: root key usage criticality is invalid",
            ),
            (
                Mutation::RootSkiCritical,
                "Validation: root subject key identifier criticality is invalid",
            ),
            (
                Mutation::LeafBasicConstraintsNotCritical,
                "Validation: leaf basic constraints criticality is invalid",
            ),
            (
                Mutation::LeafKeyUsageNotCritical,
                "Validation: leaf key usage criticality is invalid",
            ),
            (
                Mutation::LeafExtendedKeyUsageCritical,
                "Validation: leaf extended key usage criticality is invalid",
            ),
            (
                Mutation::LeafSanNotCritical,
                "Validation: leaf SAN criticality is invalid",
            ),
            (
                Mutation::LeafSkiCritical,
                "Validation: leaf subject key identifier criticality is invalid",
            ),
            (
                Mutation::LeafAkiCritical,
                "Validation: leaf authority key identifier criticality is invalid",
            ),
            (Mutation::RootSubject, "Validation: root subject is invalid"),
            (Mutation::LeafSubject, "Validation: leaf subject is invalid"),
            (
                Mutation::RootSkiMismatch,
                "Validation: root subject key identifier is invalid",
            ),
            (
                Mutation::LeafSkiMismatch,
                "Validation: leaf subject key identifier is invalid",
            ),
            (
                Mutation::LeafAkiMismatch,
                "Validation: leaf authority key identifier is invalid",
            ),
            (
                Mutation::LeafAkiIssuer,
                "Validation: leaf authority key identifier is invalid",
            ),
            (
                Mutation::LeafAkiSerial,
                "Validation: leaf authority key identifier is invalid",
            ),
            (
                Mutation::RootExpired,
                "Validation: root validity is invalid",
            ),
            (
                Mutation::LeafExpired,
                "Validation: leaf validity is invalid",
            ),
            (
                Mutation::UnsupportedSan,
                "Validation: leaf contains an unsupported SAN",
            ),
            (
                Mutation::DuplicateSan,
                "Validation: leaf SANs do not exactly match the request",
            ),
            (
                Mutation::RootSignature,
                "Validation: root self-signature is invalid",
            ),
            (
                Mutation::LeafSignature,
                "Validation: leaf certificate signature is invalid",
            ),
        ] {
            let chain = signed_chain(mutation);
            assert_profile_error(
                &chain,
                &chain.leaf_spki,
                &["server.test".to_owned()],
                expected,
            );
        }
    }

    #[test]
    fn rejects_exact_san_and_requested_spki_mismatches() {
        let chain = signed_chain(Mutation::None);
        assert_profile_error(
            &chain,
            &chain.leaf_spki,
            &["different.test".to_owned()],
            "Validation: leaf SANs do not exactly match the request",
        );
        let other = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .unwrap_or_else(|error| panic!("{error}"));
        assert_profile_error(
            &chain,
            &other.subject_public_key_info(),
            &["server.test".to_owned()],
            "Validation: leaf SPKI does not match the requested key",
        );
    }

    #[test]
    fn rejects_required_key_usage_combined_with_undefined_bit() {
        let chain = signed_chain(Mutation::UndefinedLeafKeyUsage);
        assert_profile_error(
            &chain,
            &chain.leaf_spki,
            &["server.test".to_owned()],
            "Validation: leaf key usage is invalid",
        );
    }

    struct TestChain {
        root: Vec<u8>,
        leaf: Vec<u8>,
        leaf_spki: Vec<u8>,
    }

    fn signed_chain(mutation: Mutation) -> TestChain {
        let root_algorithm = if matches!(mutation, Mutation::RootAlgorithm) {
            &rcgen::PKCS_ECDSA_P384_SHA384
        } else {
            &rcgen::PKCS_ECDSA_P256_SHA256
        };
        let leaf_algorithm = if matches!(mutation, Mutation::LeafSpkiAlgorithm) {
            &rcgen::PKCS_ECDSA_P384_SHA384
        } else {
            &rcgen::PKCS_ECDSA_P256_SHA256
        };
        let root_key =
            KeyPair::generate_for(root_algorithm).unwrap_or_else(|error| panic!("{error}"));
        let leaf_key =
            KeyPair::generate_for(leaf_algorithm).unwrap_or_else(|error| panic!("{error}"));
        let now = OffsetDateTime::now_utc();

        let mut root_name = DistinguishedName::new();
        root_name.push(
            DnType::CommonName,
            if matches!(mutation, Mutation::RootSubject) {
                "Changed Root"
            } else {
                ROOT_CN
            },
        );
        let mut root_params = CertificateParams::default();
        root_params.distinguished_name = root_name;
        root_params.not_before = now - Duration::minutes(5);
        root_params.not_after = if matches!(mutation, Mutation::RootExpired) {
            now - Duration::minutes(1)
        } else {
            now + Duration::days(1)
        };
        root_params.is_ca = match mutation {
            Mutation::RootPathLength => IsCa::Ca(BasicConstraints::Constrained(1)),
            Mutation::RootBasicConstraintsNotCritical
            | Mutation::RootCaFalse
            | Mutation::RootSkiCritical => IsCa::NoCa,
            _ => IsCa::Ca(BasicConstraints::Constrained(0)),
        };
        root_params.key_usages = if matches!(
            mutation,
            Mutation::RootMissingExtension | Mutation::RootKeyUsageNotCritical
        ) {
            Vec::new()
        } else {
            vec![KeyUsagePurpose::KeyCertSign]
        };
        if matches!(mutation, Mutation::ExtraRootKeyUsage) {
            root_params
                .key_usages
                .push(KeyUsagePurpose::DigitalSignature);
        }
        let root_ski = if matches!(mutation, Mutation::RootSkiMismatch) {
            vec![0x55; 20]
        } else {
            hash_sha1(root_key.public_key_raw())
                .unwrap_or_else(|error| panic!("{error}"))
                .to_vec()
        };
        root_params.key_identifier_method = KeyIdMethod::PreSpecified(root_ski.clone());
        match mutation {
            Mutation::RootBasicConstraintsNotCritical => {
                root_params.custom_extensions.push(custom_extension(
                    &[2, 5, 29, 19],
                    root_ca_der(0),
                    false,
                ));
                root_params
                    .custom_extensions
                    .push(ski_extension(&root_ski, false));
            }
            Mutation::RootCaFalse => {
                root_params.custom_extensions.push(custom_extension(
                    &[2, 5, 29, 19],
                    vec![0x30, 0x00],
                    true,
                ));
                root_params
                    .custom_extensions
                    .push(ski_extension(&root_ski, false));
            }
            Mutation::RootSkiCritical => {
                root_params.custom_extensions.push(custom_extension(
                    &[2, 5, 29, 19],
                    root_ca_der(0),
                    true,
                ));
                root_params
                    .custom_extensions
                    .push(ski_extension(&root_ski, true));
            }
            Mutation::RootKeyUsageNotCritical => {
                root_params.custom_extensions.push(custom_extension(
                    &[2, 5, 29, 15],
                    vec![0x03, 0x02, 0x02, 0x04],
                    false,
                ));
            }
            Mutation::RootUnexpectedExtension => {
                root_params.custom_extensions.push(custom_extension(
                    &[1, 2, 3, 4],
                    vec![0x05, 0x00],
                    false,
                ));
            }
            Mutation::RootDuplicateExtension => {
                root_params
                    .custom_extensions
                    .push(ski_extension(&root_ski, false));
            }
            _ => {}
        }
        let root = if matches!(mutation, Mutation::RootIssuer) {
            let mut issuer_params = CertificateParams::default();
            let mut issuer_name = DistinguishedName::new();
            issuer_name.push(DnType::CommonName, "Changed Issuer");
            issuer_params.distinguished_name = issuer_name;
            issuer_params.key_identifier_method = KeyIdMethod::PreSpecified(root_ski.clone());
            root_params
                .signed_by(&root_key, &Issuer::from_params(&issuer_params, &root_key))
                .unwrap_or_else(|error| panic!("{error}"))
        } else {
            root_params
                .self_signed(&root_key)
                .unwrap_or_else(|error| panic!("{error}"))
        };

        let mut leaf_params = CertificateParams::default();
        leaf_params.not_before = now - Duration::minutes(5);
        leaf_params.not_after = if matches!(mutation, Mutation::LeafExpired) {
            now - Duration::minutes(1)
        } else {
            now + Duration::hours(1)
        };
        leaf_params.is_ca = match mutation {
            Mutation::LeafCa => IsCa::Ca(BasicConstraints::Constrained(0)),
            Mutation::LeafBasicConstraintsNotCritical | Mutation::LeafSkiCritical => IsCa::NoCa,
            _ => IsCa::ExplicitNoCa,
        };
        if matches!(mutation, Mutation::LeafSubject) {
            leaf_params
                .distinguished_name
                .push(DnType::CommonName, "changed.test");
        } else {
            leaf_params.distinguished_name = DistinguishedName::new();
        }
        leaf_params.subject_alt_names = if matches!(mutation, Mutation::LeafSanNotCritical) {
            leaf_params.custom_extensions.push(custom_extension(
                &[2, 5, 29, 17],
                vec![
                    0x30, 0x0d, 0x82, 0x0b, b's', b'e', b'r', b'v', b'e', b'r', b'.', b't', b'e',
                    b's', b't',
                ],
                false,
            ));
            Vec::new()
        } else {
            let mut names = vec![SanType::DnsName(
                "server.test"
                    .try_into()
                    .unwrap_or_else(|error| panic!("{error}")),
            )];
            if matches!(mutation, Mutation::UnsupportedSan) {
                names.push(SanType::URI(
                    "https://server.test"
                        .try_into()
                        .unwrap_or_else(|error| panic!("{error}")),
                ));
            } else if matches!(mutation, Mutation::DuplicateSan) {
                names.push(SanType::DnsName(
                    "server.test"
                        .try_into()
                        .unwrap_or_else(|error| panic!("{error}")),
                ));
            }
            names
        };
        leaf_params.key_usages = if matches!(
            mutation,
            Mutation::UndefinedLeafKeyUsage | Mutation::LeafKeyUsageNotCritical
        ) {
            leaf_params.custom_extensions.push(custom_extension(
                &[2, 5, 29, 15],
                if matches!(mutation, Mutation::UndefinedLeafKeyUsage) {
                    vec![0x03, 0x03, 0x06, 0x80, 0x40]
                } else {
                    vec![0x03, 0x02, 0x07, 0x80]
                },
                !matches!(mutation, Mutation::LeafKeyUsageNotCritical),
            ));
            Vec::new()
        } else {
            vec![KeyUsagePurpose::DigitalSignature]
        };
        if matches!(mutation, Mutation::ExtraLeafKeyUsage) {
            leaf_params
                .key_usages
                .push(KeyUsagePurpose::KeyEncipherment);
        }
        leaf_params.extended_key_usages = if matches!(mutation, Mutation::LeafMissingExtension) {
            Vec::new()
        } else {
            vec![ExtendedKeyUsagePurpose::ServerAuth]
        };
        if matches!(mutation, Mutation::ExtraLeafExtendedKeyUsage) {
            leaf_params
                .extended_key_usages
                .push(ExtendedKeyUsagePurpose::ClientAuth);
        } else if matches!(mutation, Mutation::LeafExtendedKeyUsageCritical) {
            leaf_params.extended_key_usages.clear();
            leaf_params.custom_extensions.push(custom_extension(
                &[2, 5, 29, 37],
                vec![
                    0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
                ],
                true,
            ));
        }
        let leaf_ski = if matches!(mutation, Mutation::LeafSkiMismatch) {
            vec![0x77; 20]
        } else {
            hash_sha1(leaf_key.public_key_raw())
                .unwrap_or_else(|error| panic!("{error}"))
                .to_vec()
        };
        leaf_params.key_identifier_method = KeyIdMethod::PreSpecified(leaf_ski.clone());
        if matches!(mutation, Mutation::LeafBasicConstraintsNotCritical) {
            leaf_params.custom_extensions.push(custom_extension(
                &[2, 5, 29, 19],
                vec![0x30, 0x00],
                false,
            ));
            leaf_params
                .custom_extensions
                .push(ski_extension(&leaf_ski, false));
        } else if matches!(mutation, Mutation::LeafSkiCritical) {
            leaf_params.custom_extensions.push(custom_extension(
                &[2, 5, 29, 19],
                vec![0x30, 0x00],
                true,
            ));
            leaf_params
                .custom_extensions
                .push(ski_extension(&leaf_ski, true));
        }
        if matches!(mutation, Mutation::LeafUnexpectedExtension) {
            leaf_params.custom_extensions.push(custom_extension(
                &[1, 2, 3, 4],
                vec![0x05, 0x00],
                false,
            ));
        } else if matches!(mutation, Mutation::LeafDuplicateExtension) {
            leaf_params
                .custom_extensions
                .push(ski_extension(&leaf_ski, false));
        }
        let custom_aki = matches!(
            mutation,
            Mutation::LeafAkiCritical | Mutation::LeafAkiIssuer | Mutation::LeafAkiSerial
        );
        leaf_params.use_authority_key_identifier_extension = !custom_aki;
        if custom_aki {
            let content = match mutation {
                Mutation::LeafAkiIssuer => aki_with_issuer(&root_ski),
                Mutation::LeafAkiSerial => aki_with_serial(&root_ski),
                _ => aki_key_id(&root_ski),
            };
            leaf_params.custom_extensions.push(custom_extension(
                &[2, 5, 29, 35],
                content,
                matches!(mutation, Mutation::LeafAkiCritical),
            ));
        }

        let mut issuer_params = root_params;
        if matches!(mutation, Mutation::LeafAkiMismatch) {
            issuer_params.key_identifier_method = KeyIdMethod::PreSpecified(vec![0xaa; 20]);
        }
        if matches!(mutation, Mutation::LeafIssuer) {
            let mut issuer_name = DistinguishedName::new();
            issuer_name.push(DnType::CommonName, "Changed Issuer");
            issuer_params.distinguished_name = issuer_name;
        }
        let alternate_signer = if matches!(mutation, Mutation::LeafSignatureAlgorithm) {
            Some(
                KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384)
                    .unwrap_or_else(|error| panic!("{error}")),
            )
        } else {
            None
        };
        let signing_key = alternate_signer.as_ref().unwrap_or(&root_key);
        let issuer = Issuer::from_params(&issuer_params, signing_key);
        let leaf = leaf_params
            .signed_by(&leaf_key, &issuer)
            .unwrap_or_else(|error| panic!("{error}"));
        let mut root_der = root.der().to_vec();
        let mut leaf_der = leaf.der().to_vec();
        if matches!(mutation, Mutation::RootSignature) {
            *root_der.last_mut().unwrap_or_else(|| panic!("empty root")) ^= 1;
        }
        if matches!(mutation, Mutation::LeafSignature) {
            *leaf_der.last_mut().unwrap_or_else(|| panic!("empty leaf")) ^= 1;
        }
        TestChain {
            root: root_der,
            leaf: leaf_der,
            leaf_spki: leaf_key.subject_public_key_info(),
        }
    }

    fn assert_profile_error(
        chain: &TestChain,
        expected_spki: &[u8],
        expected_dns: &[String],
        expected: &str,
    ) {
        let error = verify_chain(&chain.root, &chain.leaf, expected_spki, expected_dns, &[])
            .expect_err("profile mutation was accepted");
        assert_eq!(error.to_string(), expected);
    }

    fn ski_extension(identifier: &[u8], critical: bool) -> CustomExtension {
        let mut content = vec![0x04, identifier.len() as u8];
        content.extend_from_slice(identifier);
        custom_extension(&[2, 5, 29, 14], content, critical)
    }

    fn custom_extension(oid: &[u64], content: Vec<u8>, critical: bool) -> CustomExtension {
        let mut extension = CustomExtension::from_oid_content(oid, content);
        extension.set_criticality(critical);
        extension
    }

    fn root_ca_der(path_length: u8) -> Vec<u8> {
        vec![0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, path_length]
    }

    fn aki_key_id(identifier: &[u8]) -> Vec<u8> {
        let mut content = vec![0x30, 0x16, 0x80, identifier.len() as u8];
        content.extend_from_slice(identifier);
        content
    }

    fn aki_with_issuer(identifier: &[u8]) -> Vec<u8> {
        let mut content = vec![0x30, 0x1b, 0x80, identifier.len() as u8];
        content.extend_from_slice(identifier);
        content.extend_from_slice(&[0xa1, 0x03, 0x86, 0x01, b'a']);
        content
    }

    fn aki_with_serial(identifier: &[u8]) -> Vec<u8> {
        let mut content = vec![0x30, 0x19, 0x80, identifier.len() as u8];
        content.extend_from_slice(identifier);
        content.extend_from_slice(&[0x82, 0x01, 0x01]);
        content
    }
}
