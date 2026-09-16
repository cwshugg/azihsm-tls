//! Independent Windows certificate-context and exclusive-chain acceptance oracle.

use crate::error::{Error, ErrorClass, Result};
use crate::policy::SERVER_AUTH_OID;
use crate::win::{bool_error, usize_to_u32};
use azihsm_ncrypt::PublicP256Key;
use rcgen::PublicKeyData;
use std::ptr::{null, null_mut};
use windows_sys::Win32::Security::Cryptography::*;
use x509_parser::prelude::{FromDer, X509Certificate};

#[derive(Debug)]
pub struct CertContext(*mut CERT_CONTEXT);

impl CertContext {
    pub fn create(encoded: &[u8]) -> Result<Self> {
        let context = unsafe {
            CertCreateCertificateContext(
                X509_ASN_ENCODING,
                encoded.as_ptr(),
                usize_to_u32(encoded.len(), "certificate")?,
            )
        };
        if context.is_null() {
            return Err(bool_error(
                ErrorClass::Validation,
                "CertCreateCertificateContext",
            ));
        }
        Ok(Self(context))
    }

    pub fn as_ptr(&self) -> *const CERT_CONTEXT {
        self.0
    }

    pub fn public_key_info(&self) -> *const CERT_PUBLIC_KEY_INFO {
        unsafe { &(*(*self.0).pCertInfo).SubjectPublicKeyInfo }
    }

    pub fn subject(&self) -> Result<&[u8]> {
        let subject = unsafe { &(*(*self.0).pCertInfo).Subject };
        if subject.pbData.is_null() || subject.cbData == 0 {
            return Err(Error::new(
                ErrorClass::Validation,
                "certificate subject is missing",
            ));
        }
        Ok(unsafe { std::slice::from_raw_parts(subject.pbData, subject.cbData as usize) })
    }

    pub fn subject_key_identifier(&self) -> Result<[u8; 20]> {
        let encoded = self.encoded();
        let (_, certificate) = X509Certificate::from_der(encoded)
            .map_err(|error| Error::new(ErrorClass::Validation, error.to_string()))?;
        let identifier = certificate
            .extensions()
            .iter()
            .find_map(|extension| match extension.parsed_extension() {
                x509_parser::extensions::ParsedExtension::SubjectKeyIdentifier(identifier) => {
                    Some(identifier.0)
                }
                _ => None,
            })
            .ok_or_else(|| Error::new(ErrorClass::Validation, "root SKI is missing"))?;
        identifier
            .try_into()
            .map_err(|_| Error::new(ErrorClass::Validation, "root SKI has the wrong length"))
    }

    pub fn validate_p256_public_blob(&self, expected: &[u8; 72]) -> Result<()> {
        let (_, certificate) = X509Certificate::from_der(self.encoded())
            .map_err(|error| Error::new(ErrorClass::Validation, error.to_string()))?;
        let expected = crate::crypto::public_point(expected)?;
        if certificate.public_key().subject_public_key.data.as_ref() != expected {
            return Err(Error::new(
                ErrorClass::Validation,
                "certificate SPKI does not match the named key",
            ));
        }
        Ok(())
    }

    fn encoded(&self) -> &[u8] {
        unsafe {
            std::slice::from_raw_parts((*self.0).pbCertEncoded, (*self.0).cbCertEncoded as usize)
        }
    }
}

impl Drop for CertContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CertFreeCertificateContext(self.0) };
        }
    }
}

pub fn verify_certificate_signature(certificate: &[u8], issuer: &CertContext) -> Result<()> {
    let (remainder, parsed) = X509Certificate::from_der(certificate)
        .map_err(|error| Error::new(ErrorClass::Validation, error.to_string()))?;
    let (issuer_remainder, issuer_cert) = X509Certificate::from_der(issuer.encoded())
        .map_err(|error| Error::new(ErrorClass::Validation, error.to_string()))?;
    if !remainder.is_empty() || !issuer_remainder.is_empty() {
        return Err(Error::new(
            ErrorClass::Validation,
            "certificate has trailing DER",
        ));
    }
    parsed
        .verify_signature(Some(issuer_cert.public_key()))
        .map_err(|error| Error::new(ErrorClass::Validation, error.to_string()))
}

pub fn verify_exclusive_chain(
    root: &CertContext,
    leaf: &CertContext,
    root_bytes: &[u8],
    leaf_bytes: &[u8],
) -> Result<()> {
    let store = unsafe {
        CertOpenStore(
            CERT_STORE_PROV_MEMORY,
            X509_ASN_ENCODING,
            0,
            CERT_STORE_CREATE_NEW_FLAG,
            null(),
        )
    };
    if store.is_null() {
        return Err(bool_error(ErrorClass::Validation, "CertOpenStore"));
    }
    if unsafe {
        CertAddCertificateContextToStore(store, root.as_ptr(), CERT_STORE_ADD_ALWAYS, null_mut())
    } == 0
    {
        unsafe { CertCloseStore(store, 0) };
        return Err(bool_error(
            ErrorClass::Validation,
            "CertAddCertificateContextToStore",
        ));
    }
    let config = CERT_CHAIN_ENGINE_CONFIG {
        cbSize: size_of::<CERT_CHAIN_ENGINE_CONFIG>() as u32,
        hExclusiveRoot: store,
        ..Default::default()
    };
    let mut engine = null_mut();
    if unsafe { CertCreateCertificateChainEngine(&config, &mut engine) } == 0 {
        unsafe { CertCloseStore(store, 0) };
        return Err(bool_error(
            ErrorClass::Validation,
            "CertCreateCertificateChainEngine",
        ));
    }
    let mut eku = SERVER_AUTH_OID.as_ptr().cast_mut();
    let mut parameters = CERT_CHAIN_PARA {
        cbSize: size_of::<CERT_CHAIN_PARA>() as u32,
        ..Default::default()
    };
    parameters.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    parameters.RequestedUsage.Usage.cUsageIdentifier = 1;
    parameters.RequestedUsage.Usage.rgpszUsageIdentifier = &mut eku;
    let mut chain = null_mut();
    let flags = CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL
        | CERT_CHAIN_DISABLE_AIA
        | CERT_CHAIN_DISABLE_AUTH_ROOT_AUTO_UPDATE;
    let ok = unsafe {
        CertGetCertificateChain(
            engine,
            leaf.as_ptr(),
            null(),
            null_mut(),
            &parameters,
            flags,
            null(),
            &mut chain,
        )
    };
    if ok == 0 || chain.is_null() {
        unsafe {
            CertFreeCertificateChainEngine(engine);
            CertCloseStore(store, 0);
        }
        return Err(bool_error(
            ErrorClass::Validation,
            "CertGetCertificateChain",
        ));
    }
    let valid = unsafe {
        let context = &*chain;
        context.TrustStatus.dwErrorStatus == 0 && context.cChain == 1 && {
            let simple = &**context.rgpChain;
            simple.TrustStatus.dwErrorStatus == 0
                && simple.cElement == 2
                && (0..2).all(|index| {
                    let element = &**simple.rgpElement.add(index);
                    let native = &*element.pCertContext;
                    let bytes = std::slice::from_raw_parts(
                        native.pbCertEncoded,
                        native.cbCertEncoded as usize,
                    );
                    element.TrustStatus.dwErrorStatus == 0
                        && bytes == if index == 0 { leaf_bytes } else { root_bytes }
                })
        }
    };
    unsafe {
        CertFreeCertificateChain(chain);
        CertFreeCertificateChainEngine(engine);
        CertCloseStore(store, 0);
    }
    if valid {
        Ok(())
    } else {
        Err(Error::new(
            ErrorClass::Validation,
            "exclusive chain was not a clean leaf-to-supplied-root chain",
        ))
    }
}

pub fn spki_der_from_blob(blob: &[u8; 72]) -> Result<Vec<u8>> {
    Ok(PublicP256Key::from_blob(blob)?.subject_public_key_info())
}
