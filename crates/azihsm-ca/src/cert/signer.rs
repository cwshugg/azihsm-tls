//! Rcgen signing adapter that keeps every CA signature on AziHSM through NCrypt.

use crate::crypto::{hash_sha256, public_point};
use crate::error::{Error, ErrorClass, Result};
use crate::win::ncrypt::AziKey;
use rcgen::{PublicKeyData, SignatureAlgorithm, SigningKey};
use std::sync::Mutex;

#[derive(Debug)]
pub struct AziHsmSigningKey<'a> {
    key: &'a AziKey,
    point: [u8; 65],
    native_error: Mutex<Option<(ErrorClass, String)>>,
}

impl<'a> AziHsmSigningKey<'a> {
    pub fn new(key: &'a AziKey, public_blob: &[u8; 72]) -> Result<Self> {
        Ok(Self {
            key,
            point: public_point(public_blob)?,
            native_error: Mutex::new(None),
        })
    }

    pub fn take_error(&self) -> Option<Error> {
        self.native_error
            .lock()
            .ok()
            .and_then(|mut error| error.take())
            .map(|(class, message)| Error::new(class, message))
    }
}

impl PublicKeyData for AziHsmSigningKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for AziHsmSigningKey<'_> {
    fn sign(&self, message: &[u8]) -> std::result::Result<Vec<u8>, rcgen::Error> {
        if let Ok(mut error) = self.native_error.lock() {
            *error = None;
        }
        let result = hash_sha256(message)
            .and_then(|digest| self.key.sign(&digest))
            .and_then(|signature| p1363_to_der(&signature));
        match result {
            Ok(signature) => Ok(signature),
            Err(error) => {
                if let Ok(mut saved) = self.native_error.lock() {
                    *saved = Some((error.class(), error.to_string()));
                }
                Err(rcgen::Error::RemoteKeyError)
            }
        }
    }
}

#[derive(Debug)]
pub struct PublicP256Key([u8; 65]);

impl PublicP256Key {
    pub fn from_blob(blob: &[u8; 72]) -> Result<Self> {
        Ok(Self(public_point(blob)?))
    }
}

impl PublicKeyData for PublicP256Key {
    fn der_bytes(&self) -> &[u8] {
        &self.0
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

pub fn p1363_to_der(signature: &[u8]) -> Result<Vec<u8>> {
    if signature.len() != 64 {
        return Err(Error::new(
            ErrorClass::Validation,
            "P-256 signature must contain 64 bytes",
        ));
    }
    let r = integer(&signature[..32])?;
    let s = integer(&signature[32..])?;
    let mut output = vec![0x30, (r.len() + s.len()) as u8];
    output.extend(r);
    output.extend(s);
    Ok(output)
}

fn integer(value: &[u8]) -> Result<Vec<u8>> {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .ok_or_else(|| Error::new(ErrorClass::Validation, "ECDSA component must be nonzero"))?;
    let value = &value[first..];
    let prefix = usize::from(value[0] & 0x80 != 0);
    let mut output = Vec::with_capacity(value.len() + prefix + 2);
    output.extend([0x02, (value.len() + prefix) as u8]);
    if prefix != 0 {
        output.push(0);
    }
    output.extend(value);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::p1363_to_der;

    #[test]
    fn rejects_zero_components() {
        assert!(p1363_to_der(&[0; 64]).is_err());
        let mut signature = [1; 64];
        signature[32..].fill(0);
        assert!(p1363_to_der(&signature).is_err());
    }
}
