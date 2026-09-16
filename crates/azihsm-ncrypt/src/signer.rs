//! Rcgen adapter for message signing through a named AziHSM NCrypt key.

use crate::{AzihsmKey, Error, ErrorClass, Result, hash_sha256, public_point};
use rcgen::{PublicKeyData, SignatureAlgorithm, SigningKey};
use std::sync::Mutex;

#[derive(Debug)]
pub struct AzihsmSigningKey<'a> {
    key: &'a AzihsmKey,
    point: [u8; 65],
    native_error: Mutex<Option<(ErrorClass, String)>>,
}

impl<'a> AzihsmSigningKey<'a> {
    pub fn new(key: &'a AzihsmKey, public_blob: &[u8; 72]) -> Result<Self> {
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

impl PublicKeyData for AzihsmSigningKey<'_> {
    fn der_bytes(&self) -> &[u8] {
        &self.point
    }

    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl SigningKey for AzihsmSigningKey<'_> {
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
    use super::{PublicP256Key, p1363_to_der};
    use rcgen::PublicKeyData;

    #[test]
    fn converts_fixed_width_signature_to_canonical_der() {
        let mut signature = [1; 64];
        signature[0] = 0x80;
        let der = p1363_to_der(&signature).unwrap_or_else(|error| panic!("{error}"));
        assert_eq!(der[0], 0x30);
        assert_eq!(&der[2..5], &[0x02, 0x21, 0]);
    }

    #[test]
    fn rejects_zero_components() {
        assert!(p1363_to_der(&[0; 64]).is_err());
        let mut signature = [1; 64];
        signature[32..].fill(0);
        assert!(p1363_to_der(&signature).is_err());
    }

    #[test]
    fn public_blob_converts_to_stable_p256_spki() {
        let mut blob = [0_u8; 72];
        blob[..4].copy_from_slice(&0x3153_4345_u32.to_le_bytes());
        blob[4..8].copy_from_slice(&32_u32.to_le_bytes());
        blob[8..40].copy_from_slice(&[
            0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
        ]);
        blob[40..].copy_from_slice(&[
            0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f,
            0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5,
        ]);
        let spki = PublicP256Key::from_blob(&blob)
            .unwrap_or_else(|error| panic!("{error}"))
            .subject_public_key_info();
        assert_eq!(spki.len(), 91);
        assert_eq!(&spki[0..4], &[0x30, 0x59, 0x30, 0x13]);
        assert_eq!(spki[26], 0x04);
        assert_eq!(&spki[27..], &blob[8..]);
    }
}
