//! Audited hashing, randomness, and public P-256 verification.

use crate::error::{Error, ErrorClass, Result};
use ring::{digest, rand, signature};

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut output = [0_u8; N];
    rand::SecureRandom::fill(&rand::SystemRandom::new(), &mut output)
        .map_err(|_| Error::new(ErrorClass::Signing, "system random generation failed"))?;
    Ok(output)
}

pub fn hash_sha256(data: &[u8]) -> Result<[u8; 32]> {
    digest::digest(&digest::SHA256, data)
        .as_ref()
        .try_into()
        .map_err(|_| Error::new(ErrorClass::Validation, "SHA-256 returned the wrong length"))
}

pub fn hash_sha1(data: &[u8]) -> Result<[u8; 20]> {
    digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data)
        .as_ref()
        .try_into()
        .map_err(|_| Error::new(ErrorClass::Validation, "SHA-1 returned the wrong length"))
}

pub fn public_point(blob: &[u8; 72]) -> Result<[u8; 65]> {
    let magic = u32::from_le_bytes(
        blob[..4]
            .try_into()
            .map_err(|_| Error::new(ErrorClass::Validation, "invalid ECC public blob header"))?,
    );
    let size = u32::from_le_bytes(
        blob[4..8]
            .try_into()
            .map_err(|_| Error::new(ErrorClass::Validation, "invalid ECC public blob header"))?,
    );
    if magic != 0x3153_4345
        || size != 32
        || blob[8..40].iter().all(|byte| *byte == 0)
        || blob[40..].iter().all(|byte| *byte == 0)
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "invalid P-256 public key blob",
        ));
    }
    let mut point = [0_u8; 65];
    point[0] = 4;
    point[1..].copy_from_slice(&blob[8..]);
    Ok(point)
}

pub fn verify_p256_sha256(
    public_blob: &[u8; 72],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<()> {
    let point = public_point(public_blob)?;
    signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
        .verify(message, signature)
        .map_err(|_| {
            Error::new(
                ErrorClass::Validation,
                "P-256 signature verification failed",
            )
        })
}
