//! BCrypt hashing, random generation, P-256 keys, and verification.

use crate::error::{Error, ErrorClass, Result};
use crate::policy::{MAX_ECC_BLOB, MAX_SIGNATURE};
use crate::win::handles::{BcryptAlgorithm, BcryptHash, BcryptKey};
use crate::win::{status_error, usize_to_u32};
use std::ptr::{null, null_mut};
use windows_sys::Win32::Security::Cryptography::*;

pub fn random<const N: usize>() -> Result<[u8; N]> {
    let mut output = [0_u8; N];
    // SAFETY: output is writable for exactly N bytes; a null algorithm is valid with the system RNG flag.
    let status = unsafe {
        BCryptGenRandom(
            null_mut(),
            output.as_mut_ptr(),
            usize_to_u32(N, "random")?,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 {
        return Err(status_error(ErrorClass::Signing, "BCryptGenRandom", status));
    }
    Ok(output)
}

pub fn hash_sha256(data: &[u8]) -> Result<[u8; 32]> {
    hash(data, BCRYPT_SHA256_ALGORITHM, 32).and_then(|bytes| {
        bytes.try_into().map_err(|_| {
            Error::new(
                ErrorClass::Validation,
                "BCrypt SHA-256 returned the wrong length",
            )
        })
    })
}

pub fn hash_sha1(data: &[u8]) -> Result<[u8; 20]> {
    hash(data, BCRYPT_SHA1_ALGORITHM, 20).and_then(|bytes| {
        bytes.try_into().map_err(|_| {
            Error::new(
                ErrorClass::Validation,
                "BCrypt SHA-1 returned the wrong length",
            )
        })
    })
}

fn hash(data: &[u8], algorithm_name: *const u16, expected: usize) -> Result<Vec<u8>> {
    let mut algorithm = null_mut();
    // SAFETY: all output pointers are valid and null implementation is documented.
    let status = unsafe { BCryptOpenAlgorithmProvider(&mut algorithm, algorithm_name, null(), 0) };
    if status < 0 {
        return Err(status_error(
            ErrorClass::Validation,
            "BCryptOpenAlgorithmProvider(hash)",
            status,
        ));
    }
    let algorithm = BcryptAlgorithm(algorithm);
    let object_length = property_u32(algorithm.0, BCRYPT_OBJECT_LENGTH)?;
    let hash_length = property_u32(algorithm.0, BCRYPT_HASH_LENGTH)?;
    if object_length == 0 || object_length > 1024 * 1024 || hash_length as usize != expected {
        return Err(Error::new(
            ErrorClass::Validation,
            "invalid BCrypt hash provider lengths",
        ));
    }
    let mut object = vec![0_u8; object_length as usize];
    let mut hash_handle = null_mut();
    // SAFETY: object is initialized writable storage and all pointer/length pairs agree.
    let status = unsafe {
        BCryptCreateHash(
            algorithm.0,
            &mut hash_handle,
            object.as_mut_ptr(),
            object_length,
            null(),
            0,
            0,
        )
    };
    if status < 0 {
        return Err(status_error(
            ErrorClass::Validation,
            "BCryptCreateHash",
            status,
        ));
    }
    let hash_handle = BcryptHash(hash_handle);
    for chunk in data.chunks(u32::MAX as usize) {
        // SAFETY: chunk points to the stated initialized byte count.
        let status = unsafe {
            BCryptHashData(
                hash_handle.0,
                chunk.as_ptr(),
                usize_to_u32(chunk.len(), "hash input")?,
                0,
            )
        };
        if status < 0 {
            return Err(status_error(
                ErrorClass::Validation,
                "BCryptHashData",
                status,
            ));
        }
    }
    let mut output = vec![0_u8; expected];
    // SAFETY: output is writable for the stated size.
    let status = unsafe {
        BCryptFinishHash(
            hash_handle.0,
            output.as_mut_ptr(),
            usize_to_u32(output.len(), "hash output")?,
            0,
        )
    };
    if status < 0 {
        return Err(status_error(
            ErrorClass::Validation,
            "BCryptFinishHash",
            status,
        ));
    }
    hash_handle.release()?;
    object.fill(0);
    algorithm.release()?;
    Ok(output)
}

fn property_u32(handle: BCRYPT_HANDLE, name: *const u16) -> Result<u32> {
    let mut value = 0_u32;
    let mut written = 0_u32;
    // SAFETY: value is aligned writable u32 storage and the result length is checked.
    let status = unsafe {
        BCryptGetProperty(
            handle,
            name,
            (&mut value as *mut u32).cast(),
            size_of::<u32>() as u32,
            &mut written,
            0,
        )
    };
    if status < 0 || written != size_of::<u32>() as u32 {
        return Err(status_error(
            ErrorClass::Validation,
            "BCryptGetProperty",
            status,
        ));
    }
    Ok(value)
}

pub struct P256Key {
    pub key: BcryptKey,
    algorithm: BcryptAlgorithm,
}

impl P256Key {
    pub fn generate() -> Result<Self> {
        let mut algorithm = null_mut();
        // SAFETY: output pointer is valid and other pointers are documented constants/null.
        let status = unsafe {
            BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_ECDSA_P256_ALGORITHM, null(), 0)
        };
        if status < 0 {
            return Err(status_error(
                ErrorClass::Signing,
                "BCryptOpenAlgorithmProvider(P-256)",
                status,
            ));
        }
        let algorithm = BcryptAlgorithm(algorithm);
        let mut key = null_mut();
        // SAFETY: algorithm is live and output pointer is valid.
        let status = unsafe { BCryptGenerateKeyPair(algorithm.0, &mut key, 256, 0) };
        if status < 0 {
            return Err(status_error(
                ErrorClass::Signing,
                "BCryptGenerateKeyPair",
                status,
            ));
        }
        let key = BcryptKey(key);
        // SAFETY: key is a live unfinalized BCrypt key.
        let status = unsafe { BCryptFinalizeKeyPair(key.0, 0) };
        if status < 0 {
            return Err(status_error(
                ErrorClass::Signing,
                "BCryptFinalizeKeyPair",
                status,
            ));
        }
        Ok(Self { algorithm, key })
    }

    pub fn public_blob(&self) -> Result<[u8; 72]> {
        export_public(&self.key)
    }

    pub fn sign(&self, digest: &[u8; 32]) -> Result<[u8; 64]> {
        let mut output = [0_u8; 64];
        let mut written = 0_u32;
        // SAFETY: key is live, digest and output pointer/length pairs agree.
        let status = unsafe {
            BCryptSignHash(
                self.key.0,
                null(),
                digest.as_ptr(),
                digest.len() as u32,
                output.as_mut_ptr(),
                output.len() as u32,
                &mut written,
                0,
            )
        };
        if status < 0 || written != output.len() as u32 {
            return Err(status_error(
                ErrorClass::Validation,
                "BCryptSignHash",
                status,
            ));
        }
        Ok(output)
    }

    pub fn verify(&self, digest: &[u8; 32], signature: &[u8; 64]) -> Result<()> {
        verify(&self.key, digest, signature)
    }

    pub fn algorithm_handle_for_lifetime_check(&self) -> BCRYPT_ALG_HANDLE {
        self.algorithm.0
    }

    pub fn release(self) -> Result<()> {
        self.key.release()?;
        self.algorithm.release()
    }
}

pub fn import_public(blob: &[u8; 72]) -> Result<P256Key> {
    let mut algorithm = null_mut();
    // SAFETY: output pointer is valid and constants/null pointers meet the API contract.
    let status = unsafe {
        BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_ECDSA_P256_ALGORITHM, null(), 0)
    };
    if status < 0 {
        return Err(status_error(
            ErrorClass::Validation,
            "BCryptOpenAlgorithmProvider(import)",
            status,
        ));
    }
    let algorithm = BcryptAlgorithm(algorithm);
    let mut key = null_mut();
    // SAFETY: blob is an initialized public key blob of the stated length.
    let status = unsafe {
        BCryptImportKeyPair(
            algorithm.0,
            null_mut(),
            BCRYPT_ECCPUBLIC_BLOB,
            &mut key,
            blob.as_ptr(),
            blob.len() as u32,
            0,
        )
    };
    if status < 0 {
        return Err(status_error(
            ErrorClass::Validation,
            "BCryptImportKeyPair",
            status,
        ));
    }
    Ok(P256Key {
        key: BcryptKey(key),
        algorithm,
    })
}

fn export_public(key: &BcryptKey) -> Result<[u8; 72]> {
    let mut size = 0_u32;
    // SAFETY: the null output call is the documented sizing form.
    let status = unsafe {
        BCryptExportKey(
            key.0,
            null_mut(),
            BCRYPT_ECCPUBLIC_BLOB,
            null_mut(),
            0,
            &mut size,
            0,
        )
    };
    if status < 0 || size as usize > MAX_ECC_BLOB || size != 72 {
        return Err(status_error(
            ErrorClass::Validation,
            "BCryptExportKey(size)",
            status,
        ));
    }
    let mut output = [0_u8; 72];
    // SAFETY: output is writable for exactly the requested size.
    let status = unsafe {
        BCryptExportKey(
            key.0,
            null_mut(),
            BCRYPT_ECCPUBLIC_BLOB,
            output.as_mut_ptr(),
            output.len() as u32,
            &mut size,
            0,
        )
    };
    validate_public_blob(&output)?;
    if status < 0 {
        return Err(status_error(
            ErrorClass::Validation,
            "BCryptExportKey",
            status,
        ));
    }
    Ok(output)
}

pub fn validate_public_blob(blob: &[u8; 72]) -> Result<()> {
    let magic = u32::from_le_bytes(
        blob[0..4]
            .try_into()
            .map_err(|_| Error::new(ErrorClass::Validation, "invalid ECC public blob header"))?,
    );
    let key_size = u32::from_le_bytes(
        blob[4..8]
            .try_into()
            .map_err(|_| Error::new(ErrorClass::Validation, "invalid ECC public blob header"))?,
    );
    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC
        || key_size != 32
        || blob[8..40].iter().all(|byte| *byte == 0)
        || blob[40..72].iter().all(|byte| *byte == 0)
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "invalid P-256 public key blob",
        ));
    }
    Ok(())
}

pub(crate) fn verify(key: &BcryptKey, digest: &[u8; 32], signature: &[u8; 64]) -> Result<()> {
    if signature.len() > MAX_SIGNATURE {
        return Err(Error::new(
            ErrorClass::Validation,
            "signature exceeds policy cap",
        ));
    }
    // SAFETY: key is live and both read-only pointer/length pairs agree.
    let status = unsafe {
        BCryptVerifySignature(
            key.0,
            null(),
            digest.as_ptr(),
            digest.len() as u32,
            signature.as_ptr(),
            signature.len() as u32,
            0,
        )
    };
    if status < 0 {
        return Err(status_error(
            ErrorClass::Validation,
            "BCryptVerifySignature",
            status,
        ));
    }
    Ok(())
}
