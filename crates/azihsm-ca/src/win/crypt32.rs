//! Stable certificate backing, Crypt32 signing, inspection, and isolated chain validation.

use crate::cert::der::{certificate_slices, ecdsa_der_to_raw};
use crate::error::{Error, ErrorClass, Result};
use crate::policy::{ECDSA_SHA256_OID, MAX_CERTIFICATE, MAX_NAME, SERVER_AUTH_OID};
use crate::win::bcrypt::{hash_sha1, hash_sha256};
use crate::win::{bool_error, usize_to_u32};
use std::ptr::{null, null_mut};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use windows_sys::Win32::Foundation::FILETIME;
use windows_sys::Win32::Security::Cryptography::*;

const WINDOWS_EPOCH_SECONDS: u64 = 11_644_473_600;

pub struct CertificateBacking {
    issuer: Box<[u8]>,
    subject: Box<[u8]>,
    serial: Box<[u8]>,
    point: Box<[u8]>,
    curve_oid_der: Box<[u8]>,
    extension_values: Vec<Box<[u8]>>,
    extensions: Box<[CERT_EXTENSION]>,
    info: Box<CERT_INFO>,
}

impl CertificateBacking {
    pub fn root(
        public_blob: &[u8; 72],
        serial: [u8; 16],
        now: SystemTime,
        valid_days: u16,
    ) -> Result<Self> {
        let name = encode_name("CN=AziHSM Demo Root")?;
        let point = point(public_blob);
        let ski = hash_sha1(&point)?;
        let extensions = vec![
            extension(
                szOID_BASIC_CONSTRAINTS2,
                true,
                vec![0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00],
            ),
            extension(szOID_KEY_USAGE, true, vec![0x03, 0x02, 0x02, 0x04]),
            extension(szOID_SUBJECT_KEY_IDENTIFIER, false, der_octet(&ski)),
        ];
        Self::build(
            name.clone(),
            name,
            serial,
            point,
            now.checked_sub(Duration::from_secs(300))
                .ok_or_else(|| Error::new(ErrorClass::Signing, "root notBefore underflow"))?,
            now.checked_add(Duration::from_secs(u64::from(valid_days) * 86_400))
                .ok_or_else(|| Error::new(ErrorClass::Signing, "root notAfter overflow"))?,
            extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn leaf(
        issuer: &[u8],
        public_blob: &[u8; 72],
        serial: [u8; 16],
        root_ski: &[u8; 20],
        now: SystemTime,
        valid_hours: u16,
        dns_sans: &[String],
        ip_sans: &[std::net::IpAddr],
    ) -> Result<Self> {
        let subject = vec![0x30, 0x00];
        let point = point(public_blob);
        let ski = hash_sha1(&point)?;
        let mut aki = vec![0x30, 0x16, 0x80, 0x14];
        aki.extend_from_slice(root_ski);
        let extensions = vec![
            extension(szOID_BASIC_CONSTRAINTS2, true, vec![0x30, 0x00]),
            extension(szOID_KEY_USAGE, true, vec![0x03, 0x02, 0x07, 0x80]),
            extension(szOID_SUBJECT_KEY_IDENTIFIER, false, der_octet(&ski)),
            extension(szOID_AUTHORITY_KEY_IDENTIFIER2, false, aki),
            extension(
                szOID_SUBJECT_ALT_NAME2,
                true,
                general_names(dns_sans, ip_sans)?,
            ),
            extension(
                szOID_ENHANCED_KEY_USAGE,
                false,
                vec![
                    0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
                ],
            ),
        ];
        Self::build(
            issuer.to_vec(),
            subject,
            serial,
            point,
            now.checked_sub(Duration::from_secs(300))
                .ok_or_else(|| Error::new(ErrorClass::Signing, "leaf notBefore underflow"))?,
            now.checked_add(Duration::from_secs(u64::from(valid_hours) * 3600))
                .ok_or_else(|| Error::new(ErrorClass::Signing, "leaf notAfter overflow"))?,
            extensions,
        )
    }

    fn build(
        issuer: Vec<u8>,
        subject: Vec<u8>,
        mut serial: [u8; 16],
        point: [u8; 65],
        not_before: SystemTime,
        not_after: SystemTime,
        values: Vec<ExtensionValue>,
    ) -> Result<Self> {
        serial[15] &= 0x7f;
        if serial.iter().all(|byte| *byte == 0) {
            serial[0] = 1;
        }
        let issuer = issuer.into_boxed_slice();
        let subject = subject.into_boxed_slice();
        let serial = serial.to_vec().into_boxed_slice();
        let point = point.to_vec().into_boxed_slice();
        let curve_oid_der =
            vec![0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07].into_boxed_slice();
        let extension_values: Vec<Box<[u8]>> = values
            .iter()
            .map(|value| value.bytes.clone().into_boxed_slice())
            .collect();
        let mut extensions = Vec::with_capacity(values.len());
        for (value, bytes) in values.iter().zip(&extension_values) {
            extensions.push(CERT_EXTENSION {
                pszObjId: value.oid.cast_mut(),
                fCritical: i32::from(value.critical),
                Value: CRYPT_INTEGER_BLOB {
                    cbData: usize_to_u32(bytes.len(), "extension")?,
                    pbData: bytes.as_ptr().cast_mut(),
                },
            });
        }
        let mut extensions = extensions.into_boxed_slice();
        let mut info = Box::new(CERT_INFO::default());
        info.dwVersion = CERT_V3;
        info.SerialNumber = blob(&serial)?;
        info.SignatureAlgorithm = signature_algorithm();
        info.Issuer = blob(&issuer)?;
        info.NotBefore = filetime(not_before)?;
        info.NotAfter = filetime(not_after)?;
        info.Subject = blob(&subject)?;
        info.SubjectPublicKeyInfo = CERT_PUBLIC_KEY_INFO {
            Algorithm: CRYPT_ALGORITHM_IDENTIFIER {
                pszObjId: crate::policy::EC_PUBLIC_KEY_OID.as_ptr().cast_mut(),
                Parameters: blob(&curve_oid_der)?,
            },
            PublicKey: CRYPT_BIT_BLOB {
                cbData: usize_to_u32(point.len(), "public point")?,
                pbData: point.as_ptr().cast_mut(),
                cUnusedBits: 0,
            },
        };
        info.cExtension = usize_to_u32(extensions.len(), "extensions")?;
        info.rgExtension = extensions.as_mut_ptr();
        Ok(Self {
            issuer,
            subject,
            serial,
            point,
            curve_oid_der,
            extension_values,
            extensions,
            info,
        })
    }

    pub fn issuer(&self) -> &[u8] {
        &self.issuer
    }

    pub fn subject(&self) -> &[u8] {
        &self.subject
    }

    pub fn serial_hex(&self) -> String {
        self.serial
            .iter()
            .rev()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub fn subject_key_identifier(&self) -> Result<[u8; 20]> {
        hash_sha1(&self.point)
    }

    pub fn to_be_signed_der(&self) -> Result<Vec<u8>> {
        let _keep_alive = (
            &self.curve_oid_der,
            &self.extension_values,
            &self.extensions,
        );
        let mut size = 0_u32;
        // SAFETY: all CERT_INFO pointers target frozen allocations owned by self.
        let ok = unsafe {
            CryptEncodeObjectEx(
                X509_ASN_ENCODING,
                X509_CERT_TO_BE_SIGNED,
                (&*self.info as *const CERT_INFO).cast(),
                0,
                null(),
                null_mut(),
                &mut size,
            )
        };
        if ok == 0 || size == 0 || size as usize > MAX_CERTIFICATE {
            return Err(bool_error(
                ErrorClass::Signing,
                "CryptEncodeObjectEx(root TBS size)",
            ));
        }
        let mut encoded = vec![0_u8; size as usize];
        // SAFETY: the stable CERT_INFO graph remains live and output has queried capacity.
        let ok = unsafe {
            CryptEncodeObjectEx(
                X509_ASN_ENCODING,
                X509_CERT_TO_BE_SIGNED,
                (&*self.info as *const CERT_INFO).cast(),
                0,
                null(),
                encoded.as_mut_ptr().cast(),
                &mut size,
            )
        };
        if ok == 0 || size as usize > encoded.len() {
            return Err(bool_error(
                ErrorClass::Signing,
                "CryptEncodeObjectEx(root TBS)",
            ));
        }
        encoded.truncate(size as usize);
        Ok(encoded)
    }

    pub fn sign(&self, key: NCRYPT_KEY_HANDLE) -> Result<Vec<u8>> {
        let _keep_alive = (
            &self.curve_oid_der,
            &self.extension_values,
            &self.extensions,
        );
        for _ in 0..3 {
            let mut size = 0_u32;
            let algorithm = signature_algorithm();
            // SAFETY: all nested CERT_INFO pointers target frozen allocations owned by self
            // for the duration of this synchronous call. OIDs are terminated static bytes.
            let ok = unsafe {
                CryptSignAndEncodeCertificate(
                    key,
                    0,
                    X509_ASN_ENCODING,
                    X509_CERT_TO_BE_SIGNED,
                    (&*self.info as *const CERT_INFO).cast(),
                    &algorithm,
                    null(),
                    null_mut(),
                    &mut size,
                )
            };
            if ok == 0 || size == 0 || size as usize > MAX_CERTIFICATE {
                return Err(bool_error(
                    ErrorClass::Signing,
                    "CryptSignAndEncodeCertificate(size)",
                ));
            }
            let mut encoded = vec![0_u8; size as usize];
            // SAFETY: same stable graph as above; output is writable for queried size.
            let ok = unsafe {
                CryptSignAndEncodeCertificate(
                    key,
                    0,
                    X509_ASN_ENCODING,
                    X509_CERT_TO_BE_SIGNED,
                    (&*self.info as *const CERT_INFO).cast(),
                    &algorithm,
                    null(),
                    encoded.as_mut_ptr(),
                    &mut size,
                )
            };
            if ok != 0 && size as usize <= encoded.len() {
                encoded.truncate(size as usize);
                return Ok(encoded);
            }
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if error != windows_sys::Win32::Foundation::ERROR_MORE_DATA
                && error != windows_sys::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER
            {
                return Err(Error::new(
                    ErrorClass::Signing,
                    format!("CryptSignAndEncodeCertificate failed with Win32 error {error}"),
                ));
            }
        }
        Err(Error::new(
            ErrorClass::Signing,
            "certificate output size did not stabilize",
        ))
    }
}

pub struct CertContext(*mut CERT_CONTEXT);

impl CertContext {
    pub fn create(encoded: &[u8]) -> Result<Self> {
        // SAFETY: encoded points to a complete immutable certificate for the call.
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
        // SAFETY: context is live and its encoded buffer is valid for its reported length.
        let native = unsafe {
            std::slice::from_raw_parts((*context).pbCertEncoded, (*context).cbCertEncoded as usize)
        };
        if native != encoded {
            unsafe { CertFreeCertificateContext(context) };
            return Err(Error::new(
                ErrorClass::Validation,
                "certificate context bytes differ from input",
            ));
        }
        Ok(Self(context))
    }

    pub fn as_ptr(&self) -> *const CERT_CONTEXT {
        self.0
    }

    pub fn public_key_info(&self) -> *const CERT_PUBLIC_KEY_INFO {
        // SAFETY: self owns a live context and pCertInfo.
        unsafe { &(*(*self.0).pCertInfo).SubjectPublicKeyInfo }
    }

    pub fn subject(&self) -> Result<&[u8]> {
        // SAFETY: self owns a complete CERT_INFO graph.
        let subject = unsafe { &(*(*self.0).pCertInfo).Subject };
        checked_blob(subject, "certificate subject")
    }

    pub fn subject_key_identifier(&self) -> Result<[u8; 20]> {
        // SAFETY: self owns a complete CERT_INFO graph.
        let public = unsafe { &(*(*self.0).pCertInfo).SubjectPublicKeyInfo.PublicKey };
        hash_sha1(checked_bit_blob(public, "certificate public point")?)
    }

    pub fn validate_p256_public_blob(&self, expected: &[u8; 72]) -> Result<()> {
        let expected_point = point(expected);
        // SAFETY: self owns a live context and all nested pointers are valid for its lifetime.
        let info = unsafe { &*self.public_key_info() };
        if info.PublicKey.cUnusedBits != 0 || info.PublicKey.cbData != 65 {
            return Err(Error::new(
                ErrorClass::Validation,
                "certificate SPKI has an invalid EC point BIT STRING",
            ));
        }
        // SAFETY: cbData was checked and the context owns the pointed-to bytes.
        let actual = unsafe {
            std::slice::from_raw_parts(info.PublicKey.pbData, info.PublicKey.cbData as usize)
        };
        if actual != expected_point {
            return Err(Error::new(
                ErrorClass::Validation,
                "certificate SPKI does not match the generated key",
            ));
        }
        Ok(())
    }

    pub fn release(mut self) -> Result<()> {
        // SAFETY: this wrapper uniquely owns the certificate context.
        let ok = unsafe { CertFreeCertificateContext(self.0) };
        self.0 = null_mut();
        if ok == 0 {
            return Err(bool_error(
                ErrorClass::Cleanup,
                "CertFreeCertificateContext",
            ));
        }
        Ok(())
    }
}

impl Drop for CertContext {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: this wrapper uniquely owns the context.
            unsafe { CertFreeCertificateContext(self.0) };
        }
    }
}

pub fn verify_certificate_signature(certificate: &[u8], issuer: &CertContext) -> Result<()> {
    let slices = certificate_slices(certificate)?;
    let expected_algorithm = [
        0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
    ];
    if slices.signature_algorithm != expected_algorithm {
        return Err(Error::new(
            ErrorClass::Validation,
            "outer signature AlgorithmIdentifier is not parameterless ECDSA/SHA-256",
        ));
    }
    validate_native_signed_content(certificate, &slices)?;
    validate_native_ecc_signature(
        slices.signature_der,
        &ecdsa_der_to_raw(slices.signature_der)?,
    )?;
    let certificate_context = CertContext::create(certificate)?;
    // SAFETY: the context owns a complete decoded CERT_INFO and terminated OID string.
    let algorithm = unsafe { &(*(*certificate_context.as_ptr()).pCertInfo).SignatureAlgorithm };
    if algorithm.pszObjId.is_null()
        || algorithm.Parameters.cbData != 0
        || !algorithm.Parameters.pbData.is_null()
        || unsafe { std::ffi::CStr::from_ptr(algorithm.pszObjId.cast()) }.to_bytes()
            != &ECDSA_SHA256_OID[..ECDSA_SHA256_OID.len() - 1]
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "inner signature AlgorithmIdentifier is not parameterless ECDSA/SHA-256",
        ));
    }

    let raw = ecdsa_der_to_raw(slices.signature_der)?;
    let digest = hash_sha256(slices.tbs)?;
    let mut key = null_mut();
    // SAFETY: issuer context owns a validated CERT_PUBLIC_KEY_INFO for this synchronous import.
    let ok = unsafe {
        CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            issuer.public_key_info(),
            0,
            null(),
            &mut key,
        )
    };
    if ok == 0 {
        return Err(bool_error(
            ErrorClass::Validation,
            "CryptImportPublicKeyInfoEx2",
        ));
    }
    let key = crate::win::handles::BcryptKey(key);
    crate::win::bcrypt::verify(&key, &digest, &raw)?;
    let mut tampered = digest;
    tampered[0] ^= 1;
    // SAFETY: pointers and fixed lengths agree; failure is the required outcome.
    let status = unsafe {
        BCryptVerifySignature(
            key.0,
            null(),
            tampered.as_ptr(),
            tampered.len() as u32,
            raw.as_ptr(),
            raw.len() as u32,
            0,
        )
    };
    let verification = if status >= 0 {
        Err(Error::new(
            ErrorClass::Validation,
            "tampered certificate digest unexpectedly verified",
        ))
    } else {
        Ok(())
    };
    key.release()?;
    verification
}
struct DecodeAllocation(*mut std::ffi::c_void);

impl Drop for DecodeAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: CryptDecodeObjectEx allocated this block with LocalAlloc.
            unsafe { windows_sys::Win32::Foundation::LocalFree(self.0) };
        }
    }
}

fn decode_alloc(encoded: &[u8], structure: *const u8) -> Result<(DecodeAllocation, u32)> {
    let mut allocation: *mut std::ffi::c_void = null_mut();
    let mut size = 0_u32;
    let flags = CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NO_SIGNATURE_BYTE_REVERSAL_FLAG;
    // SAFETY: encoded is complete immutable DER and allocation is an out pointer owned on success.
    if unsafe {
        CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            structure,
            encoded.as_ptr(),
            usize_to_u32(encoded.len(), "native DER decode")?,
            flags,
            null(),
            (&mut allocation as *mut *mut std::ffi::c_void).cast(),
            &mut size,
        )
    } == 0
    {
        return Err(bool_error(ErrorClass::Validation, "CryptDecodeObjectEx"));
    }
    if allocation.is_null() || size == 0 || size as usize > 64 * 1024 {
        if !allocation.is_null() {
            unsafe { windows_sys::Win32::Foundation::LocalFree(allocation) };
        }
        return Err(Error::new(
            ErrorClass::Validation,
            "native DER decode returned an invalid allocation",
        ));
    }
    Ok((DecodeAllocation(allocation), size))
}

fn validate_native_signed_content(
    certificate: &[u8],
    slices: &crate::cert::der::CertificateSlices<'_>,
) -> Result<()> {
    let (allocation, size) = decode_alloc(certificate, X509_CERT)?;
    if (size as usize) < size_of::<CERT_SIGNED_CONTENT_INFO>()
        || (allocation.0 as usize) % align_of::<CERT_SIGNED_CONTENT_INFO>() != 0
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "X509_CERT decode is undersized or misaligned",
        ));
    }
    // SAFETY: size and alignment were checked and the allocation remains owned here.
    let decoded = unsafe { &*allocation.0.cast::<CERT_SIGNED_CONTENT_INFO>() };
    let tbs = checked_blob(&decoded.ToBeSigned, "decoded TBS")?;
    let signature = checked_bit_blob(&decoded.Signature, "decoded signature")?;
    if tbs != slices.tbs
        || signature != slices.signature_der
        || decoded.Signature.cUnusedBits != 0
        || !algorithm_is_ecdsa_sha256(&decoded.SignatureAlgorithm)
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "native X509_CERT decode disagrees with strict DER inspection",
        ));
    }
    Ok(())
}

fn validate_native_ecc_signature(signature_der: &[u8], expected: &[u8; 64]) -> Result<()> {
    let (allocation, size) = decode_alloc(signature_der, X509_ECC_SIGNATURE)?;
    if (size as usize) < size_of::<CERT_ECC_SIGNATURE>()
        || (allocation.0 as usize) % align_of::<CERT_ECC_SIGNATURE>() != 0
    {
        return Err(Error::new(
            ErrorClass::Validation,
            "X509_ECC_SIGNATURE decode is undersized or misaligned",
        ));
    }
    // SAFETY: size/alignment are checked and both nested blobs are validated before use.
    let decoded = unsafe { &*allocation.0.cast::<CERT_ECC_SIGNATURE>() };
    let mut native = [0_u8; 64];
    native_integer_to_big_endian(&decoded.r, &mut native[..32])?;
    native_integer_to_big_endian(&decoded.s, &mut native[32..])?;
    if &native != expected || crate::cert::der::raw_to_ecdsa_der(&native) != signature_der {
        return Err(Error::new(
            ErrorClass::Validation,
            "native ECDSA decode endian conversion or re-encoding disagrees",
        ));
    }
    Ok(())
}

fn native_integer_to_big_endian(blob: &CRYPT_INTEGER_BLOB, output: &mut [u8]) -> Result<()> {
    let little = checked_blob(blob, "native ECDSA integer")?;
    let significant = little
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(0, |index| index + 1);
    if significant == 0 || significant > output.len() {
        return Err(Error::new(
            ErrorClass::Validation,
            "native ECDSA integer is zero or oversized",
        ));
    }
    let start = output.len() - significant;
    for (destination, source) in output[start..]
        .iter_mut()
        .zip(little[..significant].iter().rev())
    {
        *destination = *source;
    }
    Ok(())
}

fn checked_blob<'a>(blob: &CRYPT_INTEGER_BLOB, name: &str) -> Result<&'a [u8]> {
    if blob.cbData == 0 || blob.pbData.is_null() || blob.cbData as usize > 64 * 1024 {
        return Err(Error::new(
            ErrorClass::Validation,
            format!("{name} has an invalid pointer/count"),
        ));
    }
    // SAFETY: the owning native decode/context remains live and the count is capped.
    Ok(unsafe { std::slice::from_raw_parts(blob.pbData, blob.cbData as usize) })
}

fn checked_bit_blob<'a>(blob: &CRYPT_BIT_BLOB, name: &str) -> Result<&'a [u8]> {
    checked_blob(
        &CRYPT_INTEGER_BLOB {
            cbData: blob.cbData,
            pbData: blob.pbData,
        },
        name,
    )
}

fn algorithm_is_ecdsa_sha256(algorithm: &CRYPT_ALGORITHM_IDENTIFIER) -> bool {
    !algorithm.pszObjId.is_null()
        && algorithm.Parameters.cbData == 0
        && algorithm.Parameters.pbData.is_null()
        && unsafe { std::ffi::CStr::from_ptr(algorithm.pszObjId.cast()) }.to_bytes()
            == &ECDSA_SHA256_OID[..ECDSA_SHA256_OID.len() - 1]
}

pub fn verify_leaf_possession(
    leaf: &CertContext,
    private_key: &crate::win::bcrypt::P256Key,
    challenge: &[u8],
) -> Result<()> {
    let digest = hash_sha256(challenge)?;
    let signature = private_key.sign(&digest)?;
    let mut public = null_mut();
    // SAFETY: leaf owns a validated public key info for this synchronous import.
    let ok = unsafe {
        CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING,
            leaf.public_key_info(),
            0,
            null(),
            &mut public,
        )
    };
    if ok == 0 {
        return Err(bool_error(
            ErrorClass::Validation,
            "CryptImportPublicKeyInfoEx2(leaf)",
        ));
    }

    let public = crate::win::handles::BcryptKey(public);
    let verification = crate::win::bcrypt::verify(&public, &digest, &signature);
    public.release()?;
    verification
}
pub fn validate_certificate_profiles(root: &CertContext, leaf: &CertContext) -> Result<()> {
    // SAFETY: both contexts own complete CERT_INFO graphs for their lifetimes.
    let (root_info, leaf_info) =
        unsafe { (&*(*root.as_ptr()).pCertInfo, &*(*leaf.as_ptr()).pCertInfo) };
    if root_info.dwVersion != CERT_V3 || leaf_info.dwVersion != CERT_V3 {
        return profile_error("both certificates must be X.509 v3");
    }
    let root_name = encode_name("CN=AziHSM Demo Root")?;
    let leaf_name = vec![0x30, 0x00];
    if checked_blob(&root_info.Issuer, "root issuer")? != root_name
        || checked_blob(&root_info.Subject, "root subject")? != root_name
        || checked_blob(&leaf_info.Issuer, "leaf issuer")? != root_name
        || checked_blob(&leaf_info.Subject, "leaf subject")? != leaf_name
    {
        return profile_error("certificate issuer/subject profile mismatch");
    }
    validate_serial(&root_info.SerialNumber)?;
    validate_serial(&leaf_info.SerialNumber)?;
    if checked_blob(&root_info.SerialNumber, "root serial")?
        == checked_blob(&leaf_info.SerialNumber, "leaf serial")?
    {
        return profile_error("root and leaf serial numbers must differ");
    }
    let root_not_before = filetime_value(root_info.NotBefore);
    let root_not_after = filetime_value(root_info.NotAfter);
    let leaf_not_before = filetime_value(leaf_info.NotBefore);
    let leaf_not_after = filetime_value(leaf_info.NotAfter);
    if root_not_before >= root_not_after
        || leaf_not_before >= leaf_not_after
        || leaf_not_before < root_not_before
        || leaf_not_after > root_not_after
    {
        return profile_error("certificate validity relationship is invalid");
    }
    validate_spki(&root_info.SubjectPublicKeyInfo)?;
    validate_spki(&leaf_info.SubjectPublicKeyInfo)?;
    let root_ski = hash_sha1(checked_bit_blob(
        &root_info.SubjectPublicKeyInfo.PublicKey,
        "root public point",
    )?)?;
    let leaf_ski = hash_sha1(checked_bit_blob(
        &leaf_info.SubjectPublicKeyInfo.PublicKey,
        "leaf public point",
    )?)?;
    let mut root_expected = vec![
        (
            oid(szOID_BASIC_CONSTRAINTS2),
            true,
            vec![0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00],
        ),
        (oid(szOID_KEY_USAGE), true, vec![0x03, 0x02, 0x02, 0x04]),
        (
            oid(szOID_SUBJECT_KEY_IDENTIFIER),
            false,
            der_octet(&root_ski),
        ),
    ];
    let mut aki = vec![0x30, 0x16, 0x80, 0x14];
    aki.extend_from_slice(&root_ski);
    let mut leaf_expected = vec![
        (oid(szOID_BASIC_CONSTRAINTS2), true, vec![0x30, 0x00]),
        (oid(szOID_KEY_USAGE), true, vec![0x03, 0x02, 0x07, 0x80]),
        (
            oid(szOID_SUBJECT_KEY_IDENTIFIER),
            false,
            der_octet(&leaf_ski),
        ),
        (oid(szOID_AUTHORITY_KEY_IDENTIFIER2), false, aki),
        (
            oid(szOID_SUBJECT_ALT_NAME2),
            true,
            checked_extension_value(leaf_info, szOID_SUBJECT_ALT_NAME2)?,
        ),
        (
            oid(szOID_ENHANCED_KEY_USAGE),
            false,
            vec![
                0x30, 0x0a, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
            ],
        ),
    ];
    root_expected.sort_by(|left, right| left.0.cmp(&right.0));
    leaf_expected.sort_by(|left, right| left.0.cmp(&right.0));
    if native_extensions(root_info)? != root_expected
        || native_extensions(leaf_info)? != leaf_expected
    {
        return profile_error("certificate extension profile or duplicate set is invalid");
    }
    Ok(())
}

fn validate_serial(serial: &CRYPT_INTEGER_BLOB) -> Result<()> {
    let bytes = checked_blob(serial, "certificate serial")?;
    if bytes.len() != 16 || bytes.iter().all(|byte| *byte == 0) || bytes[15] & 0x80 != 0 {
        return profile_error("certificate serial must be distinct positive nonzero 16-byte value");
    }
    Ok(())
}

fn validate_spki(info: &CERT_PUBLIC_KEY_INFO) -> Result<()> {
    if info.Algorithm.pszObjId.is_null()
        || oid(info.Algorithm.pszObjId) != oid(crate::policy::EC_PUBLIC_KEY_OID.as_ptr())
        || checked_blob(&info.Algorithm.Parameters, "curve parameters")?
            != [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]
        || info.PublicKey.cUnusedBits != 0
    {
        return profile_error("certificate SPKI algorithm, curve, or BIT STRING is invalid");
    }
    let point = checked_bit_blob(&info.PublicKey, "SPKI point")?;
    if point.len() != 65
        || point[0] != 4
        || point[1..33].iter().all(|byte| *byte == 0)
        || point[33..].iter().all(|byte| *byte == 0)
    {
        return profile_error("certificate SPKI point is invalid");
    }
    Ok(())
}

fn native_extensions(info: &CERT_INFO) -> Result<Vec<(String, bool, Vec<u8>)>> {
    if info.cExtension == 0 || info.rgExtension.is_null() || info.cExtension > 32 {
        return profile_error("certificate extension pointer/count is invalid");
    }

    let extensions =
        unsafe { std::slice::from_raw_parts(info.rgExtension, info.cExtension as usize) };
    let mut output = Vec::with_capacity(extensions.len());
    for extension in extensions {
        if extension.pszObjId.is_null() {
            return profile_error("certificate extension OID is null");
        }

        output.push((
            oid(extension.pszObjId),
            extension.fCritical != 0,
            checked_blob(&extension.Value, "certificate extension")?.to_vec(),
        ));
    }
    output.sort_by(|left, right| left.0.cmp(&right.0));
    if output.windows(2).any(|pair| pair[0].0 == pair[1].0) {
        return profile_error("certificate contains a duplicate extension OID");
    }
    Ok(output)
}

fn checked_extension_value(info: &CERT_INFO, wanted: *const u8) -> Result<Vec<u8>> {
    if info.cExtension == 0 || info.rgExtension.is_null() || info.cExtension > 32 {
        return profile_error("certificate extension pointer/count is invalid");
    }
    let wanted = oid(wanted);
    let extensions =
        unsafe { std::slice::from_raw_parts(info.rgExtension, info.cExtension as usize) };
    let matches: Vec<&CERT_EXTENSION> = extensions
        .iter()
        .filter(|extension| !extension.pszObjId.is_null() && oid(extension.pszObjId) == wanted)
        .collect();
    if matches.len() != 1 {
        return profile_error("required certificate extension is missing or duplicated");
    }
    Ok(checked_blob(&matches[0].Value, "certificate extension")?.to_vec())
}

fn oid(pointer: *const u8) -> String {
    // SAFETY: callers supply generated or native decoded NUL-terminated OID pointers.
    unsafe { std::ffi::CStr::from_ptr(pointer.cast()) }
        .to_string_lossy()
        .into_owned()
}

fn filetime_value(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

fn profile_error<T>(message: &str) -> Result<T> {
    Err(Error::new(ErrorClass::Validation, message))
}

pub fn verify_exclusive_chain(
    root: &CertContext,
    leaf: &CertContext,
    root_bytes: &[u8],
    leaf_bytes: &[u8],
) -> Result<()> {
    // SAFETY: memory provider sentinel and null optional values are documented.
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
    // SAFETY: store and root context are live.
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
    // SAFETY: config and output pointers are valid.
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
    // SAFETY: engine, leaf, parameters, and output remain valid for the call.
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
    // SAFETY: chain is live and the API guarantees nested arrays for their reported counts.
    let valid = unsafe {
        let context = &*chain;
        if context.TrustStatus.dwErrorStatus != 0 || context.cChain != 1 {
            false
        } else {
            let simple = &**context.rgpChain;
            if simple.TrustStatus.dwErrorStatus != 0 || simple.cElement != 2 {
                false
            } else {
                (0..2).all(|index| {
                    let element = &**simple.rgpElement.add(index);
                    if element.TrustStatus.dwErrorStatus != 0 {
                        return false;
                    }
                    let native = &*element.pCertContext;
                    let bytes = std::slice::from_raw_parts(
                        native.pbCertEncoded,
                        native.cbCertEncoded as usize,
                    );
                    bytes == if index == 0 { leaf_bytes } else { root_bytes }
                })
            }
        }
    };
    // SAFETY: free order is chain, engine, then exclusive root store.
    unsafe {
        CertFreeCertificateChain(chain);
        CertFreeCertificateChainEngine(engine);
        CertCloseStore(store, 0);
    }
    if !valid {
        return Err(Error::new(
            ErrorClass::Validation,
            "exclusive certificate chain did not contain one clean two-element chain",
        ));
    }
    Ok(())
}

fn encode_name(name: &str) -> Result<Vec<u8>> {
    let wide: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut size = 0_u32;
    // SAFETY: name is stable terminated UTF-16 and null output is the documented sizing call.
    let ok = unsafe {
        CertStrToNameW(
            X509_ASN_ENCODING,
            wide.as_ptr(),
            CERT_X500_NAME_STR,
            null(),
            null_mut(),
            &mut size,
            null_mut(),
        )
    };
    if ok == 0 || size == 0 || size as usize > MAX_NAME {
        return Err(bool_error(ErrorClass::Signing, "CertStrToNameW(size)"));
    }
    let mut output = vec![0_u8; size as usize];
    // SAFETY: output is writable for the queried size and other pointers remain stable.
    let ok = unsafe {
        CertStrToNameW(
            X509_ASN_ENCODING,
            wide.as_ptr(),
            CERT_X500_NAME_STR,
            null(),
            output.as_mut_ptr(),
            &mut size,
            null_mut(),
        )
    };
    if ok == 0 || size as usize > output.len() {
        return Err(bool_error(ErrorClass::Signing, "CertStrToNameW"));
    }
    output.truncate(size as usize);
    Ok(output)
}

fn signature_algorithm() -> CRYPT_ALGORITHM_IDENTIFIER {
    CRYPT_ALGORITHM_IDENTIFIER {
        pszObjId: ECDSA_SHA256_OID.as_ptr().cast_mut(),
        Parameters: CRYPT_INTEGER_BLOB::default(),
    }
}

fn point(blob: &[u8; 72]) -> [u8; 65] {
    let mut point = [0_u8; 65];
    point[0] = 4;
    point[1..].copy_from_slice(&blob[8..]);
    point
}

pub fn spki_der_from_blob(blob: &[u8; 72]) -> Vec<u8> {
    let point = point(blob);
    let algorithm = [
        0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86,
        0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
    ];
    let mut body = Vec::with_capacity(algorithm.len() + 68);
    body.extend_from_slice(&algorithm);
    body.push(0x03);
    body.push(66);
    body.push(0);
    body.extend_from_slice(&point);
    wrap_der(0x30, &body)
}

fn blob(bytes: &[u8]) -> Result<CRYPT_INTEGER_BLOB> {
    Ok(CRYPT_INTEGER_BLOB {
        cbData: usize_to_u32(bytes.len(), "native blob")?,
        pbData: bytes.as_ptr().cast_mut(),
    })
}

fn filetime(time: SystemTime) -> Result<FILETIME> {
    let unix = time
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::new(ErrorClass::Signing, "time precedes Unix epoch"))?;
    let ticks = (unix.as_secs() + WINDOWS_EPOCH_SECONDS)
        .checked_mul(10_000_000)
        .and_then(|value| value.checked_add(u64::from(unix.subsec_nanos() / 100)))
        .ok_or_else(|| Error::new(ErrorClass::Signing, "FILETIME overflow"))?;
    Ok(FILETIME {
        dwLowDateTime: ticks as u32,
        dwHighDateTime: (ticks >> 32) as u32,
    })
}

struct ExtensionValue {
    oid: *const u8,
    critical: bool,
    bytes: Vec<u8>,
}

fn extension(oid: *const u8, critical: bool, bytes: Vec<u8>) -> ExtensionValue {
    ExtensionValue {
        oid,
        critical,
        bytes,
    }
}

fn der_octet(bytes: &[u8]) -> Vec<u8> {
    let mut output = vec![0x04, bytes.len() as u8];
    output.extend_from_slice(bytes);
    output
}

fn general_names(dns_sans: &[String], ip_sans: &[std::net::IpAddr]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for name in dns_sans {
        body.push(0x82);
        append_der_length(&mut body, name.len())?;
        body.extend_from_slice(name.as_bytes());
    }
    for address in ip_sans {
        let bytes: Vec<u8> = match address {
            std::net::IpAddr::V4(value) => value.octets().to_vec(),
            std::net::IpAddr::V6(value) => value.octets().to_vec(),
        };
        body.push(0x87);
        append_der_length(&mut body, bytes.len())?;
        body.extend_from_slice(&bytes);
    }
    Ok(wrap_der(0x30, &body))
}

fn wrap_der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(body.len() + 5);
    output.push(tag);
    if append_der_length(&mut output, body.len()).is_err() {
        return Vec::new();
    }
    output.extend_from_slice(body);
    output
}

fn append_der_length(output: &mut Vec<u8>, length: usize) -> Result<()> {
    if length < 128 {
        output.push(length as u8);
        return Ok(());
    }
    let bytes = length.to_be_bytes();
    let first = bytes
        .iter()
        .position(|byte| *byte != 0)
        .ok_or_else(|| Error::new(ErrorClass::Validation, "invalid DER length"))?;
    let count = bytes.len() - first;
    if count > 4 {
        return Err(Error::new(
            ErrorClass::Validation,
            "DER length exceeds policy",
        ));
    }
    output.push(0x80 | count as u8);
    output.extend_from_slice(&bytes[first..]);
    Ok(())
}
