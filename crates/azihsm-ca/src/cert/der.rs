//! Minimal strict DER reader used before native certificate decoding.

use crate::error::{Error, ErrorClass, Result};

#[derive(Debug, Clone, Copy)]
pub struct CertificateSlices<'a> {
    pub tbs: &'a [u8],
    pub signature_algorithm: &'a [u8],
    pub signature_der: &'a [u8],
}

pub fn certificate_slices(input: &[u8]) -> Result<CertificateSlices<'_>> {
    validate_complete_der(input, 0)?;
    let (outer, end) = tlv(input, 0, 0x30)?;
    if end != input.len() {
        return invalid("trailing certificate data");
    }
    let base = input.len() - outer.len();
    let (_, tbs_end) = tlv(input, base, 0x30)?;
    let (_, alg_end) = tlv(input, tbs_end, 0x30)?;
    let (bits, bits_end) = tlv(input, alg_end, 0x03)?;
    if bits_end != input.len() || bits.first() != Some(&0) {
        return invalid("invalid certificate signature BIT STRING");
    }
    Ok(CertificateSlices {
        tbs: &input[base..tbs_end],
        signature_algorithm: &input[tbs_end..alg_end],
        signature_der: &bits[1..],
    })
}

pub fn ecdsa_der_to_raw(input: &[u8]) -> Result<[u8; 64]> {
    validate_complete_der(input, 0)?;
    let (sequence, end) = tlv(input, 0, 0x30)?;
    if end != input.len() {
        return invalid("trailing ECDSA signature data");
    }
    let offset = input.len() - sequence.len();
    let (r, r_end) = tlv(input, offset, 0x02)?;
    let (s, s_end) = tlv(input, r_end, 0x02)?;
    if s_end != input.len() {
        return invalid("ECDSA signature must contain exactly two integers");
    }
    let mut raw = [0_u8; 64];
    normalize_integer(r, &mut raw[..32])?;
    normalize_integer(s, &mut raw[32..])?;
    if raw_to_ecdsa_der(&raw) != input {
        return invalid("ECDSA signature does not round-trip canonically");
    }
    Ok(raw)
}

pub fn raw_to_ecdsa_der(raw: &[u8; 64]) -> Vec<u8> {
    let r = encode_integer(&raw[..32]);
    let s = encode_integer(&raw[32..]);
    let mut output = Vec::with_capacity(2 + r.len() + s.len());
    output.push(0x30);
    output.push((r.len() + s.len()) as u8);
    output.extend(r);
    output.extend(s);
    output
}

fn encode_integer(value: &[u8]) -> Vec<u8> {
    let first = value
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(value.len() - 1);
    let significant = &value[first..];
    let padded = significant[0] & 0x80 != 0;
    let mut output = Vec::with_capacity(2 + usize::from(padded) + significant.len());
    output.push(0x02);
    output.push((significant.len() + usize::from(padded)) as u8);
    if padded {
        output.push(0);
    }
    output.extend_from_slice(significant);
    output
}

fn validate_complete_der(input: &[u8], depth: usize) -> Result<()> {
    if depth > 16 {
        return invalid("DER nesting exceeds policy depth");
    }
    let mut offset = 0;
    while offset < input.len() {
        let tag = input[offset];
        if tag & 0x1f == 0x1f {
            return invalid("high-tag-number DER is not accepted");
        }
        let (value, end) = tlv(input, offset, tag)?;
        if tag & 0x20 != 0 {
            validate_complete_der(value, depth + 1)?;
        }
        offset = end;
    }
    if offset != input.len() {
        return invalid("DER object has trailing data");
    }
    Ok(())
}

fn normalize_integer(integer: &[u8], output: &mut [u8]) -> Result<()> {
    if integer.is_empty() || integer[0] & 0x80 != 0 {
        return invalid("ECDSA integer is empty or negative");
    }
    let significant = if integer.len() > 1 && integer[0] == 0 {
        if integer[1] & 0x80 == 0 {
            return invalid("ECDSA integer has redundant sign padding");
        }
        &integer[1..]
    } else {
        integer
    };
    if significant.len() > output.len() || significant.iter().all(|byte| *byte == 0) {
        return invalid("ECDSA integer is zero or oversized");
    }
    let start = output.len() - significant.len();
    output[start..].copy_from_slice(significant);
    Ok(())
}

fn tlv(input: &[u8], offset: usize, expected_tag: u8) -> Result<(&[u8], usize)> {
    let tag = *input
        .get(offset)
        .ok_or_else(|| der_error("missing DER tag"))?;
    if tag != expected_tag || tag & 0x1f == 0x1f {
        return invalid("unexpected DER tag");
    }
    let first = *input
        .get(offset + 1)
        .ok_or_else(|| der_error("missing DER length"))?;
    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > std::mem::size_of::<usize>() {
            return invalid("indefinite or oversized DER length");
        }
        let bytes = input
            .get(offset + 2..offset + 2 + count)
            .ok_or_else(|| der_error("truncated DER length"))?;
        if bytes[0] == 0 {
            return invalid("non-minimal DER length");
        }
        let length = bytes.iter().try_fold(0_usize, |value, byte| {
            value
                .checked_mul(256)
                .and_then(|value| value.checked_add(usize::from(*byte)))
                .ok_or_else(|| der_error("DER length overflow"))
        })?;
        if length < 128 {
            return invalid("non-minimal long-form DER length");
        }
        (length, 2 + count)
    };
    let start = offset
        .checked_add(header)
        .ok_or_else(|| der_error("DER offset overflow"))?;
    let end = start
        .checked_add(length)
        .ok_or_else(|| der_error("DER length overflow"))?;
    let value = input
        .get(start..end)
        .ok_or_else(|| der_error("truncated DER value"))?;
    Ok((value, end))
}

fn der_error(message: &str) -> Error {
    Error::new(ErrorClass::Validation, message)
}

fn invalid<T>(message: &str) -> Result<T> {
    Err(der_error(message))
}
