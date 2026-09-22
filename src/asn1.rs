//! ASN.1 DER → IEEE P1363 conversion for P-256 ECDSA signatures.
//!
//! `SecKeyCreateSignature` emits **ASN.1 DER** `SEQUENCE { INTEGER r, INTEGER s }`.
//! JWS ES256 (RFC 7515 §3.4) requires **IEEE P1363** — the two integers as
//! fixed-width 32-byte big-endian values, concatenated, unwrapped.
//!
//! Getting this wrong is silent *and intermittent*. DER encodes integers
//! minimally, so a component whose top byte happens to be zero is one byte
//! shorter — roughly 1 signature in 256 per component. Code that copies the
//! magnitude without left-padding produces a signature that is valid ECDSA and
//! that a JWS verifier rejects, days or weeks after it shipped.
//!
//! This is the third implementation of the same conversion, alongside
//! `EcdsaSignatureCodec` in Kotlin and Swift, and it is driven by the **same**
//! known-answer vectors — which is what cross-validates the three against each
//! other rather than each against itself.

use crate::error::{Error, SignerErrorCode};

/// Byte width of one P-256 coordinate.
pub const COORDINATE_LENGTH: usize = 32;

/// Total length of a P-256 P1363 signature.
pub const P1363_LENGTH: usize = COORDINATE_LENGTH * 2;

fn malformed(what: impl Into<String>) -> Error {
    Error::new(SignerErrorCode::KeystoreFailure, what.into())
}

/// Read one byte, bounds-checked before the read.
fn read_byte(der: &[u8], offset: &mut usize, what: &str) -> crate::Result<u8> {
    let byte = der
        .get(*offset)
        .copied()
        .ok_or_else(|| malformed(format!("Truncated DER signature: expected {what}")))?;
    *offset += 1;
    Ok(byte)
}

/// Read one DER INTEGER's value bytes.
fn read_integer<'a>(der: &'a [u8], offset: &mut usize, what: &str) -> crate::Result<&'a [u8]> {
    if read_byte(der, offset, "INTEGER tag")? != 0x02 {
        return Err(malformed(format!("Expected DER INTEGER for {what}")));
    }
    let length = read_byte(der, offset, "INTEGER length")? as usize;
    if length & 0x80 != 0 {
        return Err(malformed(format!(
            "Unsupported long-form DER INTEGER for {what}"
        )));
    }
    if length == 0 {
        // Without this, `300402000200` parses as r = 0, s = 0 and yields 64 zero
        // bytes — a bogus signature accepted as valid. `openssl asn1parse`
        // reports "BAD INTEGER" for the same input.
        return Err(malformed(format!("Zero-length DER INTEGER for {what}")));
    }
    let end = offset
        .checked_add(length)
        .ok_or_else(|| malformed("DER INTEGER length overflows"))?;
    if end > der.len() {
        return Err(malformed(format!("Truncated DER INTEGER for {what}")));
    }
    let value = &der[*offset..end];
    *offset = end;
    Ok(value)
}

/// Strip DER's minimal-encoding leading zeros, then left-pad to 32 bytes.
///
/// Both halves matter: a high-bit component carries a `0x00` sign byte that must
/// NOT survive into P1363, and a short component must be padded on the LEFT —
/// right-alignment silently multiplies the value by 256^n.
fn normalise(value: &[u8]) -> crate::Result<[u8; COORDINATE_LENGTH]> {
    let mut start = 0;
    while start < value.len() - 1 && value[start] == 0 {
        start += 1;
    }
    let magnitude = &value[start..];
    if magnitude.len() > COORDINATE_LENGTH {
        return Err(malformed(format!(
            "ECDSA integer longer than {COORDINATE_LENGTH} bytes"
        )));
    }
    let mut out = [0u8; COORDINATE_LENGTH];
    out[COORDINATE_LENGTH - magnitude.len()..].copy_from_slice(magnitude);
    Ok(out)
}

/// Convert an ASN.1 DER ECDSA signature to IEEE P1363 `r‖s`.
///
/// The result is **always** exactly [`P1363_LENGTH`] bytes, or this returns an
/// error. Every bound is checked before the read, so malformed input fails
/// cleanly rather than panicking on a slice index.
pub fn der_to_p1363(der: &[u8]) -> crate::Result<Vec<u8>> {
    let mut offset = 0usize;

    if read_byte(der, &mut offset, "SEQUENCE tag")? != 0x30 {
        return Err(malformed("DER signature does not start with SEQUENCE"));
    }

    let mut sequence_length = read_byte(der, &mut offset, "SEQUENCE length")? as usize;
    if sequence_length & 0x80 != 0 {
        let octets = sequence_length & 0x7f;
        if !(1..=2).contains(&octets) {
            return Err(malformed(format!(
                "Unsupported DER length form ({octets} octets)"
            )));
        }
        sequence_length = 0;
        for _ in 0..octets {
            sequence_length = (sequence_length << 8)
                | read_byte(der, &mut offset, "SEQUENCE length octet")? as usize;
        }
    }
    if offset + sequence_length != der.len() {
        return Err(malformed("DER length mismatch"));
    }

    let r = normalise(read_integer(der, &mut offset, "r")?)?;
    let s = normalise(read_integer(der, &mut offset, "s")?)?;

    // r and s must account for the entire SEQUENCE. Without this, trailing bytes
    // are silently ignored, which makes the encoding malleable: junk can be
    // appended to produce a different byte string that decodes to the same
    // signature. `openssl asn1parse` rejects such input too.
    if offset != der.len() {
        return Err(malformed(format!(
            "{} trailing byte(s) after s",
            der.len() - offset
        )));
    }

    let mut out = Vec::with_capacity(P1363_LENGTH);
    out.extend_from_slice(&r);
    out.extend_from_slice(&s);
    Ok(out)
}
