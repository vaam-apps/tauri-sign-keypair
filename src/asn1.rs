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

#[cfg(test)]
mod tests {
    use super::*;

    /// **Provenance.** These are genuine P-256 signatures from
    /// `openssl dgst -sha256 -sign`, chosen to hit the shapes that occur only
    /// ~1 time in 256. Each expected P1363 value was computed independently,
    /// re-encoded to DER, and confirmed with `openssl dgst -sha256 -verify`
    /// against the real public key — so the expectations are anchored to a
    /// third-party implementation, not to this codec's own output.
    ///
    /// They are the **same vectors** the Kotlin and Swift suites use, which is
    /// what cross-validates the three implementations against one another
    /// rather than each against itself.
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn to_hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// r's magnitude is 31 bytes, so P1363 must LEFT-pad it. The ~1-in-256 case.
    #[test]
    fn real_signature_with_short_r_is_left_padded() {
        let der = hex(
            "3043021f2952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2d\
             f02207d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93",
        );
        let out = der_to_p1363(&der).unwrap();
        assert_eq!(
            to_hex(&out),
            "002952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2df\
             7d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93"
                .replace(['\n', ' '], "")
        );
        assert_eq!(out.len(), P1363_LENGTH);
        assert_eq!(out[0], 0x00, "the pad byte must be at the FRONT of r");
    }

    /// Both components high-bit: DER carries a 0x00 sign byte on each, and
    /// neither may survive into P1363.
    #[test]
    fn real_signature_with_both_high_bit_strips_both_sign_bytes() {
        let der = hex(
            "30460221008ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90\
             022100bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6",
        );
        let out = der_to_p1363(&der).unwrap();
        assert_eq!(out.len(), P1363_LENGTH);
        assert_eq!(out[0], 0x8f, "DER sign byte must not survive into r");
        assert_eq!(out[32], 0xbd, "DER sign byte must not survive into s");
    }

    #[test]
    fn tiny_integers_are_padded_on_the_left() {
        let out = der_to_p1363(&hex("3006020101020102")).unwrap();
        assert_eq!(out.len(), P1363_LENGTH);
        assert_eq!(&out[0..31], &[0u8; 31]);
        assert_eq!(out[31], 1);
        assert_eq!(&out[32..63], &[0u8; 31]);
        assert_eq!(out[63], 2);
    }

    #[test]
    fn accepts_the_long_form_sequence_length() {
        let mut body = vec![0x02, 32];
        body.extend_from_slice(&[0x11; 32]);
        body.push(0x02);
        body.push(32);
        body.extend_from_slice(&[0x22; 32]);
        let mut der = vec![0x30, 0x81, body.len() as u8];
        der.extend_from_slice(&body);

        let out = der_to_p1363(&der).unwrap();
        assert_eq!(&out[0..32], &[0x11; 32]);
        assert_eq!(&out[32..64], &[0x22; 32]);
    }

    #[test]
    fn output_is_always_exactly_64_bytes() {
        for input in [
            "3043021f2952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2d\
             f02207d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93",
            "3006020101020102",
            "3006020100020101",
        ] {
            let der = hex(&input.replace(['\n', ' '], ""));
            assert_eq!(der_to_p1363(&der).unwrap().len(), P1363_LENGTH, "{input}");
        }
    }

    /// Must fail cleanly rather than panic on a slice index. Every bound is
    /// checked before the read, so these return `Err` instead of aborting.
    #[test]
    fn malformed_inputs_are_rejected() {
        let cases = [
            ("", "empty buffer"),
            ("30", "SEQUENCE tag with no length"),
            ("3006", "length with no body"),
            ("30060201", "SEQUENCE length disagrees with the buffer"),
            ("3106020101020102", "wrong outer tag (SET, not SEQUENCE)"),
            ("3006030101020102", "wrong inner tag (BIT STRING)"),
            ("3008020101020102", "declared length overruns the buffer"),
            ("3004020101020102", "declared length undershoots the buffer"),
            ("3006022001020102", "INTEGER length overruns the buffer"),
            ("300602810102010201", "long-form INTEGER length"),
            ("3006020001020102", "zero-length INTEGER"),
            // Parses as r = 0, s = 0 without the explicit check — 64 zero bytes
            // accepted as a signature. `openssl asn1parse` says "BAD INTEGER".
            ("300402000200", "both INTEGERs zero-length"),
            // Silently ignoring these makes the encoding malleable: two distinct
            // byte strings, one signature.
            ("3009020101020102aabbcc", "trailing bytes after s"),
        ];
        for (input, why) in cases {
            assert!(
                der_to_p1363(&hex(input)).is_err(),
                "expected a rejection for {why}"
            );
        }
    }
}
