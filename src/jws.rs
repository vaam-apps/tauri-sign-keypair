//! Compact JWS assembly for Rust callers.
//!
//! The frontend does this in TypeScript (`guest-js/index.ts`) so that the web
//! fallback and the Tauri path share one code path and cannot disagree about
//! how a payload is serialized. This module is the same thing for code running
//! on the Rust side of a Tauri app — a command of your own that needs a signed
//! request, say — and is deliberately *not* exposed as an IPC command: routing
//! a JSON value through Rust's serializer and back would let the bytes signed
//! differ from the bytes the frontend believes it asked for.

use crate::b64;

/// The fixed JWS protected header for ES256, pre-encoded.
///
/// A verifier expects exactly `{"alg":"ES256","typ":"JWT"}`; key order is part
/// of the encoded bytes, so this is a literal rather than a serialized map.
pub const PROTECTED_HEADER_JSON: &str = r#"{"alg":"ES256","typ":"JWT"}"#;

/// `base64url(header).base64url(payload)` — the exact bytes that get signed.
///
/// [`payload_json`] must already be the caller's chosen serialization. It is
/// taken as a string rather than a `serde_json::Value` on purpose: re-encoding
/// a map here would reorder its keys, and a payload whose key order changes
/// between the caller's view and the signature is a bug that only shows up as
/// an unexplained verification failure on the server.
pub fn signing_input(payload_json: &str) -> String {
    format!(
        "{}.{}",
        b64::encode(PROTECTED_HEADER_JSON),
        b64::encode(payload_json)
    )
}

/// Glue a 64-byte IEEE P1363 signature onto its signing input.
pub fn compact(signing_input: &str, signature: &[u8]) -> String {
    format!("{}.{}", signing_input, b64::encode(signature))
}
