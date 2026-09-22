//! base64url without padding, as RFC 7515 requires everywhere in this crate.
//!
//! One module rather than a call to `URL_SAFE_NO_PAD` scattered about, because
//! a single `URL_SAFE` (padded) slipping in would produce a JWK whose
//! thumbprint does not match the one the same key produced elsewhere.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;

use crate::error::{Error, SignerErrorCode};

/// Encode bytes as unpadded base64url.
pub fn encode(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode unpadded base64url, tolerating padding a caller may have added.
pub fn decode(value: &str) -> crate::Result<Vec<u8>> {
    let trimmed = value.trim_end_matches('=');
    URL_SAFE_NO_PAD.decode(trimmed).map_err(|e| {
        Error::new(
            SignerErrorCode::KeystoreFailure,
            format!("Argument is not valid base64url: {e}"),
        )
    })
}
