//! Why a signer operation failed.
//!
//! Same wire↔enum discipline as [`crate::KeyBacking`]: the string exists only on
//! the IPC, and callers match on the enum. The error *serializes* as
//! `{"code": "...", "message": "..."}` rather than as a bare string, because a
//! frontend that cannot tell "the user cancelled the prompt" from "this key was
//! destroyed by a biometric re-enrolment" will handle both wrongly — the first
//! needs nothing done, the second needs a fresh key registered.

use serde::{Serialize, Serializer};

/// Machine-readable reason a call failed. Match on this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerErrorCode {
    /// No key exists under the requested id.
    KeyNotFound,
    /// A key already exists under that id and `overwrite` was not set.
    KeyAlreadyExists,
    /// Hardware backing was required but the device cannot provide it.
    HardwareUnavailable,
    /// The platform keystore refused the operation.
    KeystoreFailure,
    /// A user-present key was requested or used, but the device has no biometric
    /// enrolled and no device credential (screen lock) set.
    ///
    /// Distinct from [`Self::HardwareUnavailable`]: the secure element is present
    /// and willing, there is simply nothing to authenticate the user *against*.
    /// It is also recoverable by the user in Settings, which hardware absence is
    /// not — so the two must not share a code, or the UI cannot say anything
    /// useful.
    UserAuthenticationRequired,
    /// The user dismissed the authentication prompt, or it timed out.
    ///
    /// Not a failure of the key or the device. Callers should treat it as a
    /// cancelled action, never as a reason to re-enrol or log out.
    UserAuthenticationCancelled,
    /// The key was permanently destroyed by a change to the device's biometric
    /// enrolment or screen lock.
    ///
    /// Recovery is to generate a fresh user-present key and register its
    /// thumbprint — not a full re-enrolment ceremony, and not a logout.
    KeyInvalidated,
    /// This platform has no native implementation of the requested operation.
    UnsupportedPlatform,
    /// A code this build does not know — a newer native side, or a failure
    /// raised by something other than this plugin. The raw string is preserved
    /// on [`Error::raw_code`].
    Unknown,
}

impl SignerErrorCode {
    /// The tag this code crosses the wire as.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::KeyNotFound => "key_not_found",
            Self::KeyAlreadyExists => "key_already_exists",
            Self::HardwareUnavailable => "hardware_unavailable",
            Self::KeystoreFailure => "keystore_failure",
            Self::UserAuthenticationRequired => "user_authentication_required",
            Self::UserAuthenticationCancelled => "user_authentication_cancelled",
            Self::KeyInvalidated => "key_invalidated",
            Self::UnsupportedPlatform => "unsupported_platform",
            Self::Unknown => "unknown",
        }
    }

    /// Map a wire code onto an enum member, defaulting to [`Self::Unknown`].
    ///
    /// Unlike a backing tag there is no assurance claim to get wrong here, so a
    /// default is safe — what matters is that the unrecognised string survives
    /// on [`Error::raw_code`] instead of being flattened into a generic failure.
    pub fn from_wire(wire: &str) -> Self {
        match wire {
            "key_not_found" => Self::KeyNotFound,
            "key_already_exists" => Self::KeyAlreadyExists,
            "hardware_unavailable" => Self::HardwareUnavailable,
            "keystore_failure" => Self::KeystoreFailure,
            "user_authentication_required" => Self::UserAuthenticationRequired,
            "user_authentication_cancelled" => Self::UserAuthenticationCancelled,
            "key_invalidated" => Self::KeyInvalidated,
            "unsupported_platform" => Self::UnsupportedPlatform,
            _ => Self::Unknown,
        }
    }
}

/// Raised when the platform cannot satisfy a request.
#[derive(Debug, Clone)]
pub struct Error {
    /// Machine-readable reason. Match on this.
    pub code: SignerErrorCode,
    /// The code exactly as the platform sent it.
    ///
    /// Equal to `code.as_wire()` for everything this crate understands, and the
    /// raw unrecognised string when [`Self::code`] is [`SignerErrorCode::Unknown`]
    /// — so an unfamiliar failure stays diagnosable.
    pub raw_code: String,
    /// Human-readable explanation, safe to log — never contains key material.
    pub message: String,
}

impl Error {
    /// Build an error from a code this build knows.
    pub fn new(code: SignerErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            raw_code: code.as_wire().to_string(),
            message: message.into(),
        }
    }

    /// Build from whatever a native side put on the wire, preserving the raw tag.
    pub fn from_wire(wire: Option<&str>, message: impl Into<String>) -> Self {
        let raw = wire.unwrap_or(SignerErrorCode::Unknown.as_wire());
        Self {
            code: SignerErrorCode::from_wire(raw),
            raw_code: raw.to_string(),
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.raw_code, self.message)
    }
}

impl std::error::Error for Error {}

/// Serialized as an object, not a string: the frontend needs the code.
impl Serialize for Error {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("SignKeypairError", 2)?;
        state.serialize_field("code", &self.raw_code)?;
        state.serialize_field("message", &self.message)?;
        state.end()
    }
}

/// Convenience alias for the crate's fallible operations.
pub type Result<T> = std::result::Result<T, Error>;
