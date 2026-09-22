//! The wire vocabulary, shared with Kotlin, Swift and TypeScript.
//!
//! The Tauri IPC can only carry JSON, so these cross as strings — but each
//! string is written in exactly one place (the `serde` rename below) and parsed
//! in exactly one place. Every comparison in the rest of the crate is on the
//! enum, so adding a member is a compile error at each exhaustive `match`
//! rather than a silent fallthrough.
//!
//! These must stay in step with `android/.../Wire.kt`,
//! `ios/Sources/SignKeypairPlugin/Wire.swift` and `guest-js/index.ts`.
//! `tests/wire_contract.rs` pins the exact strings so a rename on one side
//! cannot drift past review.

use serde::{Deserialize, Serialize};

/// Where the private key actually lives, in decreasing order of assurance.
///
/// Reported by the platform, never assumed by the caller. [`KeyBacking::Software`]
/// is the floor, and the one value that means the raw private scalar is
/// reachable from process memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyBacking {
    /// Android StrongBox — a discrete, tamper-resistant security chip.
    #[serde(rename = "strongbox")]
    StrongBox,
    /// Apple Secure Enclave — a separate coprocessor. P-256 only, which is
    /// exactly the curve this plugin signs with.
    #[serde(rename = "secure_enclave")]
    SecureEnclave,
    /// Android Trusted Execution Environment — key material held by secure-world
    /// firmware, outside the Android OS.
    #[serde(rename = "tee")]
    TrustedExecutionEnvironment,
    /// Apple Keychain with a hardware-protected item, but not the Secure Enclave
    /// itself (a simulator, or an Intel Mac with no T2).
    #[serde(rename = "keychain")]
    Keychain,
    /// In-process key. The private scalar exists in heap memory and is
    /// extractable. Desktop, and any target with no native signer.
    #[serde(rename = "software")]
    Software,
}

impl KeyBacking {
    /// Map a wire tag onto a backing level.
    ///
    /// An unrecognised tag becomes [`KeyBacking::Software`]. That direction is
    /// deliberate and load-bearing: **under-reporting strength is safe,
    /// over-reporting is a false security claim.** A newer native build that
    /// reports a backing this Rust side has never heard of must not be counted
    /// as hardware on the strength of a string nobody validated.
    pub fn from_wire(wire: &str) -> Self {
        match wire {
            "strongbox" => Self::StrongBox,
            "secure_enclave" => Self::SecureEnclave,
            "tee" => Self::TrustedExecutionEnvironment,
            "keychain" => Self::Keychain,
            _ => Self::Software,
        }
    }

    /// The tag this backing crosses the wire as.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::StrongBox => "strongbox",
            Self::SecureEnclave => "secure_enclave",
            Self::TrustedExecutionEnvironment => "tee",
            Self::Keychain => "keychain",
            Self::Software => "software",
        }
    }

    /// True when the private key cannot be read out of the device.
    ///
    /// [`KeyBacking::Keychain`] is deliberately excluded: a keychain item is
    /// protected by the OS, but it is not held by a secure element and the
    /// scalar can in principle be exported.
    ///
    /// Written as an exhaustive `match` with no `_` arm on purpose. This is the
    /// one function in the crate where getting a new backing level wrong is a
    /// false security claim, so adding a variant above must fail to compile here
    /// until somebody decides which side of the line it falls on.
    pub fn is_hardware_backed(self) -> bool {
        match self {
            Self::StrongBox | Self::SecureEnclave | Self::TrustedExecutionEnvironment => true,
            Self::Keychain | Self::Software => false,
        }
    }
}

/// What the secure element demands before it will sign with a key.
///
/// The plugin splits one device credential into two keys because a single key
/// serves two populations of request with opposite requirements: a background
/// interceptor needs to sign silently, with no prompt displayable at all, while
/// a deliberate high-value action wants a prompt and can afford one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum KeyProtection {
    /// No user-presence binding. Never prompts. The key on the hot path.
    #[default]
    #[serde(rename = "ambient")]
    Ambient,
    /// Bound to a live biometric or the device credential. Prompts on every use.
    #[serde(rename = "user_present")]
    UserPresent,
}

impl KeyProtection {
    /// Parse a wire tag, or `None` when it is not one this build knows.
    ///
    /// **No default, unlike [`KeyBacking::from_wire`]** — and that asymmetry is
    /// the point. `KeyBacking` can degrade to software because under-reporting
    /// strength is harmless. Here *both* directions are harmful: guessing
    /// `Ambient` hands a caller who asked for prompted protection a key that
    /// signs silently, and guessing `UserPresent` makes a background signer
    /// prompt on every poll. An unrecognised tag is a version-pairing bug, so it
    /// fails loudly instead of being answered for.
    pub fn from_wire(wire: &str) -> Option<Self> {
        match wire {
            "ambient" => Some(Self::Ambient),
            "user_present" => Some(Self::UserPresent),
            _ => None,
        }
    }

    /// The tag this protection crosses the wire as.
    pub fn as_wire(self) -> &'static str {
        match self {
            Self::Ambient => "ambient",
            Self::UserPresent => "user_present",
        }
    }

    /// Whether the secure element will demand authentication before signing.
    pub fn requires_user_presence(self) -> bool {
        match self {
            Self::Ambient => false,
            Self::UserPresent => true,
        }
    }
}

/// An EC P-256 public key in JWK form (RFC 7517 / RFC 7518 §6.2).
///
/// `x` and `y` are base64url-encoded without padding, as the spec requires.
/// Field order matches RFC 7638's canonical form so the serialized value can be
/// thumbprinted directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcPublicJwk {
    /// Always `"P-256"`.
    pub crv: String,
    /// Always `"EC"`.
    pub kty: String,
    /// base64url, unpadded, X coordinate.
    pub x: String,
    /// base64url, unpadded, Y coordinate.
    pub y: String,
}

impl EcPublicJwk {
    /// Build a JWK from base64url coordinate strings as a native side reports them.
    pub fn new(x: impl Into<String>, y: impl Into<String>) -> Self {
        Self {
            crv: "P-256".into(),
            kty: "EC".into(),
            x: x.into(),
            y: y.into(),
        }
    }
}

/// A handle to a key held by the platform.
///
/// Deliberately does **not** carry private key material — on the hardware paths
/// there is none to carry, and the fallback keeps its scalar inside the signer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureKey {
    /// Stable identifier used to address this key on later `sign`/`delete` calls.
    pub key_id: String,
    /// The public half, ready to send to a backend for device registration.
    pub public_key: EcPublicJwk,
    /// Where the private half actually lives, as reported by the platform.
    pub backing: KeyBacking,
    /// Convenience mirror of [`KeyBacking::is_hardware_backed`], carried on the
    /// wire so a JS caller need not re-implement the classification.
    pub hardware_backed: bool,
}

impl SecureKey {
    /// Assemble a handle from the pieces a platform reports.
    pub fn new(key_id: impl Into<String>, jwk: EcPublicJwk, backing: KeyBacking) -> Self {
        Self {
            key_id: key_id.into(),
            public_key: jwk,
            backing,
            hardware_backed: backing.is_hardware_backed(),
        }
    }
}

/// What the current platform can actually do, probed at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignerCapabilities {
    /// Human-readable platform tag: `android`, `ios`, `rust-software`, `web`.
    pub platform: String,
    /// The strongest [`KeyBacking`] a `generate_key` call would produce now.
    pub best_available_backing: KeyBacking,
    /// Whether a key generated now would be non-extractable.
    pub hardware_backed: bool,
}

impl SignerCapabilities {
    /// Assemble capabilities, deriving `hardware_backed` rather than taking it.
    pub fn new(platform: impl Into<String>, backing: KeyBacking) -> Self {
        Self {
            platform: platform.into(),
            best_available_backing: backing,
            hardware_backed: backing.is_hardware_backed(),
        }
    }
}
