//! The wire contract, pinned on the Rust side.
//!
//! The same vectors are asserted in `android/src/test/.../WireContractTest.kt`
//! and `darwin_tests/Tests/SignKeypairCodecTests/WireContractTests.swift`. The
//! mapping is necessarily duplicated once per language, and duplication is what
//! drifts — these tests turn a drift into a red build on the side that moved,
//! instead of a runtime failure on one platform only.

use tauri_plugin_sign_keypair::{Error, KeyBacking, KeyProtection, SignerErrorCode};

#[test]
fn backing_wire_names_are_stable() {
    assert_eq!(KeyBacking::StrongBox.as_wire(), "strongbox");
    assert_eq!(KeyBacking::SecureEnclave.as_wire(), "secure_enclave");
    assert_eq!(KeyBacking::TrustedExecutionEnvironment.as_wire(), "tee");
    assert_eq!(KeyBacking::Keychain.as_wire(), "keychain");
    assert_eq!(KeyBacking::Software.as_wire(), "software");
}

#[test]
fn every_backing_round_trips() {
    for backing in [
        KeyBacking::StrongBox,
        KeyBacking::SecureEnclave,
        KeyBacking::TrustedExecutionEnvironment,
        KeyBacking::Keychain,
        KeyBacking::Software,
    ] {
        assert_eq!(KeyBacking::from_wire(backing.as_wire()), backing);
    }
}

/// Fail-safe, and load-bearing: under-reporting strength is harmless,
/// over-reporting is a false security claim. A newer native build reporting a
/// backing this crate has never heard of must not be counted as hardware.
#[test]
fn an_unknown_backing_degrades_to_software() {
    for unknown in ["", "titan", "STRONGBOX", "secure-enclave", "hardware"] {
        assert_eq!(
            KeyBacking::from_wire(unknown),
            KeyBacking::Software,
            "unknown tag {unknown:?} must degrade, never be guessed upward"
        );
        assert!(!KeyBacking::from_wire(unknown).is_hardware_backed());
    }
}

/// The classification callers act on. `Keychain` is deliberately false: an item
/// the OS protects is not an item a secure element holds.
#[test]
fn hardware_backing_classification() {
    assert!(KeyBacking::StrongBox.is_hardware_backed());
    assert!(KeyBacking::SecureEnclave.is_hardware_backed());
    assert!(KeyBacking::TrustedExecutionEnvironment.is_hardware_backed());
    assert!(!KeyBacking::Keychain.is_hardware_backed());
    assert!(!KeyBacking::Software.is_hardware_backed());
}

#[test]
fn protection_wire_names_are_stable() {
    assert_eq!(KeyProtection::Ambient.as_wire(), "ambient");
    assert_eq!(KeyProtection::UserPresent.as_wire(), "user_present");
}

#[test]
fn every_protection_round_trips() {
    for protection in [KeyProtection::Ambient, KeyProtection::UserPresent] {
        assert_eq!(
            KeyProtection::from_wire(protection.as_wire()),
            Some(protection)
        );
    }
}

/// **No default, unlike the backing tag** — and the asymmetry is the point.
/// Guessing `Ambient` hands a caller who asked for prompted protection a key
/// that signs silently; guessing `UserPresent` makes a background signer prompt
/// on every poll. Neither is a safe direction to be wrong in.
#[test]
fn an_unknown_protection_has_no_default() {
    for unknown in ["", "elevated", "AMBIENT", "userPresent", "user-present"] {
        assert_eq!(
            KeyProtection::from_wire(unknown),
            None,
            "unknown tag {unknown:?} must fail, not be answered for"
        );
    }
}

#[test]
fn protection_presence_classification() {
    assert!(!KeyProtection::Ambient.requires_user_presence());
    assert!(KeyProtection::UserPresent.requires_user_presence());
}

#[test]
fn error_code_wire_names_are_stable() {
    let expected = [
        (SignerErrorCode::KeyNotFound, "key_not_found"),
        (SignerErrorCode::KeyAlreadyExists, "key_already_exists"),
        (SignerErrorCode::HardwareUnavailable, "hardware_unavailable"),
        (SignerErrorCode::KeystoreFailure, "keystore_failure"),
        (
            SignerErrorCode::UserAuthenticationRequired,
            "user_authentication_required",
        ),
        (
            SignerErrorCode::UserAuthenticationCancelled,
            "user_authentication_cancelled",
        ),
        (SignerErrorCode::KeyInvalidated, "key_invalidated"),
        (SignerErrorCode::UnsupportedPlatform, "unsupported_platform"),
        (SignerErrorCode::Unknown, "unknown"),
    ];
    for (code, wire) in expected {
        assert_eq!(code.as_wire(), wire);
        assert_eq!(SignerErrorCode::from_wire(wire), code);
    }
}

/// An unrecognised code becomes `Unknown` but **keeps its raw string**. Kept as
/// a distinct variant rather than folded into `KeystoreFailure` so a caller can
/// tell "the keystore refused" from "nobody here understands this", and so the
/// raw value is the thing to read in a bug report.
#[test]
fn an_unknown_error_code_keeps_its_raw_string() {
    let error = Error::from_wire(Some("quantum_lockout"), "something new happened");
    assert_eq!(error.code, SignerErrorCode::Unknown);
    assert_eq!(error.raw_code, "quantum_lockout");
    assert_eq!(error.message, "something new happened");
}

#[test]
fn a_missing_error_code_becomes_unknown() {
    let error = Error::from_wire(None, "the transport failed");
    assert_eq!(error.code, SignerErrorCode::Unknown);
    assert_eq!(error.raw_code, "unknown");
}

/// The error serializes as an object, not a string: the frontend switches on
/// `code`, and flattening it to a message would leave "the user cancelled the
/// prompt" and "this key was destroyed" indistinguishable.
#[test]
fn errors_serialize_with_their_code() {
    let error = Error::new(SignerErrorCode::KeyInvalidated, "biometrics changed");
    let json = serde_json::to_value(&error).expect("an error must serialize");
    assert_eq!(json["code"], "key_invalidated");
    assert_eq!(json["message"], "biometrics changed");
}
