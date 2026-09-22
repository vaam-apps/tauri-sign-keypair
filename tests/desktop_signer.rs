//! End-to-end tests for the desktop software fallback, through the real plugin.
//!
//! These drive the plugin as a Tauri app would — `init()`, managed state, the
//! `SignKeypairExt` trait — rather than reaching into `desktop.rs`, so what is
//! under test is the path a consuming app actually takes.
//!
//! The signature is verified with `p256`'s **verifier** against the reported
//! JWK, not against anything this crate produced, so a coordinate-encoding bug
//! fails here rather than at a customer's device registration.

#![cfg(desktop)]

use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::EncodedPoint;
use tauri::test::{mock_builder, mock_context, noop_assets};

use tauri_plugin_sign_keypair::{
    KeyBacking, KeyProtection, SignKeypair, SignKeypairExt, SignerErrorCode,
};

fn app() -> tauri::App<tauri::test::MockRuntime> {
    mock_builder()
        .plugin(tauri_plugin_sign_keypair::init())
        .build(mock_context(noop_assets()))
        .expect("the plugin must initialise in a mock app")
}

/// A key id nothing else in this process or a previous run will collide with,
/// which deletes itself when the test ends **however it ends**.
///
/// Both halves are load-bearing and both were learned the hard way.
///
/// Unique, because the software store is a file in the app data directory and
/// outlives the test binary: a fixed alias would make the second run fail with
/// `key_already_exists` and look like a regression.
///
/// Self-deleting via `Drop` rather than a `delete_key` line at the end of the
/// test body, because a line at the end does not run when an assertion above it
/// panics — and this suite writes **private scalars in the clear**. An earlier
/// version of these tests failed mid-way and left two P-256 private keys sitting
/// in the user's Application Support directory, where nothing later cleaned them
/// up. A leaked test key is not a real credential, but a test suite that strews
/// private key material around the filesystem on failure is the wrong habit to
/// build into a signing library.
struct TestKey {
    id: String,
    app: tauri::App<tauri::test::MockRuntime>,
}

impl TestKey {
    fn new(label: &str) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock must be after 1970")
            .as_nanos();
        Self {
            id: format!("test_{label}_{nanos}"),
            app: app(),
        }
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn signer(&self) -> &SignKeypair<tauri::test::MockRuntime> {
        self.app.sign_keypair()
    }
}

impl Drop for TestKey {
    fn drop(&mut self) {
        // Best effort, and deliberately not asserted: this runs during unwind
        // from a failing test, and a panic here would replace that test's real
        // failure message with a confusing double-panic abort.
        let _ = self.app.sign_keypair().delete_key(&self.id);
    }
}

fn b64u_decode(value: &str) -> Vec<u8> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    URL_SAFE_NO_PAD
        .decode(value)
        .expect("a JWK coordinate must be base64url")
}

#[test]
fn capabilities_report_software_and_say_so() {
    let app = app();
    let capabilities = app
        .sign_keypair()
        .capabilities()
        .expect("capabilities must not fail");

    assert_eq!(capabilities.best_available_backing, KeyBacking::Software);
    // The whole point of the flag: a caller can see it is on the degraded path
    // instead of assuming a protection it does not have.
    assert!(!capabilities.hardware_backed);
}

#[test]
fn a_generated_signature_verifies_against_the_reported_jwk() {
    let test_key = TestKey::new("verify");
    let key_id = test_key.id();
    let signer = test_key.signer();

    let key = signer
        .generate_key(key_id, false, false, KeyProtection::Ambient)
        .expect("generate must succeed on the software backend");
    assert_eq!(key.backing, KeyBacking::Software);
    assert!(!key.hardware_backed);
    assert_eq!(key.public_key.crv, "P-256");
    assert_eq!(key.public_key.kty, "EC");

    let payload = b"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload";
    let signature_bytes = signer
        .sign(key_id, payload, None)
        .expect("sign must succeed");
    // JWS ES256 requires IEEE P1363, which is fixed width. A DER signature
    // would be 70-72 bytes and would fail verification roughly 1 time in 256
    // rather than every time — so assert the length, not just the verify.
    assert_eq!(
        signature_bytes.len(),
        64,
        "ES256 needs a 64-byte P1363 signature"
    );

    let x = b64u_decode(&key.public_key.x);
    let y = b64u_decode(&key.public_key.y);
    assert_eq!(x.len(), 32, "a P-256 coordinate is exactly 32 bytes");
    assert_eq!(y.len(), 32, "a P-256 coordinate is exactly 32 bytes");

    let point = EncodedPoint::from_affine_coordinates(
        x.as_slice().into(),
        y.as_slice().into(),
        /* compress = */ false,
    );
    let verifying_key =
        VerifyingKey::from_encoded_point(&point).expect("the reported JWK must be a valid point");
    let signature =
        Signature::from_slice(&signature_bytes).expect("the signature must parse as P1363");

    verifying_key
        .verify(payload, &signature)
        .expect("the signature must verify against the JWK the plugin reported");
}

/// `require_hardware` must fail loudly rather than quietly hand back a software
/// key. Silently degrading would be worse than an error, because the caller
/// would log "hardware-backed" for a key that is not.
#[test]
fn require_hardware_is_refused_not_degraded() {
    let test_key = TestKey::new("require_hardware");

    let error = test_key
        .signer()
        .generate_key(test_key.id(), true, false, KeyProtection::Ambient)
        .expect_err("require_hardware must be refused on a software backend");

    assert_eq!(error.code, SignerErrorCode::HardwareUnavailable);
    assert!(
        test_key.signer().get_key(test_key.id()).unwrap().is_none(),
        "a refused generate must not leave a key behind"
    );
}

/// There is no secure element here to withhold a signature and no prompt to
/// raise, so a "user-present" key would sign happily with nobody at the
/// keyboard. Refuse instead of issuing a key that answers to the name.
#[test]
fn user_presence_is_refused_not_faked() {
    let test_key = TestKey::new("user_present");

    let error = test_key
        .signer()
        .generate_key(test_key.id(), false, false, KeyProtection::UserPresent)
        .expect_err("a software backend must not pretend to enforce user presence");

    assert_eq!(error.code, SignerErrorCode::HardwareUnavailable);
    assert!(test_key.signer().get_key(test_key.id()).unwrap().is_none());
}

#[test]
fn generate_without_overwrite_refuses_to_clobber_an_existing_key() {
    let test_key = TestKey::new("clobber");
    let key_id = test_key.id();
    let signer = test_key.signer();

    let original = signer
        .generate_key(key_id, false, false, KeyProtection::Ambient)
        .unwrap();

    let error = signer
        .generate_key(key_id, false, false, KeyProtection::Ambient)
        .expect_err("a second generate without overwrite must be refused");
    assert_eq!(error.code, SignerErrorCode::KeyAlreadyExists);

    let surviving = signer
        .get_key(key_id)
        .unwrap()
        .expect("the key must survive");
    assert_eq!(surviving.public_key, original.public_key);

    // With overwrite it succeeds, and the key is a different one — which is why
    // the caller must re-register it.
    let replacement = signer
        .generate_key(key_id, false, true, KeyProtection::Ambient)
        .unwrap();
    assert_ne!(replacement.public_key, original.public_key);
}

#[test]
fn a_deleted_key_cannot_sign_and_deleting_twice_is_a_no_op() {
    let test_key = TestKey::new("deleted");
    let key_id = test_key.id();
    let signer = test_key.signer();

    signer
        .generate_key(key_id, false, false, KeyProtection::Ambient)
        .unwrap();
    signer.delete_key(key_id).unwrap();

    assert!(signer.get_key(key_id).unwrap().is_none());
    let error = signer
        .sign(key_id, b"payload", None)
        .expect_err("a deleted key must not sign");
    assert_eq!(error.code, SignerErrorCode::KeyNotFound);

    signer
        .delete_key(key_id)
        .expect("deleting a missing key is a documented no-op");
}

/// The store survives a restart of the plugin, which is the difference between
/// a usable desktop fallback and one that forces re-enrolment on every launch.
#[test]
fn keys_survive_a_plugin_restart() {
    // `TestKey` owns its own app handle, so dropping it at the end of the test
    // is what stands in for the "second launch" doing the cleanup.
    let test_key = TestKey::new("persistence");
    let key_id = test_key.id();

    let first = app();
    let generated = first
        .sign_keypair()
        .generate_key(key_id, false, false, KeyProtection::Ambient)
        .unwrap();
    drop(first);

    let second = app();
    let reloaded = second
        .sign_keypair()
        .get_key(key_id)
        .unwrap()
        .expect("the key must still be there after a restart");
    assert_eq!(reloaded.public_key, generated.public_key);
}
