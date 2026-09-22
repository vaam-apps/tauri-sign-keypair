//! The IPC surface.
//!
//! Thin on purpose: argument shape, the one base64url boundary for payload and
//! signature bytes, and nothing else. Both backends implement the same five
//! operations, so there is no per-platform branching here — which is what keeps
//! "the desktop fallback behaves differently" a property of `desktop.rs` alone,
//! stated there in one place, rather than something spread across the API.
//!
//! Every command is `async` so it is polled on Tauri's async runtime rather
//! than the main thread. That is load-bearing on Android: `sign` for a
//! user-present key blocks until BiometricPrompt resolves, and BiometricPrompt
//! needs the main thread to draw itself. A synchronous command would deadlock
//! on the prompt it is waiting for.

use tauri::{command, AppHandle, Runtime};

use crate::b64;
use crate::error::{Error, SignerErrorCode};
use crate::models::{KeyProtection, SecureKey, SignerCapabilities};
use crate::SignKeypairExt;

#[command]
pub(crate) async fn capabilities<R: Runtime>(
    app: AppHandle<R>,
) -> crate::Result<SignerCapabilities> {
    app.sign_keypair().capabilities()
}

#[command]
pub(crate) async fn generate_key<R: Runtime>(
    app: AppHandle<R>,
    key_id: String,
    require_hardware: Option<bool>,
    overwrite: Option<bool>,
    protection: Option<String>,
) -> crate::Result<SecureKey> {
    app.sign_keypair().generate_key(
        &key_id,
        require_hardware.unwrap_or(false),
        overwrite.unwrap_or(false),
        parse_protection(protection.as_deref())?,
    )
}

#[command]
pub(crate) async fn get_key<R: Runtime>(
    app: AppHandle<R>,
    key_id: String,
) -> crate::Result<Option<SecureKey>> {
    app.sign_keypair().get_key(&key_id)
}

#[command]
pub(crate) async fn sign<R: Runtime>(
    app: AppHandle<R>,
    key_id: String,
    payload: String,
    reason: Option<String>,
) -> crate::Result<String> {
    let bytes = b64::decode(&payload)?;
    let signature = app
        .sign_keypair()
        .sign(&key_id, &bytes, reason.as_deref())?;
    Ok(b64::encode(signature))
}

#[command]
pub(crate) async fn delete_key<R: Runtime>(app: AppHandle<R>, key_id: String) -> crate::Result<()> {
    app.sign_keypair().delete_key(&key_id)
}

/// The one wire → enum boundary for the protection tag on this side.
///
/// An absent tag means [`KeyProtection::Ambient`], which is the documented
/// default of the `generateKey` API. An unrecognised tag is a hard failure with
/// no default: guessing `ambient` would hand a caller who asked for prompted
/// protection a key that signs silently, and guessing `user_present` would make
/// a background signer prompt on every poll. The policy is baked into the key
/// permanently at creation, so a mismatched pairing fails at the call instead.
fn parse_protection(raw: Option<&str>) -> crate::Result<KeyProtection> {
    match raw {
        None => Ok(KeyProtection::Ambient),
        Some(value) => KeyProtection::from_wire(value).ok_or_else(|| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("Unknown key protection \"{value}\""),
            )
        }),
    }
}
