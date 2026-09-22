//! Desktop backends, and how one is chosen.
//!
//! Unlike mobile — where there is exactly one keystore and it is always present
//! — a desktop machine may or may not have a secure element, and which one it
//! has depends on the OS. So this module is a dispatcher: it probes for a native
//! backend at startup and falls back to [`software`] when there is none.
//!
//! | OS | Intended native backend | Status |
//! |---|---|---|
//! | macOS | Secure Enclave / data-protection keychain | implemented |
//! | Windows | CNG, Microsoft Platform Crypto Provider (TPM) | **not implemented** |
//! | Linux | TPM 2.0 via the TSS Enhanced System API | **not implemented** |
//!
//! The probe happens **once**, at plugin init, and the result is fixed for the
//! process. Re-probing per call would mean a machine whose TPM is taken by
//! another process mid-session could silently start issuing software keys under
//! the same key id as the hardware ones — the caller would see a key id it knows
//! and a backing it did not expect, which is precisely the confusion
//! `hardware_backed` exists to prevent.

use serde::de::DeserializeOwned;
use tauri::{plugin::PluginApi, AppHandle, Manager, Runtime};

use crate::error::{Error, SignerErrorCode};
use crate::models::{KeyProtection, SecureKey, SignerCapabilities};

pub(crate) mod software;

#[cfg(target_os = "macos")]
pub(crate) mod macos;

// Windows (CNG against the Microsoft Platform Crypto Provider) and Linux
// (TPM 2.0 via the TSS Enhanced System API) are not implemented yet. Each
// becomes a `mod`, a `probe() -> Option<Self>` and a `Backend` impl, with no
// change to `commands.rs` or to the public API. Until then those two resolve to
// `software`, which reports `backing: "software"` and `hardware_backed: false`
// — under-claiming rather than over-claiming while the work is outstanding.

/// What every desktop backend implements.
///
/// The same five operations as the mobile side, so `commands.rs` needs no
/// per-platform branching. `Send + Sync` because Tauri holds this in managed
/// state and commands are polled on the async runtime.
pub(crate) trait Backend: Send + Sync {
    fn capabilities(&self) -> crate::Result<SignerCapabilities>;
    fn generate_key(
        &self,
        key_id: &str,
        require_hardware: bool,
        overwrite: bool,
        protection: KeyProtection,
    ) -> crate::Result<SecureKey>;
    fn get_key(&self, key_id: &str) -> crate::Result<Option<SecureKey>>;
    fn sign(&self, key_id: &str, payload: &[u8], reason: Option<&str>) -> crate::Result<Vec<u8>>;
    fn delete_key(&self, key_id: &str) -> crate::Result<()>;
}

/// The desktop signer, held in Tauri's managed state.
pub struct SignKeypair<R: Runtime> {
    backend: Box<dyn Backend>,
    _app: AppHandle<R>,
}

/// Initialise the desktop backend, choosing a native one where there is one.
pub fn init<R: Runtime, C: DeserializeOwned>(
    app: &AppHandle<R>,
    _api: PluginApi<R, C>,
) -> crate::Result<SignKeypair<R>> {
    // `app_local_data_dir` rather than `app_data_dir`: a device key is bound to
    // the machine it was generated on, so it must not follow a roaming profile
    // onto another one. A roamed device credential is no longer device-bound.
    // Only the software backend needs it — the native ones keep their keys in
    // the platform's own store — but it is resolved here so a backend cannot
    // silently pick a different directory.
    let directory = app
        .path()
        .app_local_data_dir()
        .map(|dir| dir.join("sign-keypair"))
        .map_err(|e| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("Could not resolve the app local data directory: {e}"),
            )
        })?;

    Ok(SignKeypair {
        backend: select_backend(directory),
        _app: app.clone(),
    })
}

/// Probe for a native backend, once.
///
/// Every native constructor returns `None` rather than an error when the
/// platform cannot serve it, because "this machine has no TPM" is not a failure
/// — it is the ordinary case that the software fallback exists for. A genuine
/// misconfiguration surfaces later, on the first call, with a code the caller
/// can act on.
fn select_backend(directory: std::path::PathBuf) -> Box<dyn Backend> {
    #[cfg(target_os = "macos")]
    if let Some(backend) = macos::SecureEnclaveBackend::probe() {
        return Box::new(backend);
    }

    Box::new(software::SoftwareBackend::new(directory))
}

impl<R: Runtime> SignKeypair<R> {
    /// What this platform can actually do, as chosen at init.
    pub fn capabilities(&self) -> crate::Result<SignerCapabilities> {
        self.backend.capabilities()
    }

    /// Create a P-256 keypair under `key_id`.
    pub fn generate_key(
        &self,
        key_id: &str,
        require_hardware: bool,
        overwrite: bool,
        protection: KeyProtection,
    ) -> crate::Result<SecureKey> {
        self.backend
            .generate_key(key_id, require_hardware, overwrite, protection)
    }

    /// The existing key handle, or `None` when there is none.
    pub fn get_key(&self, key_id: &str) -> crate::Result<Option<SecureKey>> {
        self.backend.get_key(key_id)
    }

    /// Sign `payload`, returning a 64-byte IEEE P1363 `r‖s` signature.
    pub fn sign(
        &self,
        key_id: &str,
        payload: &[u8],
        reason: Option<&str>,
    ) -> crate::Result<Vec<u8>> {
        self.backend.sign(key_id, payload, reason)
    }

    /// Remove the key at `key_id`. Removing a key that does not exist is a no-op.
    pub fn delete_key(&self, key_id: &str) -> crate::Result<()> {
        self.backend.delete_key(key_id)
    }
}
