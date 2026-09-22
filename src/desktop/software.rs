//! The software fallback. The fallback, and only the fallback.
//!
//! Reached when no native backend on this OS could be opened — no TPM on
//! Windows or Linux, or the `linux-tpm` feature is off. macOS never lands here
//! in practice, because the data-protection keychain is always available.
//!
//! The private scalar lives in process memory while the key is in use and on
//! disk between runs, so it is
//! extractable by anything that can read either — which is exactly why every
//! key this signer produces reports [`KeyBacking::Software`] and
//! `hardware_backed: false`. That flag is the API's whole point: a caller can
//! see it is on the degraded path instead of assuming a protection it does not
//! have.
//!
//! Two behaviours are refusals rather than degradations, and both are
//! deliberate:
//!
//! * `require_hardware` fails outright. There is no hardware here to require.
//! * [`KeyProtection::UserPresent`] fails outright. There is no secure element
//!   to withhold a signature and no platform prompt to raise; `sign` would
//!   return happily with no human anywhere near the machine. Handing that back
//!   as a user-present key would make every downstream check that compares
//!   protection against key id — an audit log, a risk score, a backend that
//!   demands the prompting key for a sensitive operation — assert something
//!   untrue about how the signature was produced.
//!
//! Signing uses RFC 6979 deterministic `k`, which is what `p256` does; the
//! mobile keystores use a random `k`. Both are valid ES256, so never treat a
//! signature as a cache key or an idempotency token.

use std::path::PathBuf;

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};

use crate::b64;
use crate::desktop::Backend;
use crate::error::{Error, SignerErrorCode};
use crate::models::{EcPublicJwk, KeyBacking, KeyProtection, SecureKey, SignerCapabilities};

/// One stored key. Only ever holds a software scalar — there is no hardware
/// path on this target that could produce anything else.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct KeyRecord {
    /// base64url of the 32-byte private scalar.
    d: String,
    /// base64url of the 32-byte affine X coordinate.
    x: String,
    /// base64url of the 32-byte affine Y coordinate.
    y: String,
}

/// A file-backed P-256 signer.
///
/// One file per key, rather than one file holding a map of them, and no
/// in-memory cache. A single file would make every write a read-modify-write of
/// the whole store, so two instances of the same app — Tauri's single-instance
/// behaviour is opt-in, so this is a thing users do — would race, and the
/// loser's device key would silently disappear. Per-key files make a write
/// touch only the key it is about, so there is no map to lose.
pub(crate) struct SoftwareBackend {
    directory: PathBuf,
}

impl SoftwareBackend {
    pub(crate) fn new(directory: PathBuf) -> Self {
        Self { directory }
    }
}

impl Backend for SoftwareBackend {
    /// What this platform can do: software, and it says so.
    fn capabilities(&self) -> crate::Result<SignerCapabilities> {
        Ok(SignerCapabilities::new(
            "rust-software",
            KeyBacking::Software,
        ))
    }

    fn generate_key(
        &self,
        key_id: &str,
        require_hardware: bool,
        overwrite: bool,
        protection: KeyProtection,
    ) -> crate::Result<SecureKey> {
        if require_hardware {
            return Err(Error::new(
                SignerErrorCode::HardwareUnavailable,
                "The software fallback signer cannot produce a hardware-backed key",
            ));
        }
        if protection.requires_user_presence() {
            return Err(Error::new(
                SignerErrorCode::HardwareUnavailable,
                "The software fallback signer cannot enforce user presence — user-present \
                 operations require a device with a secure element",
            ));
        }
        if !overwrite && self.read(key_id)?.is_some() {
            return Err(Error::new(
                SignerErrorCode::KeyAlreadyExists,
                format!("A software key already exists under \"{key_id}\""),
            ));
        }

        let signing_key = SigningKey::random(&mut rand_core::OsRng);
        let point = signing_key.verifying_key().to_encoded_point(false);
        let x = point.x().ok_or_else(|| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                "The generated public key has no affine X coordinate",
            )
        })?;
        let y = point.y().ok_or_else(|| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                "The generated public key has no affine Y coordinate",
            )
        })?;

        let record = KeyRecord {
            d: b64::encode(signing_key.to_bytes()),
            x: b64::encode(x),
            y: b64::encode(y),
        };
        self.write(key_id, &record)?;
        Ok(describe(key_id, &record))
    }

    fn get_key(&self, key_id: &str) -> crate::Result<Option<SecureKey>> {
        Ok(self.read(key_id)?.map(|record| describe(key_id, &record)))
    }

    /// `reason` is accepted and ignored: this signer never holds a user-present
    /// key, so there is no prompt to caption.
    fn sign(&self, key_id: &str, payload: &[u8], _reason: Option<&str>) -> crate::Result<Vec<u8>> {
        let record = self.read(key_id)?.ok_or_else(|| {
            Error::new(
                SignerErrorCode::KeyNotFound,
                format!("No key stored under \"{key_id}\""),
            )
        })?;

        let scalar = b64::decode(&record.d)?;
        let signing_key = SigningKey::from_slice(&scalar).map_err(|e| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("The stored key under \"{key_id}\" is not a valid P-256 scalar: {e}"),
            )
        })?;
        // `Signer::sign` applies SHA-256 itself, matching java.security's
        // "SHA256withECDSA" and the Security framework's
        // `.ecdsaSignatureMessageX962SHA256`.
        let signature: Signature = signing_key.sign(payload);
        // `Signature::to_bytes` is already IEEE P1363 `r‖s`, fixed width — the
        // conversion the Kotlin and Swift sides must perform from DER is simply
        // not needed here.
        Ok(signature.to_bytes().to_vec())
    }

    fn delete_key(&self, key_id: &str) -> crate::Result<()> {
        match std::fs::remove_file(self.path_for(key_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("Could not delete the key under \"{key_id}\": {e}"),
            )),
        }
    }
}

impl SoftwareBackend {
    /// Where one key's record lives.
    ///
    /// The file name is the base64url of the key id, not the key id itself: the
    /// caller chooses that id, and one containing `/` or `..` would otherwise
    /// name a path outside the store.
    fn path_for(&self, key_id: &str) -> PathBuf {
        self.directory.join(format!("{}.json", b64::encode(key_id)))
    }

    fn read(&self, key_id: &str) -> crate::Result<Option<KeyRecord>> {
        match std::fs::read(self.path_for(key_id)) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
                Error::new(
                    SignerErrorCode::KeystoreFailure,
                    format!("The stored record for \"{key_id}\" is unreadable: {e}"),
                )
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("Could not read the key under \"{key_id}\": {e}"),
            )),
        }
    }

    fn write(&self, key_id: &str, record: &KeyRecord) -> crate::Result<()> {
        std::fs::create_dir_all(&self.directory).map_err(|e| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("Could not create {}: {e}", self.directory.display()),
            )
        })?;
        let path = self.path_for(key_id);
        let json = serde_json::to_vec(record).map_err(|e| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("Could not serialize the key under \"{key_id}\": {e}"),
            )
        })?;
        std::fs::write(&path, json).map_err(|e| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("Could not write {}: {e}", path.display()),
            )
        })?;

        // Owner-only. The scalar is in this file in the clear — that is inherent
        // to a software key, and stated in the README rather than hidden — so at
        // least keep other local accounts out of it. Windows has no chmod; NTFS
        // ACLs inherit from the per-user app data directory, which is already
        // owner-scoped.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }
}

fn describe(key_id: &str, record: &KeyRecord) -> SecureKey {
    SecureKey::new(
        key_id,
        EcPublicJwk::new(record.x.clone(), record.y.clone()),
        KeyBacking::Software,
    )
}
