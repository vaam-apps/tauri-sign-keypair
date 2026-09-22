//! CNG backend for Windows, preferring the TPM.
//!
//! Windows exposes key storage through **NCrypt**, and which *provider* you open
//! decides whether you get hardware:
//!
//! | Provider | Where the key lives | Reported as |
//! |---|---|---|
//! | Microsoft Platform Crypto Provider | the TPM | `tee` |
//! | Microsoft Software Key Storage Provider | a DPAPI-protected file | (not used — we fall through to our own software backend instead) |
//!
//! [`CngBackend::probe`] opens the platform provider and creates a throwaway
//! key. A machine with no TPM, a disabled TPM, or a TPM already at its key
//! capacity fails there, and the plugin falls back to the portable software
//! signer rather than to the Microsoft software KSP. That choice is deliberate:
//! two different software stores on one OS would mean a key created on a TPM
//! machine and a key created on a non-TPM machine live in different places under
//! the same key id, and `delete_key` would have to guess which.
//!
//! ### `tee`, not `strongbox`
//!
//! A TPM is a discrete tamper-resistant chip, which sounds like StrongBox. It is
//! reported as `tee` because `strongbox` is defined in this plugin's vocabulary
//! as *Android StrongBox specifically*, and inventing a fourth hardware tag
//! would mean every wire↔enum mapping in four languages has to learn it. Both
//! classify as `hardware_backed = true`, which is the only distinction a caller
//! acts on.
//!
//! ### What CNG does differently from Apple
//!
//! * `NCryptSignHash` signs a **hash**, not a message — so SHA-256 is applied
//!   here rather than by the platform.
//! * ECDSA signatures come back as raw `r‖s` already, so unlike the Kotlin and
//!   Swift sides there is **no DER conversion**.
//! * There is no per-key biometric binding. See [`CngBackend::generate_key`].

use sha2::{Digest, Sha256};
use windows::core::{HSTRING, PCWSTR};
use windows::Win32::Security::Cryptography::*;

use crate::desktop::Backend;
use crate::error::{Error, SignerErrorCode};
use crate::models::{EcPublicJwk, KeyBacking, KeyProtection, SecureKey, SignerCapabilities};

/// Namespace for key names inside the provider, matching the other platforms'
/// `kSecAttrApplicationTag` / keystore-alias prefix.
const KEY_NAME_PREFIX: &str = "app.vaam.signkeypair.";

/// `BCRYPT_ECCKEY_BLOB.dwMagic` for a P-256 public key.
const BCRYPT_ECDSA_PUBLIC_P256_MAGIC: u32 = 0x3153_4345;

/// Bytes in one P-256 coordinate.
const COORDINATE_LENGTH: usize = 32;

pub(crate) struct CngBackend;

impl CngBackend {
    /// Open the TPM provider and prove we can actually persist a key in it.
    ///
    /// Like the macOS probe, this **writes**: opening a provider succeeds on
    /// machines whose TPM then refuses key creation (disabled in firmware, owner
    /// authorisation not set, NV storage full). A probe that only opened the
    /// provider would select this backend and then fail every call.
    pub(crate) fn probe() -> Option<Self> {
        let provider = open_provider().ok()?;
        let name = key_name("__probe_can_store__");

        // Remove a leftover from an earlier interrupted probe first, or
        // NTE_EXISTS masks a perfectly healthy TPM.
        if let Ok(existing) = open_key(&provider, &name) {
            unsafe { NCryptDeleteKey(existing.0, 0) }.ok()?;
        }

        let created = create_key(&provider, &name, KeyProtection::Ambient).is_ok();
        if let Ok(handle) = open_key(&provider, &name) {
            unsafe {
                let _ = NCryptDeleteKey(handle.0, 0);
            }
        }
        created.then_some(Self)
    }
}

impl Backend for CngBackend {
    fn capabilities(&self) -> crate::Result<SignerCapabilities> {
        Ok(SignerCapabilities::new(
            "windows",
            KeyBacking::TrustedExecutionEnvironment,
        ))
    }

    /// Create a P-256 key inside the TPM.
    ///
    /// **`KeyProtection::UserPresent` is refused**, and that is a considered
    /// position rather than an omission. Windows has no equivalent of
    /// `setUserAuthenticationRequired` / `.biometryCurrentSet`: the nearest
    /// thing is `NCRYPT_UI_POLICY`, which makes the TPM demand the *key's own
    /// PIN* before each use. That is a real per-operation check, but it is not
    /// bound to a biometric enrolment, so the property the user-present key
    /// exists to carry — "a newly enrolled fingerprint does not inherit this
    /// key's authority" — simply does not hold. Windows Hello proper lives
    /// behind `KeyCredentialManager`, a WinRT API with its own enrolment
    /// ceremony and its own key store, which this plugin does not use.
    ///
    /// Issuing a key that answers to the name `user_present` without that
    /// property would make every downstream check that compares protection
    /// against key id assert something untrue. So it refuses, exactly as the
    /// software and WebCrypto backends do.
    fn generate_key(
        &self,
        key_id: &str,
        _require_hardware: bool,
        overwrite: bool,
        protection: KeyProtection,
    ) -> crate::Result<SecureKey> {
        if protection.requires_user_presence() {
            return Err(Error::new(
                SignerErrorCode::HardwareUnavailable,
                "Windows cannot bind a key to a biometric enrolment the way Android and iOS \
                 can — user-present operations are not supported on this platform. See the \
                 note on NCRYPT_UI_POLICY and KeyCredentialManager in the plugin docs.",
            ));
        }
        // `require_hardware` needs no check: reaching this backend at all means
        // the probe persisted a key in the TPM, so hardware is what you get.

        let provider = open_provider()?;
        let name = key_name(key_id);

        if let Ok(existing) = open_key(&provider, &name) {
            if !overwrite {
                return Err(Error::new(
                    SignerErrorCode::KeyAlreadyExists,
                    format!("A key already exists under \"{key_id}\""),
                ));
            }
            unsafe { NCryptDeleteKey(existing.0, 0) }.map_err(|e| {
                Error::new(
                    SignerErrorCode::KeystoreFailure,
                    format!("NCryptDeleteKey failed: {e}"),
                )
            })?;
        }

        let handle = create_key(&provider, &name, protection)?;
        let jwk = public_jwk(&handle)?;
        Ok(SecureKey::new(
            key_id,
            jwk,
            KeyBacking::TrustedExecutionEnvironment,
        ))
    }

    fn get_key(&self, key_id: &str) -> crate::Result<Option<SecureKey>> {
        let provider = open_provider()?;
        let Ok(handle) = open_key(&provider, &key_name(key_id)) else {
            return Ok(None);
        };
        Ok(Some(SecureKey::new(
            key_id,
            public_jwk(&handle)?,
            KeyBacking::TrustedExecutionEnvironment,
        )))
    }

    /// Sign `payload`, returning IEEE P1363 `r‖s`.
    ///
    /// `reason` is accepted and ignored: this backend never holds a user-present
    /// key, so there is no prompt to caption.
    fn sign(&self, key_id: &str, payload: &[u8], _reason: Option<&str>) -> crate::Result<Vec<u8>> {
        let provider = open_provider()?;
        let handle = open_key(&provider, &key_name(key_id)).map_err(|_| {
            Error::new(
                SignerErrorCode::KeyNotFound,
                format!("No key stored under \"{key_id}\""),
            )
        })?;

        // CNG signs a hash, not a message. Apple's
        // `.ecdsaSignatureMessageX962SHA256` and java.security's
        // "SHA256withECDSA" both digest internally; here it is our job, and
        // getting it wrong produces a signature over the wrong bytes that
        // verifies against nothing.
        let digest = Sha256::digest(payload);

        let mut written = 0u32;
        unsafe { NCryptSignHash(handle.0, None, &digest, None, &mut written, NCRYPT_FLAGS(0)) }
            .map_err(|e| {
                Error::new(
                    SignerErrorCode::KeystoreFailure,
                    format!("NCryptSignHash (size query) failed: {e}"),
                )
            })?;

        let mut signature = vec![0u8; written as usize];
        unsafe {
            NCryptSignHash(
                handle.0,
                None,
                &digest,
                Some(&mut signature),
                &mut written,
                NCRYPT_FLAGS(0),
            )
        }
        .map_err(|e| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("NCryptSignHash failed: {e}"),
            )
        })?;
        signature.truncate(written as usize);

        // CNG already returns fixed-width `r‖s`, so there is no DER to unwrap.
        // Assert the width anyway: a 70-odd-byte result would mean this provider
        // returned DER after all, and a JWS built from it would fail verification
        // on the server with nothing useful in the logs.
        if signature.len() != COORDINATE_LENGTH * 2 {
            return Err(Error::new(
                SignerErrorCode::KeystoreFailure,
                format!(
                    "Expected a {}-byte P1363 signature, got {}",
                    COORDINATE_LENGTH * 2,
                    signature.len()
                ),
            ));
        }
        Ok(signature)
    }

    fn delete_key(&self, key_id: &str) -> crate::Result<()> {
        let provider = open_provider()?;
        let Ok(handle) = open_key(&provider, &key_name(key_id)) else {
            // Deleting a key that does not exist is a documented no-op.
            return Ok(());
        };
        unsafe { NCryptDeleteKey(handle.0, 0) }.map_err(|e| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("NCryptDeleteKey failed: {e}"),
            )
        })
    }
}

// ---------------------------------------------------------------------------
// NCrypt plumbing
// ---------------------------------------------------------------------------

/// An owned `NCRYPT_PROV_HANDLE`, freed on drop.
struct Provider(NCRYPT_PROV_HANDLE);

impl Drop for Provider {
    fn drop(&mut self) {
        if self.0 .0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(self.0 .0));
            }
        }
    }
}

/// An owned `NCRYPT_KEY_HANDLE`, freed on drop.
struct Key(NCRYPT_KEY_HANDLE);

impl Drop for Key {
    fn drop(&mut self) {
        if self.0 .0 != 0 {
            unsafe {
                let _ = NCryptFreeObject(NCRYPT_HANDLE(self.0 .0));
            }
        }
    }
}

/// `app.vaam.signkeypair.<key_id>`, the name the key is persisted under.
fn key_name(key_id: &str) -> HSTRING {
    HSTRING::from(format!("{KEY_NAME_PREFIX}{key_id}"))
}

/// Open the TPM-backed provider.
fn open_provider() -> crate::Result<Provider> {
    let mut handle = NCRYPT_PROV_HANDLE::default();
    unsafe { NCryptOpenStorageProvider(&mut handle, MS_PLATFORM_CRYPTO_PROVIDER, 0) }.map_err(
        |e| {
            Error::new(
                SignerErrorCode::HardwareUnavailable,
                format!("This machine has no usable TPM: {e}"),
            )
        },
    )?;
    Ok(Provider(handle))
}

/// Open an existing persisted key, or fail when there is none.
fn open_key(provider: &Provider, name: &HSTRING) -> crate::Result<Key> {
    let mut handle = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptOpenKey(
            provider.0,
            &mut handle,
            PCWSTR(name.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| {
        Error::new(
            SignerErrorCode::KeyNotFound,
            format!("NCryptOpenKey failed: {e}"),
        )
    })?;
    Ok(Key(handle))
}

/// Create and finalise a persisted P-256 signing key.
fn create_key(
    provider: &Provider,
    name: &HSTRING,
    _protection: KeyProtection,
) -> crate::Result<Key> {
    let mut handle = NCRYPT_KEY_HANDLE::default();
    unsafe {
        NCryptCreatePersistedKey(
            provider.0,
            &mut handle,
            BCRYPT_ECDSA_P256_ALGORITHM,
            PCWSTR(name.as_ptr()),
            CERT_KEY_SPEC(0),
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| {
        Error::new(
            SignerErrorCode::KeystoreFailure,
            format!("NCryptCreatePersistedKey failed: {e}"),
        )
    })?;
    let key = Key(handle);

    // Nothing here makes the key exportable. NCRYPT_EXPORT_POLICY_PROPERTY is
    // left unset, which means not exportable — the TPM provider would refuse a
    // plaintext export in any case, and saying so explicitly would only invite
    // someone to "fix" it later.
    unsafe { NCryptFinalizeKey(key.0, NCRYPT_FLAGS(0)) }.map_err(|e| {
        Error::new(
            SignerErrorCode::KeystoreFailure,
            format!("NCryptFinalizeKey failed: {e}"),
        )
    })?;
    Ok(key)
}

/// Export the public half and turn it into an RFC 7517 JWK.
///
/// `BCRYPT_ECCPUBLIC_BLOB` is a `BCRYPT_ECCKEY_BLOB` header — a 4-byte magic and
/// a 4-byte coordinate length — followed by X then Y, each `cbKey` bytes, big
/// endian and already fixed width. So unlike the `BigInteger` paths on Android
/// there is no sign byte to strip and no left-padding to do.
fn public_jwk(key: &Key) -> crate::Result<EcPublicJwk> {
    let mut written = 0u32;
    unsafe {
        NCryptExportKey(
            key.0,
            Some(NCRYPT_KEY_HANDLE::default()),
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            None,
            &mut written,
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| {
        Error::new(
            SignerErrorCode::KeystoreFailure,
            format!("NCryptExportKey (size query) failed: {e}"),
        )
    })?;

    let mut blob = vec![0u8; written as usize];
    unsafe {
        NCryptExportKey(
            key.0,
            Some(NCRYPT_KEY_HANDLE::default()),
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            Some(&mut blob),
            &mut written,
            NCRYPT_FLAGS(0),
        )
    }
    .map_err(|e| {
        Error::new(
            SignerErrorCode::KeystoreFailure,
            format!("NCryptExportKey failed: {e}"),
        )
    })?;

    const HEADER: usize = 8;
    if blob.len() < HEADER + COORDINATE_LENGTH * 2 {
        return Err(Error::new(
            SignerErrorCode::KeystoreFailure,
            format!("Public key blob is {} bytes, too short", blob.len()),
        ));
    }
    let magic = u32::from_le_bytes([blob[0], blob[1], blob[2], blob[3]]);
    let cb_key = u32::from_le_bytes([blob[4], blob[5], blob[6], blob[7]]) as usize;
    if magic != BCRYPT_ECDSA_PUBLIC_P256_MAGIC || cb_key != COORDINATE_LENGTH {
        return Err(Error::new(
            SignerErrorCode::KeystoreFailure,
            format!("Expected a P-256 public blob, got magic {magic:#x} cbKey {cb_key}"),
        ));
    }

    let x = &blob[HEADER..HEADER + COORDINATE_LENGTH];
    let y = &blob[HEADER + COORDINATE_LENGTH..HEADER + COORDINATE_LENGTH * 2];
    Ok(EcPublicJwk::new(
        crate::b64::encode(x),
        crate::b64::encode(y),
    ))
}
