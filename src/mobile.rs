//! The native path: AndroidKeyStore on Android, the Secure Enclave on iOS.
//!
//! Everything here is adapter. The keystore work lives in
//! `android/src/main/java/app/vaam/signkeypair/SecureKeyStore.kt` and
//! `ios/Sources/SignKeypairPlugin/Plugin.swift`; what this module owns is the
//! call shape and, importantly, turning a rejected mobile invoke back into a
//! typed [`crate::Error`] with its code intact. A native side that reports
//! `user_authentication_cancelled` and a Rust side that flattens every failure
//! into one string would leave the frontend unable to tell a customer changing
//! their mind from a key destroyed by a biometric re-enrolment.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tauri::{
    plugin::{PluginApi, PluginHandle},
    AppHandle, Runtime,
};

use crate::b64;
use crate::error::{Error, SignerErrorCode};
use crate::models::{KeyProtection, SecureKey, SignerCapabilities};

#[cfg(target_os = "android")]
const PLUGIN_IDENTIFIER: &str = "app.vaam.signkeypair";

#[cfg(target_os = "ios")]
tauri::ios_plugin_binding!(init_plugin_sign_keypair);

/// Initialise the mobile backend by registering the native plugin.
pub fn init<R: Runtime, C: DeserializeOwned>(
    _app: &AppHandle<R>,
    api: PluginApi<R, C>,
) -> crate::Result<SignKeypair<R>> {
    #[cfg(target_os = "android")]
    let handle = api
        .register_android_plugin(PLUGIN_IDENTIFIER, "SignKeypairPlugin")
        .map_err(|e| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("Could not register the Android plugin: {e}"),
            )
        })?;
    #[cfg(target_os = "ios")]
    let handle = api
        .register_ios_plugin(init_plugin_sign_keypair)
        .map_err(|e| {
            Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("Could not register the iOS plugin: {e}"),
            )
        })?;

    Ok(SignKeypair(handle))
}

/// The mobile signer, held in Tauri's managed state.
pub struct SignKeypair<R: Runtime>(PluginHandle<R>);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct KeyIdArgs<'a> {
    key_id: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GenerateKeyArgs<'a> {
    key_id: &'a str,
    require_hardware: bool,
    overwrite: bool,
    /// The wire tag, not the enum: the native sides parse this themselves and
    /// refuse an unrecognised value rather than defaulting.
    protection: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SignArgs<'a> {
    key_id: &'a str,
    /// base64url of the raw signing input. The IPC carries JSON, so bytes
    /// travel encoded rather than as an array of numbers — which would triple
    /// the payload for no gain.
    payload: String,
    reason: Option<&'a str>,
}

#[derive(Deserialize)]
struct GetKeyResponse {
    /// `default` so an absent field reads as "no key", not a deserialization
    /// error. A native side that resolves `{}` instead of `{"key": null}` — and
    /// `JSONObject.put(k, null)` on Android does exactly that if you let it —
    /// would otherwise turn "this device is not enrolled" into a hard failure.
    #[serde(default)]
    key: Option<SecureKey>,
}

#[derive(Deserialize)]
struct SignResponse {
    /// base64url of the 64-byte IEEE P1363 signature.
    signature: String,
}

#[derive(Deserialize)]
struct EmptyResponse {}

impl<R: Runtime> SignKeypair<R> {
    /// What this device can actually do, probed now.
    pub fn capabilities(&self) -> crate::Result<SignerCapabilities> {
        self.call("capabilities", ())
    }

    /// Create a P-256 keypair inside the secure element.
    pub fn generate_key(
        &self,
        key_id: &str,
        require_hardware: bool,
        overwrite: bool,
        protection: KeyProtection,
    ) -> crate::Result<SecureKey> {
        self.call(
            "generateKey",
            GenerateKeyArgs {
                key_id,
                require_hardware,
                overwrite,
                protection: protection.as_wire(),
            },
        )
    }

    /// The existing key handle, or `None` when the device is not enrolled.
    pub fn get_key(&self, key_id: &str) -> crate::Result<Option<SecureKey>> {
        let response: GetKeyResponse = self.call("getKey", KeyIdArgs { key_id })?;
        Ok(response.key)
    }

    /// Sign `payload` inside the secure element, prompting when the key demands it.
    pub fn sign(
        &self,
        key_id: &str,
        payload: &[u8],
        reason: Option<&str>,
    ) -> crate::Result<Vec<u8>> {
        let response: SignResponse = self.call(
            "sign",
            SignArgs {
                key_id,
                payload: b64::encode(payload),
                reason,
            },
        )?;
        b64::decode(&response.signature)
    }

    /// Remove the key at `key_id`. Removing a key that does not exist is a no-op.
    pub fn delete_key(&self, key_id: &str) -> crate::Result<()> {
        let _: EmptyResponse = self.call("deleteKey", KeyIdArgs { key_id })?;
        Ok(())
    }

    /// The one place a mobile rejection is turned back into a typed error.
    ///
    /// `code` is read off the rejection rather than parsed out of the message,
    /// and an unrecognised one is preserved on `raw_code` instead of being
    /// flattened — so a native build newer than this crate stays diagnosable.
    fn call<T: DeserializeOwned>(&self, command: &str, args: impl Serialize) -> crate::Result<T> {
        use tauri::plugin::mobile::PluginInvokeError;

        self.0
            .run_mobile_plugin::<T>(command, args)
            .map_err(|e| match e {
                PluginInvokeError::InvokeRejected(response) => Error::from_wire(
                    response.code.as_deref(),
                    response
                        .message
                        .unwrap_or_else(|| format!("The native plugin rejected \"{command}\"")),
                ),
                other => Error::new(
                    SignerErrorCode::KeystoreFailure,
                    format!("The native plugin failed on \"{command}\": {other}"),
                ),
            })
    }
}
