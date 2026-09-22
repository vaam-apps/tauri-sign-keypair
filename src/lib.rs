//! Hardware-backed ES256 signing for device-bound authentication in Tauri v2.
//!
//! The private key is generated **inside** AndroidKeyStore or the Apple Secure
//! Enclave and never leaves it. Signing happens in the secure element; the raw
//! private scalar never enters the WebView, the Rust process, or app memory.
//!
//! See `README.md` for why that matters and what the two-key model buys. The
//! short version: a signer that keeps the scalar in process memory hands the
//! credential to anything that can read the process, and a single key cannot
//! correctly serve both a background request interceptor (which must never
//! prompt) and a high-value confirmation (which must always prompt).
//!
//! ```ignore
//! tauri::Builder::default()
//!     .plugin(tauri_plugin_sign_keypair::init())
//!     .run(tauri::generate_context!())
//!     .expect("error while running tauri application");
//! ```

use tauri::{
    plugin::{Builder, TauriPlugin},
    Manager, Runtime,
};

// Only macOS needs it: AndroidKeyStore and the Security framework emit DER, but
// the Kotlin and Swift sides convert before the bytes ever reach Rust, and
// Windows CNG returns IEEE P1363 already.
#[cfg(target_os = "macos")]
mod asn1;
mod b64;
mod commands;
mod error;
pub mod jws;
mod models;

#[cfg(desktop)]
mod desktop;
#[cfg(mobile)]
mod mobile;

pub use error::{Error, Result, SignerErrorCode};
pub use models::{EcPublicJwk, KeyBacking, KeyProtection, SecureKey, SignerCapabilities};

/// The platform's signer, as returned by [`SignKeypairExt::sign_keypair`].
///
/// Public so a caller can name the type — a helper that takes the signer, or a
/// test that holds one — but its inherent methods are the whole API; there is
/// nothing to construct here directly.
#[cfg(desktop)]
pub use desktop::SignKeypair;
#[cfg(mobile)]
pub use mobile::SignKeypair;

/// The key id used when a caller does not name one — the *ambient* key, meant
/// to be signed with on every request, including from a background interceptor
/// or polling timer.
pub const DEFAULT_KEY_ID: &str = "device";

/// The key id for the *user-present* key — the one that prompts.
///
/// A separate alias rather than a flag on the same one, because the platform
/// stores the protection policy *with* the key: one alias cannot be both
/// prompting and silent, and rewriting it to switch would destroy the key.
pub const DEFAULT_USER_PRESENT_KEY_ID: &str = "device_user_present";

/// Reach the signer from any [`Manager`] — an `AppHandle`, a `Window`, the
/// `App` itself.
pub trait SignKeypairExt<R: Runtime> {
    /// The plugin's backend for this platform.
    fn sign_keypair(&self) -> &SignKeypair<R>;
}

impl<R: Runtime, T: Manager<R>> SignKeypairExt<R> for T {
    fn sign_keypair(&self) -> &SignKeypair<R> {
        self.state::<SignKeypair<R>>().inner()
    }
}

/// Register the plugin with a Tauri builder.
pub fn init<R: Runtime>() -> TauriPlugin<R> {
    Builder::new("sign-keypair")
        .invoke_handler(tauri::generate_handler![
            commands::capabilities,
            commands::generate_key,
            commands::get_key,
            commands::sign,
            commands::delete_key,
        ])
        .setup(|app, api| {
            #[cfg(mobile)]
            let signer = mobile::init(app, api)?;
            #[cfg(desktop)]
            let signer = desktop::init(app, api)?;
            app.manage(signer);
            Ok(())
        })
        .build()
}
