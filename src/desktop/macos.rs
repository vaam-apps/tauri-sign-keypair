//! Secure Enclave / data-protection keychain backend for macOS.
//!
//! This is the Rust twin of `ios/Sources/SignKeypair/Plugin.swift`: the same
//! Security-framework calls, the same access-control policy, the same two-key
//! model. It exists as a separate implementation because a Tauri app on macOS
//! runs through Rust rather than Swift, so the iOS plugin cannot simply be
//! reused — but the *behaviour* has to match, or a device enrolled on a Mac
//! would differ from one enrolled on an iPhone in ways a backend cannot see.
//!
//! ### What you get, by machine
//!
//! Apple silicon and T2 Macs have a Secure Enclave. A key created with
//! `kSecAttrTokenIDSecureEnclave` lives inside it — non-extractable, reported
//! here as `secure_enclave`. An older Intel Mac has none, so the key becomes an
//! ordinary data-protection keychain item, reported as `keychain`, which this
//! plugin deliberately does **not** count as hardware-backed: the keychain
//! protects an item without a secure element holding it.
//!
//! Either way this backend is used. There is no path that falls through to the
//! software signer, because even a keychain item is better than a scalar in a
//! file, and saying so honestly is what the `hardware_backed` flag is for.
//!
//! ### `kSecUseDataProtectionKeychain`, and why it is on every query
//!
//! Without it macOS uses the *file* keychain, where the Secure Enclave token is
//! not addressable at all. Key creation appears to succeed and silently yields a
//! non-enclave key. It is the one macOS-specific attribute that separates this
//! from the iOS code, and getting it wrong is the classic way to think you have
//! hardware backing when you do not.
//!
//! The cost is that the data-protection keychain requires a **signed** binary
//! with a keychain-access-group entitlement. An unsigned binary — `cargo test`,
//! or `cargo run` on a bare executable — gets `errSecMissingEntitlement`
//! (-34018). [`SecureEnclaveBackend::probe`] detects that at startup and
//! declines, so an unsigned build falls through to the software signer with an
//! honest `software` backing rather than failing every call at runtime.

use std::ptr;

use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::{CFRelease, CFTypeRef};
use core_foundation_sys::error::CFErrorRef;
use core_foundation_sys::string::CFStringRef;
use security_framework_sys::access_control::*;
use security_framework_sys::base::{SecAccessControlRef, SecKeyRef};
use security_framework_sys::item::*;
use security_framework_sys::key::*;
use security_framework_sys::keychain_item::{SecItemCopyMatching, SecItemDelete};

use crate::desktop::Backend;
use crate::error::{Error, SignerErrorCode};
use crate::models::{EcPublicJwk, KeyBacking, KeyProtection, SecureKey, SignerCapabilities};

extern "C" {
    /// Not re-exported by `security-framework-sys`, but a real exported symbol
    /// of Security.framework. Declared here rather than worked around, because
    /// the alternative — keying items by `kSecAttrLabel` — would collide with
    /// any other item in the keychain that happens to share a label.
    static kSecAttrApplicationTag: CFStringRef;
}

/// Namespace for `kSecAttrApplicationTag`, identical to the iOS plugin's.
///
/// Keys are namespaced so a key id of `device` cannot collide with an unrelated
/// keychain item, and the prefix is the same string the Swift side writes, so
/// the two implementations address the same items.
const TAG_PREFIX: &str = "app.vaam.signkeypair.";

/// X9.63 uncompressed point: `0x04 || X(32) || Y(32)`.
const UNCOMPRESSED_POINT_LENGTH: usize = 1 + 32 * 2;

/// `errSecItemNotFound`.
const ERR_SEC_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecUserCanceled` — the prompt was dismissed.
const ERR_SEC_USER_CANCELED: i32 = -128;
/// `errSecInteractionNotAllowed` — the item exists but cannot be used right now.
const ERR_SEC_INTERACTION_NOT_ALLOWED: i32 = -25308;
/// `errSecAuthFailed` — what the enclave returns for a key whose biometry set
/// has changed since creation.
const ERR_SEC_AUTH_FAILED: i32 = -25293;

pub(crate) struct SecureEnclaveBackend {
    /// Whether this machine's enclave accepted a throwaway probe key at startup.
    ///
    /// Probed once rather than per call: `SecKeyCreateRandomKey` against the
    /// enclave is not free, and a Mac does not grow a Secure Enclave mid-session.
    enclave_available: bool,
}

impl SecureEnclaveBackend {
    /// Decide whether this process can actually *store* a key in the
    /// data-protection keychain.
    ///
    /// Returns `None` when it cannot — almost always an unsigned binary, which
    /// cannot hold the `keychain-access-groups` entitlement and gets
    /// `errSecMissingEntitlement` (-34018). Declining here rather than failing
    /// later is deliberate: a backend that registers successfully and then
    /// errors on every call would make an unsigned `cargo run` look like a
    /// broken plugin, when the honest answer is "this build gets the software
    /// signer".
    ///
    /// The probe **writes**, and that is the whole point. An earlier version
    /// only did a lookup, which an unsigned binary is perfectly allowed to do —
    /// so the probe passed, the backend was selected, and every `generate_key`
    /// then failed with -34018. Reads and writes to this keychain have
    /// different entitlement requirements, so a probe has to exercise the one
    /// the backend depends on.
    pub(crate) fn probe() -> Option<Self> {
        let enclave = enclave_available();
        // Create under a reserved tag, then remove it. `enclave` is passed
        // through so the probe uses the same code path a real key will.
        let probe_id = "__probe_can_store__";
        let access = access_control(KeyProtection::Ambient, enclave).ok()?;
        let stored = create_key(probe_id, &access, enclave).is_ok();

        // Best effort: if the create failed there is nothing to remove, and if
        // the delete fails the leftover is a throwaway key under a reserved tag.
        let query = base_query(probe_id, &[]);
        unsafe { SecItemDelete(query.as_concrete_TypeRef()) };

        stored.then_some(Self {
            enclave_available: enclave,
        })
    }

    fn backing(&self) -> KeyBacking {
        if self.enclave_available {
            KeyBacking::SecureEnclave
        } else {
            KeyBacking::Keychain
        }
    }
}

impl Backend for SecureEnclaveBackend {
    fn capabilities(&self) -> crate::Result<SignerCapabilities> {
        Ok(SignerCapabilities::new("macos", self.backing()))
    }

    fn generate_key(
        &self,
        key_id: &str,
        require_hardware: bool,
        overwrite: bool,
        protection: KeyProtection,
    ) -> crate::Result<SecureKey> {
        // Capability checks FIRST, before anything destructive. `overwrite`
        // deletes the incumbent key below, so a rejection after that point would
        // leave the Mac with no credential at all — unable to authenticate and
        // unable to sign its way through re-enrolment.
        if require_hardware && !self.enclave_available {
            return Err(Error::new(
                SignerErrorCode::HardwareUnavailable,
                "This Mac has no Secure Enclave and requireHardware was set",
            ));
        }

        if find_key(key_id)?.is_some() {
            if !overwrite {
                return Err(Error::new(
                    SignerErrorCode::KeyAlreadyExists,
                    format!("A key already exists under \"{key_id}\""),
                ));
            }
            self.delete_key(key_id)?;
        }

        let access = access_control(protection, self.enclave_available)?;
        let key = create_key(key_id, &access, self.enclave_available)?;
        let jwk = public_jwk(key.as_ref())?;
        Ok(SecureKey::new(key_id, jwk, self.backing()))
    }

    fn get_key(&self, key_id: &str) -> crate::Result<Option<SecureKey>> {
        let Some(key) = find_key(key_id)? else {
            return Ok(None);
        };
        // Backing is read back from the key's own attributes rather than
        // inferred from how it was requested, so a silent fallback inside the
        // Security framework cannot be reported as enclave-backed.
        let backing = if is_enclave_key(key.as_ref()) {
            KeyBacking::SecureEnclave
        } else {
            KeyBacking::Keychain
        };
        Ok(Some(SecureKey::new(
            key_id,
            public_jwk(key.as_ref())?,
            backing,
        )))
    }

    fn sign(&self, key_id: &str, payload: &[u8], _reason: Option<&str>) -> crate::Result<Vec<u8>> {
        let key = find_key(key_id)?.ok_or_else(|| {
            Error::new(
                SignerErrorCode::KeyNotFound,
                format!("No key stored under \"{key_id}\""),
            )
        })?;
        let der = create_signature(key.as_ref(), payload)?;
        // The Security framework emits ASN.1 DER; JWS ES256 needs IEEE P1363.
        crate::asn1::der_to_p1363(&der)
    }

    fn delete_key(&self, key_id: &str) -> crate::Result<()> {
        let query = base_query(key_id, &[]);
        let status = unsafe { SecItemDelete(query.as_concrete_TypeRef()) };
        if status == 0 || status == ERR_SEC_ITEM_NOT_FOUND {
            Ok(())
        } else {
            Err(os_status_error(status, "SecItemDelete"))
        }
    }
}

// ---------------------------------------------------------------------------
// Security framework plumbing
// ---------------------------------------------------------------------------

/// An owned `SecKeyRef`, released on drop.
///
/// The Security framework's `Copy`/`Create` functions return +1 references. A
/// plain `SecKeyRef` would leak one per call, and a signing hot path leaks
/// forever.
struct OwnedKey(SecKeyRef);

impl OwnedKey {
    fn as_ref(&self) -> SecKeyRef {
        self.0
    }
}

impl Drop for OwnedKey {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0 as CFTypeRef) };
        }
    }
}

/// An owned `SecAccessControlRef`, released on drop.
struct OwnedAccessControl(SecAccessControlRef);

impl Drop for OwnedAccessControl {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0 as CFTypeRef) };
        }
    }
}

/// `app.vaam.signkeypair.<key_id>` as the bytes the keychain stores.
fn tag_data(key_id: &str) -> CFData {
    CFData::from_buffer(format!("{TAG_PREFIX}{key_id}").as_bytes())
}

/// The attributes that identify one of our keys, plus whatever `extra` adds.
///
/// Every query goes through here so `kSecUseDataProtectionKeychain` cannot be
/// forgotten on one of them — and forgetting it on a single query is enough to
/// make that query silently address a different keychain than the others.
fn base_query(key_id: &str, extra: &[(CFString, CFType)]) -> CFDictionary<CFString, CFType> {
    let mut pairs: Vec<(CFString, CFType)> = unsafe {
        vec![
            (
                CFString::wrap_under_get_rule(kSecClass),
                CFString::wrap_under_get_rule(kSecClassKey).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrApplicationTag),
                tag_data(key_id).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                CFBoolean::true_value().as_CFType(),
            ),
        ]
    };
    pairs.extend(extra.iter().cloned());
    CFDictionary::from_CFType_pairs(&pairs)
}

/// Look one of our keys up, returning `None` when it is simply not there.
fn find_key(key_id: &str) -> crate::Result<Option<OwnedKey>> {
    let query = unsafe {
        base_query(
            key_id,
            &[(
                CFString::wrap_under_get_rule(kSecReturnRef),
                CFBoolean::true_value().as_CFType(),
            )],
        )
    };

    let mut item: CFTypeRef = ptr::null();
    let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut item) };
    match status {
        0 if !item.is_null() => Ok(Some(OwnedKey(item as SecKeyRef))),
        0 => Ok(None),
        ERR_SEC_ITEM_NOT_FOUND => Ok(None),
        other => Err(os_status_error(other, "SecItemCopyMatching")),
    }
}

/// `SecAccessControlCreateFlags` for the two-key model.
///
/// `privateKeyUsage` is what makes an enclave key usable for signing at all, and
/// on its own prompts for nothing — that is the ambient key.
///
/// The user-present key adds `biometryCurrentSet | or | devicePasscode`: a Touch
/// ID fingerprint from the enrolment set that existed when the key was made, OR
/// the login password. `biometryCurrentSet` rather than `biometryAny` so a newly
/// enrolled fingerprint does not inherit this key's authority, and the password
/// branch because most Macs have no Touch ID at all.
///
/// The accessibility class differs by protection for the same reason as on iOS.
/// The ambient key must be readable while the screen is locked, because
/// background request signing continues there; the user-present key only ever
/// signs a deliberate action, so narrowing it to `WhenUnlocked` costs nothing
/// and removes a class of attack on a locked-but-awake machine. `ThisDeviceOnly`
/// on both keeps the key out of iCloud Keychain, so a device-bound credential
/// stays bound to *this* Mac.
fn access_control(
    protection: KeyProtection,
    use_enclave: bool,
) -> crate::Result<OwnedAccessControl> {
    unsafe {
        let protection_class = if protection.requires_user_presence() {
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        } else {
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        };

        let mut flags = if use_enclave {
            kSecAccessControlPrivateKeyUsage
        } else {
            0
        };
        if protection.requires_user_presence() {
            flags |= kSecAccessControlBiometryCurrentSet
                | kSecAccessControlOr
                | kSecAccessControlDevicePasscode;
        }

        let mut error: CFErrorRef = ptr::null_mut();
        let access = SecAccessControlCreateWithFlags(
            ptr::null(),
            protection_class as CFTypeRef,
            flags,
            &mut error,
        );
        if access.is_null() {
            return Err(cf_error(error, "SecAccessControlCreateWithFlags"));
        }
        Ok(OwnedAccessControl(access))
    }
}

/// Generate the key, inside the enclave when there is one.
fn create_key(
    key_id: &str,
    access: &OwnedAccessControl,
    use_enclave: bool,
) -> crate::Result<OwnedKey> {
    unsafe {
        let private_attrs = CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrIsPermanent),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrApplicationTag),
                tag_data(key_id).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccessControl),
                CFType::wrap_under_get_rule(access.0 as CFTypeRef),
            ),
        ]);

        let mut pairs: Vec<(CFString, CFType)> = vec![
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                CFNumber::from(256).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                CFBoolean::true_value().as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecPrivateKeyAttrs),
                private_attrs.as_CFType(),
            ),
        ];
        if use_enclave {
            pairs.push((
                CFString::wrap_under_get_rule(kSecAttrTokenID),
                CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType(),
            ));
        }
        let attributes = CFDictionary::from_CFType_pairs(&pairs);

        let mut error: CFErrorRef = ptr::null_mut();
        let key = SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut error);
        if key.is_null() {
            return Err(cf_error(error, "SecKeyCreateRandomKey"));
        }
        Ok(OwnedKey(key))
    }
}

/// Whether a live key is actually held by the Secure Enclave.
fn is_enclave_key(key: SecKeyRef) -> bool {
    unsafe {
        let attrs = SecKeyCopyAttributes(key);
        if attrs.is_null() {
            return false;
        }
        let attrs: CFDictionary<CFString, CFType> = CFDictionary::wrap_under_create_rule(attrs);
        attrs
            .find(CFString::wrap_under_get_rule(kSecAttrTokenID))
            .and_then(|v| v.downcast::<CFString>())
            .map(|t| t == CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave))
            .unwrap_or(false)
    }
}

/// Probe the enclave by creating and immediately discarding a non-permanent key.
///
/// `LAContext.canEvaluatePolicy` is not a valid proxy: it reports biometric
/// enrolment, not enclave presence, and the two diverge on a Mac with no Touch
/// ID but a T2 chip.
fn enclave_available() -> bool {
    unsafe {
        let mut error: CFErrorRef = ptr::null_mut();
        let access = SecAccessControlCreateWithFlags(
            ptr::null(),
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly as CFTypeRef,
            kSecAccessControlPrivateKeyUsage,
            &mut error,
        );
        if access.is_null() {
            return false;
        }
        let access = OwnedAccessControl(access);

        let private_attrs = CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrIsPermanent),
                CFBoolean::false_value().as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrAccessControl),
                CFType::wrap_under_get_rule(access.0 as CFTypeRef),
            ),
        ]);
        let attributes = CFDictionary::from_CFType_pairs(&[
            (
                CFString::wrap_under_get_rule(kSecAttrKeyType),
                CFString::wrap_under_get_rule(kSecAttrKeyTypeECSECPrimeRandom).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrKeySizeInBits),
                CFNumber::from(256).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrTokenID),
                CFString::wrap_under_get_rule(kSecAttrTokenIDSecureEnclave).as_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecPrivateKeyAttrs),
                private_attrs.as_CFType(),
            ),
        ]);

        let mut error: CFErrorRef = ptr::null_mut();
        let key = SecKeyCreateRandomKey(attributes.as_concrete_TypeRef(), &mut error);
        if key.is_null() {
            if !error.is_null() {
                CFRelease(error as CFTypeRef);
            }
            return false;
        }
        let key = OwnedKey(key);
        is_enclave_key(key.as_ref())
    }
}

/// The public half, as an RFC 7517 JWK.
fn public_jwk(key: SecKeyRef) -> crate::Result<EcPublicJwk> {
    unsafe {
        let public = SecKeyCopyPublicKey(key);
        if public.is_null() {
            return Err(Error::new(
                SignerErrorCode::KeystoreFailure,
                "Could not derive the public key",
            ));
        }
        let public = OwnedKey(public);

        let mut error: CFErrorRef = ptr::null_mut();
        let data = SecKeyCopyExternalRepresentation(public.as_ref(), &mut error);
        if data.is_null() {
            return Err(cf_error(error, "SecKeyCopyExternalRepresentation"));
        }
        let data = CFData::wrap_under_create_rule(data);
        let raw = data.bytes();

        // X9.63 uncompressed point: 0x04 || X (32) || Y (32).
        if raw.len() != UNCOMPRESSED_POINT_LENGTH || raw[0] != 0x04 {
            return Err(Error::new(
                SignerErrorCode::KeystoreFailure,
                format!("Unexpected public key encoding ({} bytes)", raw.len()),
            ));
        }
        Ok(EcPublicJwk::new(
            crate::b64::encode(&raw[1..33]),
            crate::b64::encode(&raw[33..65]),
        ))
    }
}

/// Sign inside the secure element, prompting when the key's access control says so.
fn create_signature(key: SecKeyRef, payload: &[u8]) -> crate::Result<Vec<u8>> {
    unsafe {
        let data = CFData::from_buffer(payload);
        let mut error: CFErrorRef = ptr::null_mut();
        // `...MessageX962SHA256` digests the message for us, matching
        // java.security's "SHA256withECDSA" and p256's `Signer` impl.
        let signature = SecKeyCreateSignature(
            key,
            kSecKeyAlgorithmECDSASignatureMessageX962SHA256,
            data.as_concrete_TypeRef(),
            &mut error,
        );
        if signature.is_null() {
            return Err(signing_error(error));
        }
        Ok(CFData::wrap_under_create_rule(signature).bytes().to_vec())
    }
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

/// Turn a `CFErrorRef` into a typed error, releasing it.
fn cf_error(error: CFErrorRef, what: &str) -> Error {
    let code = unsafe {
        if error.is_null() {
            0
        } else {
            let c = core_foundation_sys::error::CFErrorGetCode(error);
            CFRelease(error as CFTypeRef);
            c as i32
        }
    };
    Error::new(
        SignerErrorCode::KeystoreFailure,
        format!("{what} failed with status {code}"),
    )
}

/// Map a signing failure onto a code the frontend can act on.
///
/// The distinction that earns its keep is cancelled-versus-anything-else: a
/// dismissed prompt is someone changing their mind at a confirmation screen, and
/// treating it as an auth failure would trigger re-enrolment for a routine
/// interaction.
fn signing_error(error: CFErrorRef) -> Error {
    let code = unsafe {
        if error.is_null() {
            0
        } else {
            let c = core_foundation_sys::error::CFErrorGetCode(error);
            CFRelease(error as CFTypeRef);
            c as i32
        }
    };
    match code {
        ERR_SEC_USER_CANCELED => Error::new(
            SignerErrorCode::UserAuthenticationCancelled,
            "The authentication prompt was dismissed",
        ),
        ERR_SEC_INTERACTION_NOT_ALLOWED => Error::new(
            SignerErrorCode::UserAuthenticationRequired,
            "This key requires user presence and cannot be used from the background",
        ),
        ERR_SEC_AUTH_FAILED => Error::new(
            // `biometryCurrentSet` firing as designed: the Touch ID enrolment
            // changed, so this key is gone. Recovery is narrow — generate a
            // fresh user-present key and register its thumbprint. The ambient
            // key is untouched.
            SignerErrorCode::KeyInvalidated,
            "The key was invalidated by a change to this Mac's Touch ID enrolment or password",
        ),
        other => Error::new(
            SignerErrorCode::KeystoreFailure,
            format!("SecKeyCreateSignature failed with status {other}"),
        ),
    }
}

/// Wrap an `OSStatus` so the numeric code survives into the message.
fn os_status_error(status: i32, what: &str) -> Error {
    Error::new(
        SignerErrorCode::KeystoreFailure,
        format!("{what} failed with status {status}"),
    )
}
