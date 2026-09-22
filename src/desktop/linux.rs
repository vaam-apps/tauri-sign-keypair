//! TPM 2.0 backend for Linux, over the TSS Enhanced System API.
//!
//! # ⚠️ This module has never been compiled or run
//!
//! It is behind the **off-by-default** `linux-tpm` feature, and that gating is
//! not optional: `tss-esapi` links the `tpm2-tss` C libraries, so enabling it by
//! default would break `cargo build` for every Linux consumer without
//! `libtss2-dev` installed.
//!
//! It was written against the real `tss-esapi` 7.7 API — every signature here
//! was read out of the crate's source rather than recalled — but the build
//! machine had no way to verify it: `tpm2-tss` has no Homebrew formula, and the
//! Tauri Linux target cannot be cross-checked from macOS because its GTK/WebKit
//! dependencies are unresolvable for a foreign target. **Treat this as a
//! reviewed draft, not as working code**, and see `docs/07-linux-tpm.md` for the
//! validation steps (swtpm first, then real hardware) before trusting it.
//!
//! Nothing reaches this module unless somebody opts in, so an unverified draft
//! cannot affect a default build.
//!
//! # How a TPM key differs from every other backend here
//!
//! AndroidKeyStore, the Apple keychain and Windows CNG all store a key *under a
//! name* and hand you a handle when you ask for that name. A TPM does not work
//! that way:
//!
//! * A key is created **under a parent**, and comes back as a public blob plus
//!   an *encrypted* private blob. The private blob is ciphertext that only this
//!   TPM's parent key can decrypt — it is useless on any other machine, which is
//!   what makes it safe to keep on ordinary disk.
//! * Persisting a key *inside* the TPM (`EvictControl`) consumes NV storage,
//!   of which typical hardware has a few dozen slots. A library that persisted
//!   one slot per key would exhaust it, so the blobs go in the app data
//!   directory and the parent is re-derived on each use.
//! * The parent is re-created deterministically with `CreatePrimary` from the
//!   owner hierarchy. Same TPM and same template gives the same parent every
//!   time, so a blob sealed today loads tomorrow.
//!
//! # What it reports, and what it refuses
//!
//! Backing is `tee`, for the same reason as Windows: a TPM is a discrete chip,
//! but `strongbox` means *Android StrongBox* in this plugin's vocabulary, and a
//! fourth hardware tag would have to be learned by four languages' wire
//! mappings for a distinction no caller acts on.
//!
//! `KeyProtection::UserPresent` is **refused**. A TPM can demand an auth value
//! per use, but there is no OS-level prompt and no binding to a biometric
//! enrolment, so the property that key exists to carry does not hold — the same
//! reasoning as the Windows backend.

use std::path::PathBuf;
use std::str::FromStr;

use sha2::{Digest as _, Sha256};
use tss_esapi::attributes::ObjectAttributesBuilder;
use tss_esapi::handles::KeyHandle;
use tss_esapi::interface_types::algorithm::{HashingAlgorithm, PublicAlgorithm};
use tss_esapi::interface_types::ecc::EccCurve;
use tss_esapi::interface_types::resource_handles::Hierarchy;
use tss_esapi::constants::tss::{TPM2_RH_NULL, TPM2_ST_HASHCHECK};
use tss_esapi::structures::{
    Digest, EccPoint, EccScheme, HashScheme, HashcheckTicket, Private, Public, PublicBuilder,
    PublicEccParametersBuilder, Signature, SignatureScheme, SymmetricDefinitionObject,
};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

use crate::desktop::Backend;
use crate::error::{Error, SignerErrorCode};
use crate::models::{EcPublicJwk, KeyBacking, KeyProtection, SecureKey, SignerCapabilities};

/// Bytes in one P-256 coordinate.
const COORDINATE_LENGTH: usize = 32;

pub(crate) struct TpmBackend {
    /// Where the public/private blob pairs live. One file per key, for the same
    /// reason the software backend uses one file per key: a single map file
    /// makes every write a read-modify-write, and two app instances race.
    directory: PathBuf,
}

/// What we persist per key. Both halves are required to `Load` the key back,
/// and neither is secret in the usual sense — the private blob is ciphertext
/// bound to this TPM.
#[derive(serde::Serialize, serde::Deserialize)]
struct KeyBlobs {
    /// TPM2B_PUBLIC, marshalled.
    public: String,
    /// TPM2B_PRIVATE, marshalled — encrypted to this TPM's parent key.
    private: String,
}

impl TpmBackend {
    /// Open the TPM and prove we can actually create a key in it.
    ///
    /// Like the macOS and Windows probes, this **creates** rather than merely
    /// opening the device. `/dev/tpmrm0` opens fine on machines whose TPM then
    /// refuses key creation — owner authorisation set, hierarchy disabled,
    /// resource manager unavailable — and a probe that only opened it would
    /// select this backend and fail every call.
    ///
    /// Returns `None` on any failure, including the most common one by far:
    /// `/dev/tpmrm0` is typically `root:tss` mode 0660, so a desktop app whose
    /// user is not in the `tss` group cannot open it at all.
    pub(crate) fn probe(directory: PathBuf) -> Option<Self> {
        let mut context = open_context().ok()?;
        let primary = create_primary(&mut context).ok()?;
        let created = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(
                    primary,
                    signing_key_template().ok()?,
                    None,
                    None,
                    None,
                    None,
                )
                .ok()
            })
            .flatten()
            .is_some();
        let _ = context.flush_context(primary.into());
        created.then_some(Self { directory })
    }

    fn path_for(&self, key_id: &str) -> PathBuf {
        // base64url of the key id, not the id itself: the caller chooses it, and
        // one containing `/` or `..` would otherwise name a path outside the
        // store.
        self.directory
            .join(format!("{}.tpm.json", crate::b64::encode(key_id)))
    }

    fn read(&self, key_id: &str) -> crate::Result<Option<KeyBlobs>> {
        match std::fs::read(self.path_for(key_id)) {
            Ok(bytes) => serde_json::from_slice(&bytes).map(Some).map_err(|e| {
                keystore(format!(
                    "The stored blobs for \"{key_id}\" are unreadable: {e}"
                ))
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(keystore(format!("Could not read \"{key_id}\": {e}"))),
        }
    }

    /// Load a stored key back into the TPM, returning its transient handle.
    ///
    /// The caller **must** `flush_context` the result. A TPM has room for only a
    /// handful of transient objects, and leaking them wedges it for every other
    /// process on the machine until reboot.
    fn load(&self, context: &mut Context, key_id: &str) -> crate::Result<(KeyHandle, KeyHandle)> {
        let blobs = self.read(key_id)?.ok_or_else(|| {
            Error::new(
                SignerErrorCode::KeyNotFound,
                format!("No key stored under \"{key_id}\""),
            )
        })?;

        let public: Public = unmarshal(&blobs.public)?;
        let private = decode_private(&blobs.private)?;
        let primary = create_primary(context)?;
        let key = context
            .execute_with_nullauth_session(|ctx| ctx.load(primary, private, public))
            .map_err(|e| keystore(format!("TPM2_Load failed for \"{key_id}\": {e}")))?;
        Ok((key, primary))
    }
}

impl Backend for TpmBackend {
    fn capabilities(&self) -> crate::Result<SignerCapabilities> {
        Ok(SignerCapabilities::new(
            "linux-tpm",
            KeyBacking::TrustedExecutionEnvironment,
        ))
    }

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
                "A TPM cannot bind a key to a biometric enrolment, and Linux has no \
                 OS-level presence prompt — user-present operations are not supported \
                 on this platform.",
            ));
        }
        // `require_hardware` needs no check: reaching this backend means the
        // probe created a key in the TPM, so hardware is what you get.

        if !overwrite && self.read(key_id)?.is_some() {
            return Err(Error::new(
                SignerErrorCode::KeyAlreadyExists,
                format!("A key already exists under \"{key_id}\""),
            ));
        }

        let mut context = open_context()?;
        let template = signing_key_template()
            .map_err(|e| keystore(format!("Could not build the key template: {e}")))?;
        let primary = create_primary(&mut context)?;
        let result = context
            .execute_with_nullauth_session(|ctx| {
                ctx.create(primary, template, None, None, None, None)
            })
            .map_err(|e| keystore(format!("TPM2_Create failed: {e}")));
        let _ = context.flush_context(primary.into());
        let result = result?;

        let jwk = jwk_from_public(&result.out_public)?;
        let blobs = KeyBlobs {
            public: marshal(&result.out_public)?,
            private: encode_private(&result.out_private),
        };

        std::fs::create_dir_all(&self.directory).map_err(|e| {
            keystore(format!(
                "Could not create {}: {e}",
                self.directory.display()
            ))
        })?;
        let path = self.path_for(key_id);
        let json = serde_json::to_vec(&blobs)
            .map_err(|e| keystore(format!("Could not serialize the blobs: {e}")))?;
        std::fs::write(&path, json)
            .map_err(|e| keystore(format!("Could not write {}: {e}", path.display())))?;
        // Owner-only. The private blob is ciphertext bound to this TPM, so this
        // is defence in depth rather than the thing keeping the key secret.
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(SecureKey::new(
            key_id,
            jwk,
            KeyBacking::TrustedExecutionEnvironment,
        ))
    }

    fn get_key(&self, key_id: &str) -> crate::Result<Option<SecureKey>> {
        let Some(blobs) = self.read(key_id)? else {
            return Ok(None);
        };
        let public: Public = unmarshal(&blobs.public)?;
        Ok(Some(SecureKey::new(
            key_id,
            jwk_from_public(&public)?,
            KeyBacking::TrustedExecutionEnvironment,
        )))
    }

    /// Sign `payload`, returning IEEE P1363 `r‖s`.
    ///
    /// `reason` is accepted and ignored: this backend never holds a user-present
    /// key, so there is no prompt to caption.
    fn sign(&self, key_id: &str, payload: &[u8], _reason: Option<&str>) -> crate::Result<Vec<u8>> {
        let mut context = open_context()?;
        let (key, primary) = self.load(&mut context, key_id)?;

        // TPM2_Sign takes a digest, not a message — like Windows CNG and unlike
        // Apple's `.ecdsaSignatureMessageX962SHA256`. Hashing here rather than
        // in the TPM also avoids its restriction on signing digests it produced
        // itself.
        let digest = Digest::try_from(Sha256::digest(payload).to_vec())
            .map_err(|e| keystore(format!("Could not wrap the SHA-256 digest: {e}")))?;

        let signature = context
            .execute_with_nullauth_session(|ctx| {
                ctx.sign(
                    key,
                    digest,
                    SignatureScheme::EcDsa {
                        hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                    },
                    // A null ticket: the digest was computed outside the TPM, so
                    // there is no proof-of-origin ticket to present.
                    tss_esapi::structures::HashcheckTicket::try_from(
                        tss_esapi::tss2_esys::TPMT_TK_HASHCHECK {
                            tag: tss_esapi::constants::tss::TPM2_ST_HASHCHECK,
                            hierarchy: tss_esapi::constants::tss::TPM2_RH_NULL,
                            digest: Default::default(),
                        },
                    )
                    .map_err(|_| {
                        tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam)
                    })?,
                )
            })
            .map_err(|e| keystore(format!("TPM2_Sign failed: {e}")));

        let _ = context.flush_context(key.into());
        let _ = context.flush_context(primary.into());
        let signature = signature?;

        // The TPM returns r and s as separate, minimally-encoded parameters, so
        // each must be left-padded to 32 bytes exactly as the DER paths do. Get
        // this wrong and you have a valid ECDSA signature that a JWS verifier
        // rejects roughly 1 time in 256.
        match signature {
            Signature::EcDsa(ecc) => {
                let mut out = Vec::with_capacity(COORDINATE_LENGTH * 2);
                out.extend_from_slice(&left_pad(ecc.signature_r().as_ref())?);
                out.extend_from_slice(&left_pad(ecc.signature_s().as_ref())?);
                Ok(out)
            }
            other => Err(keystore(format!(
                "Expected an ECDSA signature, got {other:?}"
            ))),
        }
    }

    fn delete_key(&self, key_id: &str) -> crate::Result<()> {
        // Only the blobs are removed. Nothing is persisted inside the TPM, so
        // there is no NV slot to evict — which is the upside of keeping the
        // blobs on disk.
        match std::fs::remove_file(self.path_for(key_id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(keystore(format!("Could not delete \"{key_id}\": {e}"))),
        }
    }
}

// ---------------------------------------------------------------------------
// TPM plumbing
// ---------------------------------------------------------------------------

fn keystore(message: String) -> Error {
    Error::new(SignerErrorCode::KeystoreFailure, message)
}

/// Connect through the kernel resource manager.
///
/// `/dev/tpmrm0` rather than `/dev/tpm0`: the raw device allows one client at a
/// time, so using it would make this plugin fight every other TPM consumer on
/// the machine. `TCTI` in the environment overrides this for a simulator.
fn open_context() -> crate::Result<Context> {
    let tcti = std::env::var("TCTI")
        .ok()
        .and_then(|v| TctiNameConf::from_str(&v).ok())
        .unwrap_or(TctiNameConf::Device(Default::default()));
    Context::new(tcti).map_err(|e| {
        Error::new(
            SignerErrorCode::HardwareUnavailable,
            format!("Could not open the TPM: {e}"),
        )
    })
}

/// The storage parent, re-derived deterministically on every use.
///
/// Same TPM plus same template gives the same key every time, which is what
/// lets a blob written today load tomorrow without occupying an NV slot.
fn create_primary(context: &mut Context) -> crate::Result<KeyHandle> {
    let template = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(
            ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_restricted(true)
                .with_decrypt(true)
                .build()
                .map_err(|e| keystore(format!("Could not build the parent attributes: {e}")))?,
        )
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_restricted_decryption_key(
                SymmetricDefinitionObject::AES_128_CFB,
                EccCurve::NistP256,
            )
            .build()
            .map_err(|e| keystore(format!("Could not build the parent parameters: {e}")))?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|e| keystore(format!("Could not build the parent template: {e}")))?;

    context
        .execute_with_nullauth_session(|ctx| {
            ctx.create_primary(Hierarchy::Owner, template, None, None, None, None)
        })
        .map(|r| r.key_handle)
        .map_err(|e| keystore(format!("TPM2_CreatePrimary failed: {e}")))
}

/// The template for the signing keys this plugin issues.
///
/// `fixed_tpm` and `fixed_parent` are what make the key non-migratable. Without
/// them it could be duplicated onto another TPM, and reporting `tee` for
/// something duplicable would be exactly the false claim this plugin exists to
/// avoid.
fn signing_key_template() -> tss_esapi::Result<Public> {
    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(
            ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(true)
                .with_sign_encrypt(true)
                .build()?,
        )
        .with_ecc_parameters(
            PublicEccParametersBuilder::new_unrestricted_signing_key(
                EccScheme::EcDsa(HashScheme::new(HashingAlgorithm::Sha256)),
                EccCurve::NistP256,
            )
            .build()?,
        )
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
}

/// Pull the affine coordinates out of a `Public` and build the JWK.
fn jwk_from_public(public: &Public) -> crate::Result<EcPublicJwk> {
    match public {
        Public::Ecc { unique, .. } => Ok(EcPublicJwk::new(
            crate::b64::encode(left_pad(unique.x().as_ref())?),
            crate::b64::encode(left_pad(unique.y().as_ref())?),
        )),
        _ => Err(keystore("The stored key is not an ECC key".into())),
    }
}

/// Left-pad a minimally-encoded TPM parameter to exactly 32 bytes.
///
/// The TPM strips leading zeros, so a coordinate or signature component whose
/// top byte is zero comes back short — the same ~1-in-256 hazard the DER paths
/// have, arriving by a different route.
fn left_pad(value: &[u8]) -> crate::Result<[u8; COORDINATE_LENGTH]> {
    if value.len() > COORDINATE_LENGTH {
        return Err(keystore(format!(
            "Expected at most {COORDINATE_LENGTH} bytes, got {}",
            value.len()
        )));
    }
    let mut out = [0u8; COORDINATE_LENGTH];
    out[COORDINATE_LENGTH - value.len()..].copy_from_slice(value);
    Ok(out)
}

/// Marshal a TPM structure to base64url for storage.
fn marshal<T: tss_esapi::traits::Marshall>(value: &T) -> crate::Result<String> {
    value
        .marshall()
        .map(crate::b64::encode)
        .map_err(|e| keystore(format!("Could not marshal a TPM structure: {e}")))
}

/// The inverse of [`marshal`].
fn unmarshal<T: tss_esapi::traits::UnMarshall>(encoded: &str) -> crate::Result<T> {
    let bytes = crate::b64::decode(encoded)?;
    T::unmarshall(&bytes).map_err(|e| keystore(format!("Could not unmarshal a TPM structure: {e}")))
}
