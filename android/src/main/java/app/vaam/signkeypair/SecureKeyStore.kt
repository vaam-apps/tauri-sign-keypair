package app.vaam.signkeypair

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import android.util.Base64

/**
 * All AndroidKeyStore interaction, with no Tauri dependency.
 *
 * Split out of [SignKeypairPlugin] so the instrumented tests can drive **the
 * production code path** rather than a copy of its `KeyGenParameterSpec`. That
 * distinction matters: a test that rebuilds the spec itself would keep passing
 * if the real spec drifted to something exportable, which is precisely the
 * regression the tests exist to catch.
 *
 * The security property this class provides: the private key is generated
 * inside the keystore and never leaves it. [KeyStore.getKey] returns an opaque
 * [PrivateKey] whose `encoded` is null, and signing happens in the TEE (or
 * StrongBox). Nothing here can return private key material — there is no method
 * that could.
 *
 * @param strongBoxAvailable whether the device advertises
 *   `FEATURE_STRONGBOX_KEYSTORE`. Injected rather than read from a
 *   `PackageManager` so this class needs no Android `Context`.
 * @param userAuthenticationAvailable whether the device has a secure lock screen
 *   or an enrolled biometric — anything the keystore would accept as proof a
 *   human is present. Injected for the same reason: answering it needs a
 *   `KeyguardManager`, and taking a `Context` here would put this class back out
 *   of reach of the instrumented tests that drive the production spec.
 */
internal class SecureKeyStore(
    private val strongBoxAvailable: Boolean,
    private val userAuthenticationAvailable: () -> Boolean,
) {

    /** A public key plus where its private half lives. Never carries the scalar. */
    data class Description(
        val keyId: String,
        val x: String,
        val y: String,
        val backing: KeyBacking,
    )

    /**
     * The strongest backing this device offers, probed without leaving a key behind.
     *
     * StrongBox presence is a package feature flag, so it can be read directly.
     * TEE presence cannot: it depends on the keymaster implementation, so the
     * only honest probe is to generate a throwaway key and read its [KeyInfo].
     */
    fun bestAvailableBacking(): KeyBacking {
        if (strongBoxAvailable) return KeyBacking.STRONGBOX
        val probeAlias = "$PROBE_ALIAS_PREFIX${System.nanoTime()}"
        return try {
            createKeyPair(probeAlias, useStrongBox = false, protection = KeyProtection.AMBIENT)
            backingOf(probeAlias)
        } catch (e: Exception) {
            KeyBacking.SOFTWARE
        } finally {
            runCatching { keyStore().deleteEntry(probeAlias) }
        }
    }

    fun generateKey(
        keyId: String,
        requireHardware: Boolean,
        overwrite: Boolean,
        protection: KeyProtection,
    ): Description {
        val store = keyStore()

        // Capability checks FIRST, before anything destructive.
        //
        // `overwrite = true` deletes the incumbent key before generating, so a
        // rejection after that point would leave the device with no credential
        // at all — unable to authenticate and unable to sign its way through
        // re-enrolment. That is a far worse outcome than the failure the caller
        // asked for. The probe below uses a throwaway alias, so it costs nothing
        // but a keygen.
        if (requireHardware && !bestAvailableBacking().isHardwareBacked) {
            throw SignerError(
                SignerErrorCode.HARDWARE_UNAVAILABLE,
                "This device has no secure element and requireHardware was set",
            )
        }

        // `setUserAuthenticationRequired(true)` makes keygen itself throw when
        // the device has no secure lock screen. Checking here rather than
        // catching there keeps the failure ahead of the delete below, and lets
        // the caller distinguish "set a screen lock" (the user can fix this in
        // Settings) from "no secure element" (they cannot).
        if (protection.requiresUserPresence && !userAuthenticationAvailable()) {
            throw SignerError(
                SignerErrorCode.USER_AUTHENTICATION_REQUIRED,
                "A user-present key needs a screen lock or an enrolled biometric, " +
                    "and this device has neither",
            )
        }

        if (store.containsAlias(keyId)) {
            if (!overwrite) {
                throw SignerError(
                    SignerErrorCode.KEY_ALREADY_EXISTS,
                    "A key already exists under \"$keyId\"",
                )
            }
            store.deleteEntry(keyId)
        }

        // StrongBox first, then TEE. A device can advertise the StrongBox
        // feature and still refuse a given spec, so the fallback hangs off the
        // exception, not off the feature flag alone.
        if (strongBoxAvailable) {
            try {
                createKeyPair(keyId, useStrongBox = true, protection = protection)
            } catch (e: StrongBoxUnavailableException) {
                runCatching { store.deleteEntry(keyId) }
                createKeyPair(keyId, useStrongBox = false, protection = protection)
            }
        } else {
            createKeyPair(keyId, useStrongBox = false, protection = protection)
        }

        val backing = backingOf(keyId)
        // Second line of defence: the pre-check above says the device CAN do
        // hardware, but a keymaster may still refuse this particular spec. Fail
        // loudly rather than hand back a software key to a caller that asked for
        // hardware — silently degrading would be worse than an error, because
        // the caller would log "hardware-backed" for a key that is not.
        //
        // Residual risk, stated plainly: reaching here with overwrite = true
        // means the incumbent key is already gone. AndroidKeyStore cannot rename
        // an alias, so generate-then-swap is not available; this path is narrow
        // (device advertises hardware, then refuses) and the pre-check covers
        // the common case.
        if (requireHardware && !backing.isHardwareBacked) {
            runCatching { store.deleteEntry(keyId) }
            throw SignerError(
                SignerErrorCode.HARDWARE_UNAVAILABLE,
                "This device produced a software-backed key and requireHardware was set",
            )
        }

        return describeKey(keyId)
            ?: throw SignerError(
                SignerErrorCode.KEYSTORE_FAILURE,
                "Key vanished immediately after creation",
            )
    }

    fun describeKey(keyId: String): Description? {
        val store = keyStore()
        if (!store.containsAlias(keyId)) return null
        val certificate = store.getCertificate(keyId) ?: return null
        val publicKey = certificate.publicKey as? ECPublicKey
            ?: throw SignerError(SignerErrorCode.KEYSTORE_FAILURE, "Stored key is not an EC key")

        val point = publicKey.w
        return Description(
            keyId = keyId,
            x = base64Url(EcdsaSignatureCodec.coordinateBytes(point.affineX)),
            y = base64Url(EcdsaSignatureCodec.coordinateBytes(point.affineY)),
            backing = backingOf(keyId),
        )
    }

    /**
     * Sign [payload] with the key at [keyId], inside the secure element.
     *
     * The scalar is never materialised here: `initSign` takes the opaque
     * keystore handle and the keymaster does the arithmetic.
     *
     * Only valid for an ambient key. On a user-present key `sign()` throws
     * `UserNotAuthenticatedException`, because the keymaster wants an operation
     * that BiometricPrompt has authorised — see [beginSign].
     */
    fun sign(keyId: String, payload: ByteArray): ByteArray =
        finishSign(beginSign(keyId), payload)

    /**
     * Start a signing operation, returning the initialised [Signature] so a
     * caller can hand it to `BiometricPrompt.CryptoObject`.
     *
     * This is the split that user-present keys force. For an ambient key,
     * `initSign` + `sign` in one breath is fine. For a key created with
     * `setUserAuthenticationRequired(true)` and a zero timeout, the keymaster
     * authorises **this specific operation**, and only once BiometricPrompt has
     * reported success against it — so the operation has to exist, be carried
     * through the prompt, and come back to be finished.
     */
    fun beginSign(keyId: String): Signature {
        val privateKey = keyStore().getKey(keyId, null) as? PrivateKey
            ?: throw SignerError(SignerErrorCode.KEY_NOT_FOUND, "No key stored under \"$keyId\"")

        return Signature.getInstance(SIGNATURE_ALGORITHM).apply {
            try {
                initSign(privateKey)
            } catch (e: KeyPermanentlyInvalidatedException) {
                // The biometric-invalidation flag firing as designed: a
                // biometric was re-enrolled and the keymaster destroyed this
                // key. Reported distinctly because the recovery is narrow —
                // generate a fresh user-present key and register its thumbprint.
                // The ambient key is untouched, so the device can still
                // authenticate itself while doing so, and treating this as a
                // generic keystore failure would send the user through a full
                // re-enrolment ceremony for nothing.
                throw SignerError(
                    SignerErrorCode.KEY_INVALIDATED,
                    "The key under \"$keyId\" was invalidated by a change to this " +
                        "device's biometric enrolment or screen lock",
                )
            }
        }
    }

    /**
     * Complete an operation begun by [beginSign], after any prompt has passed.
     *
     * [payload] is fed in here rather than before the prompt so the bytes being
     * signed are the ones the caller supplied at completion time.
     */
    fun finishSign(signature: Signature, payload: ByteArray): ByteArray {
        signature.update(payload)
        // java.security emits ASN.1 DER; JWS ES256 needs IEEE P1363 r‖s.
        return EcdsaSignatureCodec.derToP1363(signature.sign())
    }

    /**
     * Whether the key at [keyId] will demand authentication before it signs.
     *
     * Read back from the keystore's own [KeyInfo] rather than inferred from the
     * alias or from what the caller once asked for — the same discipline
     * [backingOf] follows, and for the same reason: the plugin decides whether
     * to raise a biometric prompt on the strength of this answer, and an
     * inferred one would eventually be wrong about a key created by an older
     * build.
     */
    fun requiresUserAuthentication(keyId: String): Boolean {
        val privateKey = keyStore().getKey(keyId, null) as? PrivateKey
            ?: throw SignerError(SignerErrorCode.KEY_NOT_FOUND, "No key stored under \"$keyId\"")
        val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
        return factory.getKeySpec(privateKey, KeyInfo::class.java).isUserAuthenticationRequired
    }

    fun deleteKey(keyId: String) {
        val store = keyStore()
        if (store.containsAlias(keyId)) store.deleteEntry(keyId)
    }

    /**
     * The keystore handle for [keyId], for tests that need to assert on the key
     * object itself (notably that `encoded` is null).
     *
     * This returns an opaque handle, not key material — there is no API on
     * AndroidKeyStore that would return the scalar.
     */
    fun privateKeyHandle(keyId: String): PrivateKey? =
        keyStore().getKey(keyId, null) as? PrivateKey

    /**
     * Where a key actually lives, per the keystore itself.
     *
     * On API 31+ `securityLevel` distinguishes StrongBox from TEE explicitly.
     * Below that, `isInsideSecureHardware` only answers yes/no — so a pre-31
     * hardware key is reported as TEE, which understates StrongBox rather than
     * overstating anything.
     */
    fun backingOf(keyId: String): KeyBacking {
        val privateKey = keyStore().getKey(keyId, null) as? PrivateKey ?: return KeyBacking.SOFTWARE
        val factory = KeyFactory.getInstance(privateKey.algorithm, ANDROID_KEYSTORE)
        val info = factory.getKeySpec(privateKey, KeyInfo::class.java)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            return when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeyBacking.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeyBacking.TEE
                // SECURITY_LEVEL_UNKNOWN_SECURE means "secure, but the keystore
                // will not say which" — still non-extractable, so TEE is the
                // conservative truthful answer.
                KeyProperties.SECURITY_LEVEL_UNKNOWN_SECURE -> KeyBacking.TEE
                else -> KeyBacking.SOFTWARE
            }
        }

        @Suppress("DEPRECATION")
        return if (info.isInsideSecureHardware) KeyBacking.TEE else KeyBacking.SOFTWARE
    }

    /**
     * The one place a key is created.
     *
     * [KeyProtection.AMBIENT] carries no authentication binding, deliberately:
     * this is the key a request interceptor signs every call with, and requests
     * are generated by background timers in contexts where no prompt can be
     * displayed at all.
     *
     * [KeyProtection.USER_PRESENT] binds three things:
     *
     *  - `setUserAuthenticationRequired(true)` — the keymaster refuses to sign
     *    until BiometricPrompt authorises the operation. This is categorically
     *    stronger than an app-lock screen, which only decides whether to draw
     *    some UI and which anything running in-process walks straight past.
     *  - a **zero** timeout with `AUTH_BIOMETRIC_STRONG or AUTH_DEVICE_CREDENTIAL`
     *    — per-operation authorisation, with the device credential accepted
     *    alongside biometrics because a meaningful share of real hardware has no
     *    working sensor. Requiring biometrics specifically would exclude those
     *    users entirely.
     *  - `setInvalidatedByBiometricEnrollment(true)` — a newly enrolled
     *    fingerprint must not inherit this key's authority.
     *
     * Be precise about what that last flag buys, because it is less than it
     * first reads: Android does not invalidate a key that also accepts the
     * device credential, so in this combination the flag only takes effect on
     * the biometric branch. It is not load-bearing on its own — what actually
     * protects the key is that enrolling a biometric requires the existing
     * credential first, so an attacker who can add their fingerprint already
     * holds what the surviving branch asks for.
     *
     * Equally deliberately, nothing here makes any key exportable.
     * AndroidKeyStore has no such option for a generated key, which is the point.
     */
    private fun createKeyPair(alias: String, useStrongBox: Boolean, protection: KeyProtection) {
        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE,
        )
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .apply {
                if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                    setIsStrongBoxBacked(true)
                }
                if (protection.requiresUserPresence) {
                    setUserAuthenticationRequired(true)
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        setUserAuthenticationParameters(
                            AUTH_PER_OPERATION,
                            KeyProperties.AUTH_BIOMETRIC_STRONG or
                                KeyProperties.AUTH_DEVICE_CREDENTIAL,
                        )
                    } else {
                        // Pre-R has no authenticator-type selector, and the
                        // sentinel for per-operation authorisation is -1, not 0
                        // — a positive duration is what makes a key time-bound
                        // and credential-eligible there.
                        //
                        // The honest consequence: on API 24-29 the user-present
                        // key is **biometric-only**, so "the device credential
                        // is an acceptable authenticator" does not hold on those
                        // releases. A passcode-only device on API 24-29 cannot
                        // create one, and the availability check above will not
                        // catch that — the keygen below throws and surfaces as a
                        // keystore failure. Accepted rather than papered over:
                        // the platform offers no per-operation credential-backed
                        // key before R.
                        @Suppress("DEPRECATION")
                        setUserAuthenticationValidityDurationSeconds(AUTH_PER_OPERATION_LEGACY)
                    }
                    setInvalidatedByBiometricEnrollment(true)
                }
            }
            .build()
        generator.initialize(spec)
        generator.generateKeyPair()
    }

    private fun keyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun base64Url(bytes: ByteArray): String =
        Base64.encodeToString(bytes, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)

    internal class SignerError(val code: SignerErrorCode, override val message: String) :
        Exception(message)

    companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        /**
         * Zero seconds of validity — authorise each signature individually.
         *
         * The alternative, a short window, is kinder to a multi-step flow like a
         * transfer with a confirmation screen, and weaker against an attacker
         * who wins the race inside the window. Per-operation is the stronger
         * default and the one to move away from only with measurement against
         * real flows.
         */
        private const val AUTH_PER_OPERATION = 0

        /**
         * The same intent expressed for `setUserAuthenticationValidityDurationSeconds`,
         * whose sentinel differs: -1 is per-operation there, while 0 is
         * per-operation for `setUserAuthenticationParameters`. Passing one API's
         * sentinel to the other silently produces a key with the wrong policy.
         */
        private const val AUTH_PER_OPERATION_LEGACY = -1

        private const val PROBE_ALIAS_PREFIX = "__tauri_sign_keypair_backing_probe_"
    }
}
