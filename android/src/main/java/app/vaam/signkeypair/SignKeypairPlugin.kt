package app.vaam.signkeypair

import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin
import org.json.JSONObject
import java.security.Signature
import java.util.concurrent.Executor

@InvokeArg
internal class KeyIdArgs {
    lateinit var keyId: String
}

@InvokeArg
internal class GenerateKeyArgs {
    lateinit var keyId: String
    var requireHardware: Boolean? = null
    var overwrite: Boolean? = null
    var protection: String? = null
}

@InvokeArg
internal class SignArgs {
    lateinit var keyId: String

    /** base64url of the raw signing input. */
    lateinit var payload: String
    var reason: String? = null
}

/**
 * Tauri adapter over [SecureKeyStore].
 *
 * Everything that touches AndroidKeyStore lives in [SecureKeyStore], which has
 * no Tauri dependency and is therefore drivable by instrumented tests. What
 * remains here is command dispatch, argument validation, error mapping — and
 * the one thing that genuinely cannot move: raising BiometricPrompt for a
 * user-present key, which needs an Activity.
 */
@TauriPlugin
class SignKeypairPlugin(private val activity: Activity) : Plugin(activity) {

    private val keys = SecureKeyStore(
        strongBoxAvailable = hasStrongBox(activity.packageManager),
        userAuthenticationAvailable = { hasUserAuthentication(activity) },
    )
    private val mainExecutor: Executor = Executor { Handler(Looper.getMainLooper()).post(it) }

    @Command
    fun capabilities(invoke: Invoke) {
        respond(invoke) {
            val backing = keys.bestAvailableBacking()
            JSObject().apply {
                put("platform", "android")
                put("bestAvailableBacking", backing.wire)
                put("hardwareBacked", backing.isHardwareBacked)
            }
        }
    }

    @Command
    fun generateKey(invoke: Invoke) {
        respond(invoke) {
            val args = invoke.parseArgs(GenerateKeyArgs::class.java)
            describe(
                keys.generateKey(
                    keyId = args.keyId,
                    requireHardware = args.requireHardware ?: false,
                    overwrite = args.overwrite ?: false,
                    protection = requireProtection(args.protection),
                )
            )
        }
    }

    @Command
    fun getKey(invoke: Invoke) {
        respond(invoke) {
            val args = invoke.parseArgs(KeyIdArgs::class.java)
            val description = keys.describeKey(args.keyId)
            JSObject().apply {
                // JSONObject.put(key, null) *removes* the key, which would send
                // `{}` and make the Rust side's `Option` field absent rather
                // than null. JSONObject.NULL is the one that serializes.
                put("key", description?.let { describe(it) } ?: JSONObject.NULL)
            }
        }
    }

    @Command
    fun sign(invoke: Invoke) {
        val args = try {
            invoke.parseArgs(SignArgs::class.java)
        } catch (e: Exception) {
            return invoke.reject(
                e.message ?: "Could not parse the arguments to sign",
                SignerErrorCode.KEYSTORE_FAILURE.wire,
            )
        }

        val payload = try {
            Base64.decode(args.payload, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
        } catch (e: IllegalArgumentException) {
            return invoke.reject(
                "Argument \"payload\" is not valid base64url",
                SignerErrorCode.KEYSTORE_FAILURE.wire,
            )
        }

        try {
            // Begin first: this is what surfaces a key destroyed by a biometric
            // re-enrolment (key_invalidated), and doing it before the prompt
            // means the user is not asked for a fingerprint that cannot help
            // them.
            val operation = keys.beginSign(args.keyId)
            if (!keys.requiresUserAuthentication(args.keyId)) {
                return invoke.resolve(signatureObject(keys.finishSign(operation, payload)))
            }

            val host = activity as? FragmentActivity ?: throw SecureKeyStore.SignerError(
                SignerErrorCode.KEYSTORE_FAILURE,
                "A user-present key needs a FragmentActivity to host the authentication " +
                    "prompt, and this app's activity is not one",
            )
            // BiometricPrompt must be built and shown on the main thread. The
            // Tauri invoke arrives on whichever thread the IPC used, so this is
            // not optional.
            host.runOnUiThread { promptThenSign(host, operation, payload, args.reason, invoke) }
        } catch (e: SecureKeyStore.SignerError) {
            invoke.reject(e.message, e.code.wire)
        } catch (e: Exception) {
            invoke.reject(e.message ?: e.javaClass.simpleName, SignerErrorCode.KEYSTORE_FAILURE.wire)
        }
    }

    @Command
    fun deleteKey(invoke: Invoke) {
        respond(invoke) {
            val args = invoke.parseArgs(KeyIdArgs::class.java)
            keys.deleteKey(args.keyId)
            JSObject()
        }
    }

    /**
     * Run [body], resolving with what it returns and rejecting *with the code*
     * when it throws. The one place an error crosses back to Rust.
     *
     * The broad `catch (e: Exception)` is deliberate: every java.security
     * failure mode — provider missing, key invalidated by a lock-screen change,
     * StrongBox wedged — must reach the frontend as a typed rejection rather
     * than crashing the WebView. The message never contains key material.
     */
    private fun respond(invoke: Invoke, body: () -> JSObject) {
        try {
            invoke.resolve(body())
        } catch (e: SecureKeyStore.SignerError) {
            invoke.reject(e.message, e.code.wire)
        } catch (e: Exception) {
            invoke.reject(e.message ?: e.javaClass.simpleName, SignerErrorCode.KEYSTORE_FAILURE.wire)
        }
    }

    private fun promptThenSign(
        host: FragmentActivity,
        operation: Signature,
        payload: ByteArray,
        reason: String?,
        invoke: Invoke,
    ) {
        // Every path below must complete the invoke exactly once. A second
        // reply is a protocol error, and a dropped one hangs the caller's
        // promise for the life of the process — so the guard is on the callback
        // object, which is the only thing all three outcomes pass through.
        var replied = false
        fun replyOnce(body: () -> Unit) {
            if (replied) return
            replied = true
            body()
        }

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(auth: BiometricPrompt.AuthenticationResult) {
                replyOnce {
                    try {
                        // Sign with the Signature the keymaster just authorised —
                        // `auth.cryptoObject`, not the local `operation`. They are
                        // the same object today, but reading it back from the
                        // result is what makes that a fact rather than an
                        // assumption, and an unauthorised operation would throw
                        // here instead of silently producing nothing.
                        val authorised = auth.cryptoObject?.signature
                            ?: throw SecureKeyStore.SignerError(
                                SignerErrorCode.KEYSTORE_FAILURE,
                                "Authentication succeeded without an authorised signing operation",
                            )
                        invoke.resolve(signatureObject(keys.finishSign(authorised, payload)))
                    } catch (e: SecureKeyStore.SignerError) {
                        invoke.reject(e.message, e.code.wire)
                    } catch (e: Exception) {
                        invoke.reject(
                            e.message ?: e.javaClass.simpleName,
                            SignerErrorCode.KEYSTORE_FAILURE.wire,
                        )
                    }
                }
            }

            override fun onAuthenticationError(code: Int, message: CharSequence) {
                replyOnce { invoke.reject(message.toString(), errorCodeFor(code).wire) }
            }

            // Deliberately no reply here: a rejected fingerprint is a retry
            // within the same prompt, not the end of it. BiometricPrompt calls
            // onAuthenticationError when it finally gives up.
            override fun onAuthenticationFailed() = Unit
        }

        try {
            val authenticators = allowedAuthenticators()
            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(reason?.takeIf { it.isNotEmpty() } ?: DEFAULT_PROMPT_TITLE)
                .setAllowedAuthenticators(authenticators)
                .apply {
                    // A negative button is required when the credential is not an
                    // allowed authenticator, and forbidden when it is — the
                    // builder throws either way round. On pre-R the key is
                    // biometric-only (see SecureKeyStore.createKeyPair), so this
                    // branch tracks the same version split the key spec does.
                    if (authenticators and BiometricManager.Authenticators.DEVICE_CREDENTIAL == 0) {
                        setNegativeButtonText(DEFAULT_PROMPT_CANCEL)
                    }
                }
                .build()
            BiometricPrompt(host, mainExecutor, callback)
                .authenticate(info, BiometricPrompt.CryptoObject(operation))
        } catch (e: Exception) {
            replyOnce {
                invoke.reject(
                    e.message ?: e.javaClass.simpleName,
                    SignerErrorCode.KEYSTORE_FAILURE.wire,
                )
            }
        }
    }

    /**
     * Which authenticators the prompt will accept.
     *
     * Crypto-backed authentication with the device credential only works from
     * API 30 — below that, `authenticate(info, cryptoObject)` rejects a prompt
     * that allows DEVICE_CREDENTIAL. This mirrors the key spec exactly, and it
     * must: a prompt that allows something the key does not, or vice versa,
     * fails at the moment the user is looking at it.
     */
    private fun allowedAuthenticators(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.DEVICE_CREDENTIAL
        } else {
            BiometricManager.Authenticators.BIOMETRIC_STRONG
        }

    /**
     * Map a BiometricPrompt error onto a wire code.
     *
     * The distinction that earns its keep is cancelled-versus-unavailable: a
     * dismissed prompt is someone changing their mind at a confirmation screen,
     * and reporting it as an authentication failure would send them through
     * re-enrolment for a routine interaction.
     */
    private fun errorCodeFor(code: Int): SignerErrorCode = when (code) {
        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
        BiometricPrompt.ERROR_USER_CANCELED,
        BiometricPrompt.ERROR_CANCELED,
        BiometricPrompt.ERROR_TIMEOUT,
        -> SignerErrorCode.USER_AUTHENTICATION_CANCELLED

        BiometricPrompt.ERROR_NO_BIOMETRICS,
        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL,
        BiometricPrompt.ERROR_HW_NOT_PRESENT,
        BiometricPrompt.ERROR_HW_UNAVAILABLE,
        BiometricPrompt.ERROR_LOCKOUT,
        BiometricPrompt.ERROR_LOCKOUT_PERMANENT,
        -> SignerErrorCode.USER_AUTHENTICATION_REQUIRED

        else -> SignerErrorCode.KEYSTORE_FAILURE
    }

    private fun describe(description: SecureKeyStore.Description): JSObject = JSObject().apply {
        put("keyId", description.keyId)
        put(
            "publicKey",
            JSObject().apply {
                put("crv", "P-256")
                put("kty", "EC")
                put("x", description.x)
                put("y", description.y)
            },
        )
        put("backing", description.backing.wire)
        put("hardwareBacked", description.backing.isHardwareBacked)
    }

    private fun signatureObject(signature: ByteArray): JSObject = JSObject().apply {
        put(
            "signature",
            Base64.encodeToString(
                signature,
                Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP,
            ),
        )
    }

    private fun hasStrongBox(packageManager: PackageManager): Boolean =
        Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    /**
     * Whether the device has anything the keystore would accept as proof a human
     * is present.
     *
     * `KeyguardManager.isDeviceSecure` rather than
     * `BiometricManager.canAuthenticate(BIOMETRIC_STRONG)`: the key accepts the
     * device credential too, so probing for biometrics alone would refuse a
     * passcode-only device this plugin can serve perfectly well.
     */
    private fun hasUserAuthentication(context: Context): Boolean {
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as? KeyguardManager
            ?: return false
        return keyguard.isDeviceSecure
    }

    /**
     * The one wire -> enum boundary for the protection tag.
     *
     * Absent means ambient, which is the documented default. Unrecognised is a
     * hard failure with no default: guessing AMBIENT would hand a caller who
     * asked for prompted protection a key that signs without a human; guessing
     * USER_PRESENT would make a background signer prompt on every poll. The
     * policy is baked into the key permanently at creation, so a mismatched
     * pairing fails at the call instead.
     */
    private fun requireProtection(raw: String?): KeyProtection {
        if (raw == null) return KeyProtection.AMBIENT
        return KeyProtection.from(raw) ?: throw SecureKeyStore.SignerError(
            SignerErrorCode.KEYSTORE_FAILURE,
            "Unknown key protection \"$raw\"",
        )
    }

    private companion object {
        /**
         * Shown only when the caller supplies no `reason`.
         *
         * Deliberately a bare English string rather than considered copy: a
         * caller that omits `reason` and ships this to production is a bug worth
         * being able to spot in a screenshot. Pass `reason` to show your own
         * localized copy instead.
         */
        const val DEFAULT_PROMPT_TITLE = "Authentication required"
        const val DEFAULT_PROMPT_CANCEL = "Cancel"
    }
}
