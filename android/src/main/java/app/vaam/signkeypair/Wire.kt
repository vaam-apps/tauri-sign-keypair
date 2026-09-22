package app.vaam.signkeypair

/**
 * The wire vocabulary shared with the Rust side, as enums.
 *
 * The Tauri IPC can only carry JSON, so strings do cross the wire. What this
 * file buys is that each string is written in exactly **one** place and parsed
 * in exactly one place; every comparison in the rest of the module is on an
 * enum. Adding a member here is then a compile error at each exhaustive `when`
 * rather than a silent fallthrough.
 *
 * These must stay in step with `src/models.rs`, `src/error.rs`,
 * `ios/Sources/SignKeypair/Wire.swift` and `guest-js/index.ts`.
 * `WireContractTest` pins the exact strings so a rename on one side cannot
 * drift past review.
 */

/**
 * Where a private key lives, strongest first.
 *
 * [SOFTWARE] is the floor and the safe default: under-reporting strength is
 * harmless, over-reporting is a false security claim.
 */
internal enum class KeyBacking(val wire: String) {
    STRONGBOX("strongbox"),
    TEE("tee"),
    SOFTWARE("software"),
    ;

    /** True when the key cannot be read out of the device. */
    val isHardwareBacked: Boolean
        get() = when (this) {
            STRONGBOX, TEE -> true
            SOFTWARE -> false
        }

    companion object {
        fun from(wire: String): KeyBacking? = entries.firstOrNull { it.wire == wire }
    }
}

/**
 * What the keystore demands before it signs.
 *
 * Unlike [KeyBacking] this has **no safe default**: answering [AMBIENT] for an
 * unrecognised tag would hand a caller who asked for prompted protection a key
 * that signs silently, and answering [USER_PRESENT] would make a background
 * request signer prompt on every poll. [from] therefore returns null and the
 * call fails.
 */
internal enum class KeyProtection(val wire: String) {
    AMBIENT("ambient"),
    USER_PRESENT("user_present"),
    ;

    /** Whether the keystore will demand authentication before signing. */
    val requiresUserPresence: Boolean
        get() = when (this) {
            AMBIENT -> false
            USER_PRESENT -> true
        }

    companion object {
        fun from(wire: String): KeyProtection? = entries.firstOrNull { it.wire == wire }
    }
}

/**
 * Why an operation failed.
 *
 * Becomes the `code` on the rejected invoke, which `src/mobile.rs` maps
 * straight back onto its own enum — so a distinction drawn here survives all
 * the way to the frontend's `catch`.
 */
internal enum class SignerErrorCode(val wire: String) {
    KEY_NOT_FOUND("key_not_found"),
    KEY_ALREADY_EXISTS("key_already_exists"),
    HARDWARE_UNAVAILABLE("hardware_unavailable"),
    KEYSTORE_FAILURE("keystore_failure"),
    USER_AUTHENTICATION_REQUIRED("user_authentication_required"),
    USER_AUTHENTICATION_CANCELLED("user_authentication_cancelled"),
    KEY_INVALIDATED("key_invalidated"),
    ;

    companion object {
        fun from(wire: String): SignerErrorCode? = entries.firstOrNull { it.wire == wire }
    }
}
