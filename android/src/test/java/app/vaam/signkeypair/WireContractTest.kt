package app.vaam.signkeypair

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Pins the exact strings that cross the IPC.
 *
 * The enums in `Wire.kt` are the single place each string is written, which
 * makes a rename a one-line change — and that is exactly the problem: a rename
 * here compiles, ships, and then fails at runtime against a Rust side that was
 * not renamed with it. These assertions are the thing a rename has to walk past.
 *
 * The same vectors are asserted in `tests/wire_contract.rs` and
 * `darwin_tests/Tests/SignKeypairCodecTests/WireContractTests.swift`.
 */
class WireContractTest {

    @Test
    fun `backing tags are stable`() {
        assertEquals("strongbox", KeyBacking.STRONGBOX.wire)
        assertEquals("tee", KeyBacking.TEE.wire)
        assertEquals("software", KeyBacking.SOFTWARE.wire)
    }

    @Test
    fun `every backing round trips`() {
        for (backing in KeyBacking.entries) {
            assertEquals(backing, KeyBacking.from(backing.wire), "round trip for ${backing.name}")
        }
    }

    /**
     * The classification callers act on. Getting a member on the wrong side of
     * this line is a false security claim, not a cosmetic bug.
     */
    @Test
    fun `hardware backing classification`() {
        assertEquals(true, KeyBacking.STRONGBOX.isHardwareBacked)
        assertEquals(true, KeyBacking.TEE.isHardwareBacked)
        assertEquals(false, KeyBacking.SOFTWARE.isHardwareBacked)
    }

    @Test
    fun `protection tags are stable`() {
        assertEquals("ambient", KeyProtection.AMBIENT.wire)
        assertEquals("user_present", KeyProtection.USER_PRESENT.wire)
    }

    @Test
    fun `every protection round trips`() {
        for (protection in KeyProtection.entries) {
            assertEquals(
                protection,
                KeyProtection.from(protection.wire),
                "round trip for ${protection.name}",
            )
        }
    }

    /**
     * No default, unlike the backing tag. Guessing AMBIENT would hand a caller
     * who asked for prompted protection a key that signs silently; guessing
     * USER_PRESENT would make a background signer prompt on every poll. Neither
     * is a safe direction to be wrong in.
     */
    @Test
    fun `an unknown protection tag has no default`() {
        assertNull(KeyProtection.from("elevated"))
        assertNull(KeyProtection.from(""))
        assertNull(KeyProtection.from("AMBIENT"))
    }

    @Test
    fun `protection presence classification`() {
        assertEquals(false, KeyProtection.AMBIENT.requiresUserPresence)
        assertEquals(true, KeyProtection.USER_PRESENT.requiresUserPresence)
    }

    @Test
    fun `error codes are stable`() {
        assertEquals("key_not_found", SignerErrorCode.KEY_NOT_FOUND.wire)
        assertEquals("key_already_exists", SignerErrorCode.KEY_ALREADY_EXISTS.wire)
        assertEquals("hardware_unavailable", SignerErrorCode.HARDWARE_UNAVAILABLE.wire)
        assertEquals("keystore_failure", SignerErrorCode.KEYSTORE_FAILURE.wire)
        assertEquals(
            "user_authentication_required",
            SignerErrorCode.USER_AUTHENTICATION_REQUIRED.wire,
        )
        assertEquals(
            "user_authentication_cancelled",
            SignerErrorCode.USER_AUTHENTICATION_CANCELLED.wire,
        )
        assertEquals("key_invalidated", SignerErrorCode.KEY_INVALIDATED.wire)
    }

    @Test
    fun `every error code round trips`() {
        for (code in SignerErrorCode.entries) {
            assertEquals(code, SignerErrorCode.from(code.wire), "round trip for ${code.name}")
        }
    }
}
