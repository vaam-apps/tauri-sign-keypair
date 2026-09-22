package app.vaam.signkeypair

import java.math.BigInteger
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Known-answer tests for DER -> IEEE P1363 and coordinate padding.
 *
 * AndroidKeyStore does not exist off-device, so keystore behaviour is covered by
 * the instrumented test in `src/androidTest`. What *can* be covered here is the
 * encoding step, which is where "valid ECDSA signature that the server rejects"
 * bugs actually come from.
 *
 * **Provenance of the vectors.** The `real signature` cases are genuine P-256
 * signatures from `openssl dgst -sha256 -sign`, picked out of a large sample to
 * hit the shapes that occur only ~1 time in 256. Each expected P1363 value was
 * computed independently, re-encoded to DER, and confirmed with
 * `openssl dgst -sha256 -verify` against the real public key — so the
 * expectations are anchored to a third-party implementation rather than to our
 * own output.
 *
 * These are the **same vectors** the Swift suite uses
 * (`darwin_tests/Tests/SignKeypairCodecTests/EcdsaSignatureCodecTests.swift`),
 * so the two implementations cross-validate rather than each being checked
 * against itself.
 */
class EcdsaSignatureCodecTest {

    private fun hex(value: String): ByteArray =
        value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    // --- real signatures ----------------------------------------------------

    /** r's magnitude is 31 bytes, so P1363 must LEFT-pad it. The ~1-in-256 case. */
    @Test
    fun `real signature with short r is left padded`() {
        val der = hex(
            "3043021f2952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2d" +
                "f02207d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93",
        )
        val expected =
            "002952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2df" +
                "7d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93"

        val actual = EcdsaSignatureCodec.derToP1363(der)

        assertEquals(expected, actual.toHex())
        assertEquals(64, actual.size)
        assertEquals(0x00, actual[0].toInt(), "pad byte must be at the FRONT of r")
        assertEquals(0x29, actual[1].toInt() and 0xff)
    }

    /** s's magnitude is 31 bytes behind a DER sign byte. */
    @Test
    fun `real signature with short s is left padded`() {
        val der = hex(
            "3044022007cf881741f66ab5f83b43c30b5ad3795bd6bb666010d2843ad594a9ba2c78c0" +
                "022000c35b6cfbdc8a99489ef54bc7d8308b262c10c88c4b321b90d92de7f683df52",
        )
        val expected =
            "07cf881741f66ab5f83b43c30b5ad3795bd6bb666010d2843ad594a9ba2c78c0" +
                "00c35b6cfbdc8a99489ef54bc7d8308b262c10c88c4b321b90d92de7f683df52"

        val actual = EcdsaSignatureCodec.derToP1363(der)

        assertEquals(expected, actual.toHex())
        assertEquals(64, actual.size)
        assertEquals(0x00, actual[32].toInt(), "s must be left-padded")
        assertEquals(0xc3, actual[33].toInt() and 0xff)
    }

    /** Both components high-bit: DER carries a 0x00 sign byte on each. */
    @Test
    fun `real signature with both high bit set strips both sign bytes`() {
        val der = hex(
            "30460221008ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90" +
                "022100bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6",
        )
        val expected =
            "8ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90" +
                "bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6"

        val actual = EcdsaSignatureCodec.derToP1363(der)

        assertEquals(expected, actual.toHex())
        assertEquals(64, actual.size)
        assertEquals(0x8f, actual[0].toInt() and 0xff, "DER sign byte must not survive into r")
        assertEquals(0xbd, actual[32].toInt() and 0xff, "DER sign byte must not survive into s")
    }

    // --- synthetic extremes -------------------------------------------------

    @Test
    fun `tiny integers are padded on the left`() {
        val actual = EcdsaSignatureCodec.derToP1363(hex("3006020101020102"))

        assertEquals(64, actual.size)
        assertContentEquals(ByteArray(31), actual.copyOfRange(0, 31))
        assertEquals(1, actual[31].toInt())
        assertContentEquals(ByteArray(31), actual.copyOfRange(32, 63))
        assertEquals(2, actual[63].toInt())
    }

    @Test
    fun `both components short`() {
        val r = ByteArray(30) { 0xaa.toByte() }
        val s = ByteArray(29) { 0x0b }
        val body = byteArrayOf(0x02, r.size.toByte()) + r + byteArrayOf(0x02, s.size.toByte()) + s
        val der = byteArrayOf(0x30, body.size.toByte()) + body

        val actual = EcdsaSignatureCodec.derToP1363(der)

        assertEquals(64, actual.size)
        assertContentEquals(ByteArray(2), actual.copyOfRange(0, 2))
        assertEquals(0xaa, actual[2].toInt() and 0xff)
        assertContentEquals(ByteArray(3), actual.copyOfRange(32, 35))
        assertEquals(0x0b, actual[35].toInt())
    }

    @Test
    fun `zero component`() {
        val actual = EcdsaSignatureCodec.derToP1363(hex("3006020100020101"))

        assertEquals(64, actual.size)
        assertContentEquals(ByteArray(32), actual.copyOfRange(0, 32))
        assertEquals(1, actual[63].toInt())
    }

    @Test
    fun `accepts the long-form SEQUENCE length`() {
        val r = ByteArray(32) { 0x11 }
        val s = ByteArray(32) { 0x22 }
        val body = byteArrayOf(0x02, 32) + r + byteArrayOf(0x02, 32) + s
        val der = byteArrayOf(0x30, 0x81.toByte(), body.size.toByte()) + body

        assertContentEquals(r + s, EcdsaSignatureCodec.derToP1363(der))
    }

    @Test
    fun `output is always exactly 64 bytes`() {
        val inputs = listOf(
            "3043021f2952020b371b18ca4929dad12eb900b0ab30354dd7c714387280c2c126e2d" +
                "f02207d71f47c1b2406eaef13a3f1f7c6d42b0e1f3427c7433b5cb7f4e47458ac9a93",
            "30460221008ff702c97a2c11fc716b238919cef2bf0896545f8e65e2437cb77c97c2eb6c90" +
                "022100bd221a344e59eb869cf132f004dba37c2692024546681d46641b235b7a8822c6",
            "3006020101020102",
            "3006020100020100",
        )
        for (input in inputs) {
            assertEquals(64, EcdsaSignatureCodec.derToP1363(hex(input)).size, "input $input")
        }
    }

    // --- malformed input ----------------------------------------------------

    /**
     * Must fail cleanly rather than crash or read out of bounds. An unchecked
     * read would throw IndexOutOfBoundsException; asserting the codec's own
     * IllegalArgumentException proves the bounds were checked BEFORE the read.
     */
    @Test
    fun `malformed inputs are rejected`() {
        val cases = listOf(
            "" to "empty buffer",
            "30" to "SEQUENCE tag with no length",
            "3006" to "length with no body",
            "30060201" to "SEQUENCE length disagrees with the buffer",
            "300602010102" to "truncated before s's length",
            "3106020101020102" to "wrong outer tag (SET, not SEQUENCE)",
            "3006030101020102" to "wrong inner tag (BIT STRING, not INTEGER)",
            "3008020101020102" to "declared length overruns the buffer",
            "3004020101020102" to "declared length undershoots the buffer",
            "3006022001020102" to "INTEGER length overruns the buffer",
            "300602810102010201" to "long-form INTEGER length",
            "3006020001020102" to "zero-length INTEGER",
            // Without an explicit zero-length check this parses as r = 0, s = 0
            // and returns 64 zero bytes — a bogus signature accepted as valid.
            // `openssl asn1parse` reports "BAD INTEGER" for it.
            "300402000200" to "both INTEGERs zero-length (openssl: BAD INTEGER)",
            // Silently ignoring trailing bytes makes the encoding malleable:
            // two distinct byte strings, one signature. `openssl asn1parse`
            // rejects this same input with "Error in encoding".
            "3009020101020102aabbcc" to "trailing bytes after s",
            ("30250221" + "11".repeat(33) + "020101") to "r wider than 32 bytes",
        )

        for ((input, description) in cases) {
            assertFailsWith<IllegalArgumentException>("expected a throw for $description") {
                EcdsaSignatureCodec.derToP1363(hex(input))
            }
        }
    }

    // --- coordinate padding -------------------------------------------------

    /**
     * `BigInteger.toByteArray()` prepends a 0x00 sign byte when the high bit is
     * set. Letting that through would produce a 33-byte "coordinate" and a JWK
     * the server cannot verify anything against.
     */
    @Test
    fun `high bit coordinate loses its sign byte`() {
        val value = BigInteger(1, hex("ff".repeat(32)))
        val bytes = EcdsaSignatureCodec.coordinateBytes(value)

        assertEquals(33, value.toByteArray().size, "precondition: BigInteger adds a sign byte")
        assertEquals(32, bytes.size)
        assertEquals("ff".repeat(32), bytes.toHex())
    }

    /**
     * The opposite direction: a coordinate with leading zeros is FEWER than 32
     * bytes, and must be padded on the left. Right-alignment would silently
     * multiply the value.
     */
    @Test
    fun `small coordinate is left padded`() {
        val bytes = EcdsaSignatureCodec.coordinateBytes(BigInteger.ONE)

        assertEquals(32, bytes.size)
        assertContentEquals(ByteArray(31), bytes.copyOfRange(0, 31))
        assertEquals(1, bytes[31].toInt())
    }

    @Test
    fun `zero coordinate is all zeros`() {
        assertContentEquals(ByteArray(32), EcdsaSignatureCodec.coordinateBytes(BigInteger.ZERO))
    }
}
