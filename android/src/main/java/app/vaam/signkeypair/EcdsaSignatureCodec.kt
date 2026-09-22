package app.vaam.signkeypair

import java.math.BigInteger

/**
 * ASN.1 DER -> IEEE P1363 conversion for P-256 ECDSA signatures, plus the
 * coordinate padding the public JWK needs.
 *
 * Deliberately free of any Android import, so a plain JVM unit test can drive
 * it without a device or an emulator — `./gradlew test`, seconds rather than
 * minutes.
 *
 * `java.security.Signature` emits **ASN.1 DER** `SEQUENCE { INTEGER r, INTEGER s }`.
 * JWS ES256 (RFC 7515 §3.4 / RFC 7518 §3.4) requires **IEEE P1363** — the two
 * integers as fixed-width 32-byte big-endian values, concatenated, unwrapped.
 *
 * Getting this wrong is silent *and intermittent*. DER encodes integers
 * minimally, so a component whose top byte happens to be zero is one byte
 * shorter — roughly 1 signature in 256 per component. Code that copies the
 * magnitude without left-padding produces a signature that is valid ECDSA and
 * that a JWS verifier rejects, days or weeks after it shipped.
 */
internal object EcdsaSignatureCodec {

    /** Byte width of one P-256 coordinate. */
    const val COORDINATE_LENGTH = 32

    /** Total length of a P-256 P1363 signature. */
    const val P1363_LENGTH = COORDINATE_LENGTH * 2

    /**
     * Left-pad / trim a BigInteger to exactly 32 bytes (P-256 coordinate width).
     *
     * Same bug class as [derToP1363]: `BigInteger.toByteArray()` prepends a 0x00
     * sign byte when the high bit is set (33 bytes), and returns FEWER than 32
     * bytes for a coordinate with leading zeros. Getting either wrong corrupts
     * the public JWK sent at device registration, and the symptom is "every
     * signature this device makes is rejected" — with no hint that the *key*,
     * not the signing, was wrong.
     */
    fun coordinateBytes(value: BigInteger): ByteArray {
        val raw = value.toByteArray()
        val out = ByteArray(COORDINATE_LENGTH)
        if (raw.size > COORDINATE_LENGTH) {
            System.arraycopy(raw, raw.size - COORDINATE_LENGTH, out, 0, COORDINATE_LENGTH)
        } else {
            System.arraycopy(raw, 0, out, COORDINATE_LENGTH - raw.size, raw.size)
        }
        return out
    }

    /**
     * Convert an ASN.1 DER ECDSA signature to IEEE P1363 `r‖s`.
     *
     * The result is **always** exactly [P1363_LENGTH] bytes, or the call throws
     * [IllegalArgumentException].
     */
    fun derToP1363(der: ByteArray): ByteArray {
        var offset = 0
        fun readByte(what: String): Int {
            require(offset < der.size) { "Truncated DER signature: expected $what at offset $offset" }
            return der[offset++].toInt() and 0xff
        }

        require(readByte("SEQUENCE tag") == 0x30) { "DER signature does not start with SEQUENCE" }
        var sequenceLength = readByte("SEQUENCE length")
        if (sequenceLength and 0x80 != 0) {
            val lengthOctets = sequenceLength and 0x7f
            require(lengthOctets in 1..2) { "Unsupported DER length form ($lengthOctets octets)" }
            sequenceLength = 0
            repeat(lengthOctets) {
                sequenceLength = (sequenceLength shl 8) or readByte("SEQUENCE length octet")
            }
        }
        require(offset + sequenceLength == der.size) { "DER length mismatch" }

        fun readInteger(what: String): ByteArray {
            require(readByte("$what INTEGER tag") == 0x02) { "Expected DER INTEGER for $what" }
            val length = readByte("$what INTEGER length")
            require(length and 0x80 == 0) { "Unsupported long-form DER INTEGER for $what" }
            require(length > 0) { "Zero-length DER INTEGER for $what" }
            require(offset + length <= der.size) { "Truncated DER INTEGER for $what" }
            val value = der.copyOfRange(offset, offset + length)
            offset += length
            return value
        }

        /**
         * Strip DER's minimal-encoding leading zeros, then left-pad to 32 bytes.
         *
         * Both halves matter: a high-bit component carries a 0x00 sign byte that
         * must NOT survive into P1363, and a short component must be padded on
         * the LEFT — right-alignment silently multiplies the value by 256^n.
         */
        fun normalise(value: ByteArray): ByteArray {
            var start = 0
            while (start < value.size - 1 && value[start].toInt() == 0) start++
            val length = value.size - start
            require(length <= COORDINATE_LENGTH) { "ECDSA integer longer than $COORDINATE_LENGTH bytes" }
            val out = ByteArray(COORDINATE_LENGTH)
            System.arraycopy(value, start, out, COORDINATE_LENGTH - length, length)
            return out
        }

        val r = normalise(readInteger("r"))
        val s = normalise(readInteger("s"))

        // r and s must account for the entire SEQUENCE. Without this, trailing
        // bytes are silently ignored, which makes the encoding malleable: junk
        // can be appended to produce a different byte string that decodes to the
        // same signature. `openssl asn1parse` rejects such input too.
        require(offset == der.size) { "${der.size - offset} trailing byte(s) after s" }

        return r + s
    }
}
