package app.vaam.signkeypair

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.Signature
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.math.BigInteger
import java.util.Base64
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assume
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device tests for [SecureKeyStore] — the real production path.
 *
 * These drive [SecureKeyStore] directly rather than rebuilding its
 * `KeyGenParameterSpec`. That distinction is the whole point: a test that
 * constructs its own spec would keep passing if the shipping spec drifted to
 * something weaker, which is exactly the regression worth catching.
 *
 * What each assertion is worth on which hardware:
 *  • [privateKeyIsNeverExportable] holds on **every** Android device, emulator
 *    included, because keystore keys live in the `keystore2` daemon rather than
 *    in the app process. It is genuinely proven here, on any device.
 *  • [keyLivesInSecureHardware] can only pass on a **physical** device. An
 *    emulator ships a software keymaster, so it is skipped there — skipped, not
 *    passed, because an emulator cannot prove hardware residency and pretending
 *    otherwise is the failure mode these tests exist to prevent.
 */
@RunWith(AndroidJUnit4::class)
class SecureKeyStoreTest {

    private val keyId = "tauri_sign_keypair_instrumented_test"

    // StrongBox is not assumed: the emulator has none, and a device that has it
    // is exercised by the same code path with strongBoxAvailable = true.
    private val keys = SecureKeyStore(
        strongBoxAvailable = false,
        // These tests only exercise ambient keys, which never consult this.
        // A user-present key needs a device with a configured lock screen
        // and a prompt somebody can answer, so it belongs in an
        // instrumented UI test, not here.
        userAuthenticationAvailable = { false },
    )

    @After
    fun tearDown() {
        runCatching { keys.deleteKey(keyId) }
    }

    private fun generate() = keys.generateKey(keyId, requireHardware = false, overwrite = true, protection = KeyProtection.AMBIENT)

    // --- the security property ---------------------------------------------

    /**
     * The private key cannot be read out of the keystore.
     *
     * This is the security property in one assertion. A signer that keeps the
     * scalar in process memory hands 32 bytes of private key to anything that
     * can read the heap. Here there is nothing to extract — `encoded` is null,
     * and no method on [SecureKeyStore] returns key material.
     */
    @Test
    fun privateKeyIsNeverExportable() {
        generate()

        val handle = keys.privateKeyHandle(keyId)
        assertTrue("no key handle after generate()", handle != null)
        assertNull("the keystore handed back encoded private key material", handle!!.encoded)
        assertEquals("EC", handle.algorithm)
        // getFormat() is null for a non-extractable key; a format string would
        // mean there IS a serialisation the key can be exported into.
        assertNull("the key advertises an export format", handle.format)
    }

    /**
     * Hardware residency. Skipped on a software keymaster (emulator) rather than
     * failing, so this suite is honest about what it did and did not prove.
     */
    @Test
    fun keyLivesInSecureHardware() {
        generate()
        val backing = keys.backingOf(keyId)
        Assume.assumeTrue(
            "this device has a software keymaster (emulator?) — hardware residency " +
                "cannot be proven here; run on a physical phone",
            backing != KeyBacking.SOFTWARE,
        )
        assertTrue(
            "unexpected backing: $backing",
            backing == KeyBacking.TEE || backing == KeyBacking.STRONGBOX,
        )
    }

    /**
     * `requireHardware = true` must fail loudly rather than return a software
     * key. On an emulator this is the *positive* path for the assertion: the
     * device genuinely cannot provide hardware, so the call must throw.
     */
    @Test
    fun requireHardwareFailsLoudlyOnASoftwareKeymaster() {
        val backing = keys.bestAvailableBacking()
        if (backing == KeyBacking.SOFTWARE) {
            try {
                keys.generateKey(keyId, requireHardware = true, overwrite = true, protection = KeyProtection.AMBIENT)
                throw AssertionError(
                    "requireHardware = true silently returned a software key — " +
                        "this is the exact failure mode the flag exists to prevent",
                )
            } catch (e: SecureKeyStore.SignerError) {
                assertEquals(SignerErrorCode.HARDWARE_UNAVAILABLE, e.code)
            }
            // And it must not leave a half-created key behind.
            assertNull("a rejected key was left in the keystore", keys.describeKey(keyId))
        } else {
            // On real hardware the same call must succeed and report hardware.
            val description = keys.generateKey(keyId, requireHardware = true, overwrite = true, protection = KeyProtection.AMBIENT)
            assertTrue("expected hardware backing", description.backing.isHardwareBacked)
        }
    }

    /**
     * A rejected `requireHardware` generate must not destroy the key that was
     * already there.
     *
     * This is the dangerous case, and it only shows up when a key EXISTS first:
     * `overwrite = true` deletes the incumbent before generating, so a later
     * rejection can leave the device with no credential at all — unable to
     * authenticate AND unable to sign its way through re-enrolment.
     */
    @Test
    fun rejectedRequireHardwareDoesNotDestroyTheExistingKey() {
        val backing = keys.bestAvailableBacking()
        Assume.assumeTrue(
            "this device can provide hardware, so requireHardware will not be rejected",
            backing == KeyBacking.SOFTWARE,
        )

        val original = generate()

        try {
            keys.generateKey(keyId, requireHardware = true, overwrite = true, protection = KeyProtection.AMBIENT)
            throw AssertionError("requireHardware = true should have been rejected")
        } catch (e: SecureKeyStore.SignerError) {
            assertEquals(SignerErrorCode.HARDWARE_UNAVAILABLE, e.code)
        }

        val surviving = keys.describeKey(keyId)
        assertTrue("the pre-existing key was destroyed by a failed generate", surviving != null)
        assertEquals(original.x, surviving!!.x)
        assertEquals(original.y, surviving.y)
    }

    // --- correctness --------------------------------------------------------

    /**
     * A signature made inside the keystore verifies against the public key the
     * plugin reports — using the coordinates exactly as they are sent to the
     * backend at device registration, so a JWK-encoding bug would surface here too.
     */
    @Test
    fun signatureVerifiesAgainstTheReportedPublicKey() {
        val description = generate()
        val payload = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload".toByteArray()

        val p1363 = keys.sign(keyId, payload)
        assertEquals("JWS ES256 requires a 64-byte P1363 signature", 64, p1363.size)

        // Rebuild the public key from the reported base64url JWK coordinates.
        val decoder = Base64.getUrlDecoder()
        val x = BigInteger(1, decoder.decode(description.x))
        val y = BigInteger(1, decoder.decode(description.y))
        val params = (
            java.security.KeyFactory.getInstance("EC")
                .generatePublic(
                    ECPublicKeySpec(
                        ECPoint(x, y),
                        (
                            java.security.KeyStore.getInstance(SecureKeyStore.ANDROID_KEYSTORE)
                                .apply { load(null) }
                                .getCertificate(keyId).publicKey as ECPublicKey
                            ).params,
                    ),
                ) as ECPublicKey
            )

        // Convert P1363 back to DER for java.security's verifier.
        val verified = Signature.getInstance(SecureKeyStore.SIGNATURE_ALGORITHM).run {
            initVerify(params)
            update(payload)
            verify(p1363ToDer(p1363))
        }
        assertTrue("the keystore signature did not verify against the reported JWK", verified)
    }

    @Test
    fun deletedKeysCannotSign() {
        generate()
        keys.deleteKey(keyId)

        assertNull(keys.describeKey(keyId))
        try {
            keys.sign(keyId, "x".toByteArray())
            throw AssertionError("signing with a deleted key should have failed")
        } catch (e: SecureKeyStore.SignerError) {
            assertEquals(SignerErrorCode.KEY_NOT_FOUND, e.code)
        }
    }

    @Test
    fun generateWithoutOverwriteRefusesToClobberAnExistingKey() {
        generate()
        try {
            keys.generateKey(keyId, requireHardware = false, overwrite = false, protection = KeyProtection.AMBIENT)
            throw AssertionError("expected key_already_exists")
        } catch (e: SecureKeyStore.SignerError) {
            assertEquals(SignerErrorCode.KEY_ALREADY_EXISTS, e.code)
        }
    }

    @Test
    fun publicKeyIsStableAcrossReads() {
        val first = generate()
        val second = keys.describeKey(keyId)!!
        assertEquals(first.x, second.x)
        assertEquals(first.y, second.y)
        // 32 bytes each, base64url-unpadded.
        assertEquals(32, Base64.getUrlDecoder().decode(first.x).size)
        assertEquals(32, Base64.getUrlDecoder().decode(first.y).size)
    }

    /** IEEE P1363 r‖s -> ASN.1 DER, so java.security's verifier can read it. */
    private fun p1363ToDer(p1363: ByteArray): ByteArray {
        fun derInteger(magnitude: ByteArray): ByteArray {
            var start = 0
            while (start < magnitude.size - 1 && magnitude[start].toInt() == 0) start++
            var value = magnitude.copyOfRange(start, magnitude.size)
            if (value[0].toInt() and 0x80 != 0) value = byteArrayOf(0x00) + value
            return byteArrayOf(0x02, value.size.toByte()) + value
        }
        val body = derInteger(p1363.copyOfRange(0, 32)) + derInteger(p1363.copyOfRange(32, 64))
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}
