import { beforeEach, describe, expect, it } from 'vitest'

import { SignKeypairError, SignerErrorCode } from './models'
import { WebCryptoBackend } from './web-backend'

/**
 * The WebCrypto fallback, including the two things it refuses to do.
 *
 * Signatures are verified with WebCrypto's own **verifier** against the JWK the
 * backend reported, not against anything the backend produced internally, so a
 * coordinate-encoding bug fails here rather than at device registration.
 */
describe('WebCryptoBackend', () => {
  let backend: WebCryptoBackend
  let keyId: string

  beforeEach(() => {
    backend = new WebCryptoBackend()
    // IndexedDB persists across tests in one process, so each test gets an id
    // nothing else will collide with.
    keyId = `test_${Math.random().toString(36).slice(2)}`
  })

  const ambient = {
    requireHardware: false,
    overwrite: false,
    protection: 'ambient' as const,
  }

  it('reports software backing and says it is not hardware', async () => {
    const capabilities = await backend.capabilities()
    expect(capabilities.platform).toBe('web')
    expect(capabilities.bestAvailableBacking).toBe('software')
    // The whole point of the flag: a caller can see it is on the degraded path.
    expect(capabilities.hardwareBacked).toBe(false)
  })

  it('produces a signature that verifies against the JWK it reported', async () => {
    const key = await backend.generateKey({ keyId, ...ambient })
    expect(key.publicKey.crv).toBe('P-256')
    expect(key.publicKey.kty).toBe('EC')
    expect(key.hardwareBacked).toBe(false)

    const payload = new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.payload')
    const signature = await backend.sign({ keyId, payload })
    // JWS ES256 requires IEEE P1363, which is fixed width. A DER signature
    // would be 70-72 bytes and would fail roughly 1 time in 256 rather than
    // every time — so assert the length, not just the verify.
    expect(signature.length).toBe(64)

    const verifier = await crypto.subtle.importKey(
      'jwk',
      { ...key.publicKey, ext: true, key_ops: ['verify'] },
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['verify']
    )
    const verified = await crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      verifier,
      new Uint8Array(signature),
      new Uint8Array(payload)
    )
    expect(verified).toBe(true)
  })

  /**
   * The key is generated with `extractable: false`, so there is nothing for a
   * compromised page to read out. This asserts the property rather than
   * trusting the flag was passed.
   */
  it('stores a private key that cannot be exported', async () => {
    await backend.generateKey({ keyId, ...ambient })
    const stored = await openStoredKey(keyId)
    expect(stored.extractable).toBe(false)
    await expect(crypto.subtle.exportKey('jwk', stored)).rejects.toThrow()
  })

  /**
   * There is no hardware here to require. Refusing is the point of the flag —
   * silently returning a software key would make the caller log "hardware-backed"
   * for a key that is not.
   */
  it('refuses requireHardware rather than degrading', async () => {
    const raised = await backend
      .generateKey({ keyId, ...ambient, requireHardware: true })
      .catch((e: unknown) => e)
    expect(raised).toBeInstanceOf(SignKeypairError)
    expect((raised as SignKeypairError).code).toBe(SignerErrorCode.hardwareUnavailable)
    expect(await backend.getKey(keyId)).toBeNull()
  })

  /**
   * WebCrypto has no user-presence binding and no prompt to raise, so a
   * "user-present" key here would sign happily with nobody at the keyboard.
   * Issuing one would make every downstream check that compares protection
   * against key id assert something untrue.
   */
  it('refuses user presence rather than faking it', async () => {
    const raised = await backend
      .generateKey({ keyId, ...ambient, protection: 'user_present' })
      .catch((e: unknown) => e)
    expect(raised).toBeInstanceOf(SignKeypairError)
    expect((raised as SignKeypairError).code).toBe(SignerErrorCode.hardwareUnavailable)
    expect(await backend.getKey(keyId)).toBeNull()
  })

  it('refuses to clobber an existing key without overwrite', async () => {
    const original = await backend.generateKey({ keyId, ...ambient })

    const raised = await backend.generateKey({ keyId, ...ambient }).catch((e: unknown) => e)
    expect((raised as SignKeypairError).code).toBe(SignerErrorCode.keyAlreadyExists)
    expect((await backend.getKey(keyId))?.publicKey).toEqual(original.publicKey)

    const replacement = await backend.generateKey({ keyId, ...ambient, overwrite: true })
    // A different key, which is why the caller must re-register it.
    expect(replacement.publicKey).not.toEqual(original.publicKey)
  })

  it('reports a missing key as null, not as a failure', async () => {
    expect(await backend.getKey(keyId)).toBeNull()
  })

  it('cannot sign with a deleted key, and deleting twice is a no-op', async () => {
    await backend.generateKey({ keyId, ...ambient })
    await backend.deleteKey(keyId)

    expect(await backend.getKey(keyId)).toBeNull()
    const raised = await backend.sign({ keyId, payload: new Uint8Array([1]) }).catch((e) => e)
    expect((raised as SignKeypairError).code).toBe(SignerErrorCode.keyNotFound)

    await expect(backend.deleteKey(keyId)).resolves.toBeUndefined()
  })

  /**
   * The JWK is rebuilt rather than passed through from `exportKey`, which also
   * returns `ext` and `key_ops`. A caller that thumbprints what we hand back
   * (RFC 7638) must get the same digest a native platform's JWK would produce,
   * and the thumbprint input is exactly `{crv, kty, x, y}`.
   */
  it('reports a JWK with only the canonical thumbprint members', async () => {
    const key = await backend.generateKey({ keyId, ...ambient })
    expect(Object.keys(key.publicKey).sort()).toEqual(['crv', 'kty', 'x', 'y'])
  })
})

/** Reach into IndexedDB for the raw CryptoKey, to assert on it directly. */
function openStoredKey(keyId: string): Promise<CryptoKey> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open('tauri-sign-keypair', 1)
    open.onsuccess = () => {
      const request = open.result
        .transaction('keys', 'readonly')
        .objectStore('keys')
        .get(keyId)
      request.onsuccess = () => resolve(request.result.privateKey as CryptoKey)
      request.onerror = () => reject(request.error)
    }
    open.onerror = () => reject(open.error)
  })
}
