import { describe, expect, it, vi } from 'vitest'

import * as b64 from './base64url'
import {
  DEFAULT_KEY_ID,
  DEFAULT_USER_PRESENT_KEY_ID,
  SignKeypair,
} from './index'
import {
  SignKeypairError,
  SignerErrorCode,
  type KeyProtection,
  type SecureKey,
  type SignKeypairBackend,
  type SignerCapabilities,
} from './models'

/**
 * A backend that records what it was asked, so the facade's own behaviour —
 * defaults, JWS assembly, the enrolment rollback — can be tested without a
 * keystore.
 */
class RecordingBackend implements SignKeypairBackend {
  readonly generated: string[] = []
  readonly deleted: string[] = []
  readonly signed: { keyId: string; reason?: string }[] = []
  readonly existing = new Set<string>()
  failUserPresentWith?: SignKeypairError

  async capabilities(): Promise<SignerCapabilities> {
    return { platform: 'fake', bestAvailableBacking: 'software', hardwareBacked: false }
  }

  async generateKey(options: {
    keyId: string
    protection: KeyProtection
  }): Promise<SecureKey> {
    if (options.protection === 'user_present' && this.failUserPresentWith) {
      throw this.failUserPresentWith
    }
    this.generated.push(options.keyId)
    this.existing.add(options.keyId)
    return this.describe(options.keyId)
  }

  async getKey(keyId: string): Promise<SecureKey | null> {
    return this.existing.has(keyId) ? this.describe(keyId) : null
  }

  async sign(options: { keyId: string; payload: Uint8Array; reason?: string }) {
    this.signed.push({ keyId: options.keyId, reason: options.reason })
    // A fixed, recognisable 64 bytes: the facade must pass it through
    // untouched, and a length other than 64 would be a JWS the server rejects.
    return new Uint8Array(64).fill(0x2a)
  }

  async deleteKey(keyId: string): Promise<void> {
    this.deleted.push(keyId)
    this.existing.delete(keyId)
  }

  private describe(keyId: string): SecureKey {
    return {
      keyId,
      publicKey: { crv: 'P-256', kty: 'EC', x: 'x', y: 'y' },
      backing: 'software',
      hardwareBacked: false,
    }
  }
}

describe('SignKeypair', () => {
  it('defaults to the ambient key, which never prompts', async () => {
    const backend = new RecordingBackend()
    const signer = new SignKeypair(backend)

    await signer.generateKey()
    await signer.signCompactJws({ nonce: 1 })

    expect(backend.generated).toEqual([DEFAULT_KEY_ID])
    expect(backend.signed[0]?.keyId).toBe(DEFAULT_KEY_ID)
  })

  it('carries the reason through to the prompting key', async () => {
    const backend = new RecordingBackend()
    const signer = new SignKeypair(backend)

    await signer.signCompactJws(
      { amount: 1 },
      { keyId: DEFAULT_USER_PRESENT_KEY_ID, reason: 'Confirm this transfer' }
    )

    expect(backend.signed[0]).toEqual({
      keyId: DEFAULT_USER_PRESENT_KEY_ID,
      reason: 'Confirm this transfer',
    })
  })

  describe('signCompactJws', () => {
    it('emits the exact ES256 protected header a verifier expects', async () => {
      const signer = new SignKeypair(new RecordingBackend())

      const [header] = (await signer.signCompactJws({ a: 1 })).split('.')

      // Key order is part of the encoded bytes, so this is a byte-for-byte
      // assertion, not a "parses to the right object" one.
      expect(new TextDecoder().decode(b64.decode(header!))).toBe(
        '{"alg":"ES256","typ":"JWT"}'
      )
    })

    it('signs exactly the bytes it emits as header.payload', async () => {
      const backend = new RecordingBackend()
      const spy = vi.spyOn(backend, 'sign')
      const signer = new SignKeypair(backend)

      const jws = await signer.signCompactJws({ device: 'abc', ts: 17 })
      const [header, payload, signature] = jws.split('.')

      const signedBytes = spy.mock.calls[0]![0].payload
      expect(new TextDecoder().decode(signedBytes)).toBe(`${header}.${payload}`)
      expect(b64.decode(signature!)).toEqual(new Uint8Array(64).fill(0x2a))
    })

    it('round trips a payload with accented text and nested values', async () => {
      const signer = new SignKeypair(new RecordingBackend())
      const payload = { méthode: 'POST', chemin: '/v1/paiements', tags: ['a', 'b'] }

      const [, encoded] = (await signer.signCompactJws(payload)).split('.')

      expect(JSON.parse(new TextDecoder().decode(b64.decode(encoded!)))).toEqual(payload)
    })

    it('produces three base64url segments with no padding', async () => {
      const signer = new SignKeypair(new RecordingBackend())

      const jws = await signer.signCompactJws({ a: 1 })

      expect(jws.split('.')).toHaveLength(3)
      expect(jws).not.toContain('=')
      expect(jws).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/)
    })
  })

  describe('generateDeviceKeys', () => {
    it('enrols both keys and reports the pair as only as strong as its weaker half', async () => {
      const backend = new RecordingBackend()
      const signer = new SignKeypair(backend)

      const keys = await signer.generateDeviceKeys()

      expect(backend.generated).toEqual([DEFAULT_KEY_ID, DEFAULT_USER_PRESENT_KEY_ID])
      expect(keys.hardwareBacked).toBe(false)
    })

    /**
     * A device holding an ambient key the backend has never seen is worse than
     * a device holding neither: it looks enrolled to itself and unknown to the
     * server, so every request is rejected and the client cannot tell that from
     * a revocation.
     */
    it('rolls the ambient key back when the user-present key cannot be made', async () => {
      const backend = new RecordingBackend()
      backend.failUserPresentWith = new SignKeypairError(
        SignerErrorCode.userAuthenticationRequired,
        'no screen lock'
      )
      const signer = new SignKeypair(backend)

      const raised = await signer.generateDeviceKeys().catch((e: unknown) => e)

      expect((raised as SignKeypairError).code).toBe(SignerErrorCode.userAuthenticationRequired)
      expect(backend.deleted).toEqual([DEFAULT_KEY_ID])
      expect(await signer.hasKey()).toBe(false)
    })

    /**
     * The rollback must NOT run for a key that was already the device's live
     * identity — deleting it would turn a failed upgrade into a full lockout.
     */
    it('leaves a pre-existing ambient key alone when the upgrade fails', async () => {
      const backend = new RecordingBackend()
      const signer = new SignKeypair(backend)
      await signer.generateKey()

      backend.failUserPresentWith = new SignKeypairError(
        SignerErrorCode.userAuthenticationRequired,
        'no screen lock'
      )
      await signer.generateDeviceKeys({ overwrite: true }).catch(() => undefined)

      expect(backend.deleted).toEqual([])
      expect(await signer.hasKey()).toBe(true)
    })
  })

  it('reports a missing key as null rather than throwing', async () => {
    const signer = new SignKeypair(new RecordingBackend())

    expect(await signer.getKey()).toBeNull()
    expect(await signer.hasKey()).toBe(false)
    expect(await signer.getPublicKeyJwk()).toBeNull()
  })
})

describe('SignKeypairError', () => {
  /**
   * Tauri rejects with the serialized Rust `Error`, which is `{code, message}`.
   * The code is what survives this boundary, and it must: a frontend that
   * cannot tell "the user cancelled" from "this key was destroyed" will handle
   * both wrongly.
   */
  it('recovers the code from a Tauri rejection', () => {
    const error = SignKeypairError.from({
      code: 'user_authentication_cancelled',
      message: 'dismissed',
    })
    expect(error.code).toBe(SignerErrorCode.userAuthenticationCancelled)
    expect(error.message).toBe('dismissed')
  })

  /**
   * An unrecognised code becomes `unknown` but keeps its raw string, so a
   * native build newer than this package stays diagnosable instead of being
   * flattened into a generic failure.
   */
  it('keeps an unrecognised code on rawCode', () => {
    const error = SignKeypairError.from({ code: 'quantum_lockout', message: 'new' })
    expect(error.code).toBe(SignerErrorCode.unknown)
    expect(error.rawCode).toBe('quantum_lockout')
  })

  it('survives a plain Error or a string', () => {
    expect(SignKeypairError.from(new Error('boom')).code).toBe(SignerErrorCode.unknown)
    expect(SignKeypairError.from('boom').message).toBe('boom')
  })

  it('passes an already-typed error through unchanged', () => {
    const original = new SignKeypairError(SignerErrorCode.keyNotFound, 'gone')
    expect(SignKeypairError.from(original)).toBe(original)
  })
})
