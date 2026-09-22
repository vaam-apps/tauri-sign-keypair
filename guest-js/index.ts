/**
 * Hardware-backed ES256 signing for device-bound authentication.
 *
 * See `README.md` for the why. The short version: a signer that keeps the
 * private scalar in process memory hands the credential to anything that can
 * read the process. This package moves both the key and the signing operation
 * into AndroidKeyStore / the Apple Secure Enclave, so the scalar never exists
 * outside the secure element.
 */

import { isTauri } from '@tauri-apps/api/core'

import * as b64 from './base64url'
import {
  KeyProtection,
  SignKeypairError,
  type DeviceKeyPair,
  type SecureKey,
  type SignKeypairBackend,
  type SignerCapabilities,
} from './models'
import { TauriBackend } from './tauri-backend'
import { WebCryptoBackend } from './web-backend'

export * from './models'

/**
 * The key id used when a caller does not name one — the *ambient* key, meant to
 * be signed with on every request, including from a background interceptor or
 * polling timer.
 *
 * Stable on purpose: a device that already holds a key under this id keeps it
 * and gains the user-present key alongside, rather than being forced through a
 * re-enrolment ceremony to pick up a new alias.
 */
export const DEFAULT_KEY_ID = 'device'

/**
 * The key id for the *user-present* key — the one that prompts.
 *
 * A separate alias rather than a flag on the same one, because the platform
 * stores the protection policy *with* the key: one alias cannot be both
 * prompting and silent, and rewriting it to switch would destroy the key.
 */
export const DEFAULT_USER_PRESENT_KEY_ID = 'device_user_present'

/**
 * The fixed JWS protected header for ES256, pre-encoded once.
 *
 * A JWS verifier expects exactly `{"alg":"ES256","typ":"JWT"}`; key order is
 * part of the encoded bytes, so this is a literal rather than a serialized
 * object.
 */
const PROTECTED_HEADER = b64.encodeText('{"alg":"ES256","typ":"JWT"}')

/** Options every keyed call accepts. */
export interface KeyIdOptions {
  /** Defaults to {@link DEFAULT_KEY_ID}. */
  keyId?: string
}

/** Options for {@link SignKeypair.generateKey}. */
export interface GenerateKeyOptions extends KeyIdOptions {
  /**
   * Make a device without a secure element fail loudly instead of silently
   * getting a software key.
   */
  requireHardware?: boolean
  /**
   * Replace an existing key. That invalidates whatever device registration your
   * backend holds for it, so it must be followed by re-registering the new
   * `publicKey`.
   */
  overwrite?: boolean
  /** Defaults to `ambient`, which is the key on the hot path. */
  protection?: KeyProtection
}

/** Options for {@link SignKeypair.signCompactJws} and {@link SignKeypair.signRaw}. */
export interface SignOptions extends KeyIdOptions {
  /**
   * The localized sentence shown in the authentication prompt for a
   * user-present key. Ignored for ambient keys, which never prompt.
   *
   * Every user-present call site should pass its own copy. Omitting it shows
   * whatever generic string the platform falls back to, in whatever language
   * the platform picked — treat seeing that in production as a bug.
   */
  reason?: string
}

/**
 * The app-facing API.
 *
 * Shaped around one specific job — build a JSON payload, wrap it in a fixed
 * ES256 header, sign, emit compact JWS — rather than a general-purpose crypto
 * surface.
 *
 * ```ts
 * const signer = new SignKeypair()
 * const keys = await signer.generateDeviceKeys()   // once, at enrolment
 * await registerDevice(keys.ambient.publicKey)     // send the JWK to your backend
 * const jws = await signer.signCompactJws({ payload: { nonce } })
 * ```
 */
export class SignKeypair {
  private readonly backend: SignKeypairBackend

  /**
   * Uses the platform default backend unless one is passed in (tests).
   *
   * The default is the Tauri plugin when running inside a Tauri WebView, and
   * WebCrypto otherwise — see {@link WebCryptoBackend} for what that does and
   * does not buy.
   */
  constructor(backend?: SignKeypairBackend) {
    this.backend = backend ?? (isTauri() ? new TauriBackend() : new WebCryptoBackend())
  }

  /** What this device can actually do. Probe once at startup and log it. */
  capabilities(): Promise<SignerCapabilities> {
    return this.backend.capabilities()
  }

  /** True when a key generated right now would be non-extractable. */
  async isHardwareBackingAvailable(): Promise<boolean> {
    return (await this.capabilities()).hardwareBacked
  }

  /**
   * Create one device signing key.
   *
   * For the user-present key prefer {@link generateDeviceKeys}, which enrols
   * both as one unit — see its doc for why a bare pair of calls is the wrong
   * shape at enrolment time.
   */
  generateKey(options: GenerateKeyOptions = {}): Promise<SecureKey> {
    return this.backend.generateKey({
      keyId: options.keyId ?? DEFAULT_KEY_ID,
      requireHardware: options.requireHardware ?? false,
      overwrite: options.overwrite ?? false,
      protection: options.protection ?? KeyProtection.ambient,
    })
  }

  /**
   * Create both keys of the two-key model as a single unit, for enrolment.
   *
   * The hazard this closes: a device that registers one key and fails on the
   * second must not end up half-enrolled. A device holding an ambient key the
   * backend has never seen is worse than a device holding neither — it looks
   * enrolled to itself and unknown to the server, so every request is rejected
   * and the client cannot tell that from a revocation.
   *
   * So if the user-present key fails — no biometric enrolled, no screen lock, a
   * keymaster that refuses the spec — the ambient key created moments earlier is
   * deleted and the original error is rethrown. The caller gets a device in the
   * state it started in.
   *
   * The rollback deliberately does **not** run when the ambient key already
   * existed and `overwrite` was false: that key is the device's live identity,
   * and deleting it would turn a failed user-present-key upgrade into a full
   * lockout.
   */
  async generateDeviceKeys(
    options: {
      ambientKeyId?: string
      userPresentKeyId?: string
      requireHardware?: boolean
      overwrite?: boolean
    } = {}
  ): Promise<DeviceKeyPair> {
    const ambientKeyId = options.ambientKeyId ?? DEFAULT_KEY_ID
    const userPresentKeyId = options.userPresentKeyId ?? DEFAULT_USER_PRESENT_KEY_ID
    const requireHardware = options.requireHardware ?? false
    const overwrite = options.overwrite ?? false

    const ambientPreexisting = await this.hasKey({ keyId: ambientKeyId })
    const ambient = await this.generateKey({ keyId: ambientKeyId, requireHardware, overwrite })

    try {
      const userPresent = await this.generateKey({
        keyId: userPresentKeyId,
        requireHardware,
        overwrite,
        protection: KeyProtection.userPresent,
      })
      return {
        ambient,
        userPresent,
        hardwareBacked: ambient.hardwareBacked && userPresent.hardwareBacked,
      }
    } catch (raised) {
      if (!ambientPreexisting) {
        // Best-effort: if the rollback itself fails there is nothing further to
        // try, and swallowing it here keeps the original cause — the reason the
        // user-present key could not be made — as the error the caller sees.
        try {
          await this.deleteKey({ keyId: ambientKeyId })
        } catch {
          // Deliberately ignored; see above.
        }
      }
      throw SignKeypairError.from(raised)
    }
  }

  /** The existing key handle, or `null` when the device is not enrolled. */
  getKey(options: KeyIdOptions = {}): Promise<SecureKey | null> {
    return this.backend.getKey(options.keyId ?? DEFAULT_KEY_ID)
  }

  /** Whether a key exists under `keyId`. */
  async hasKey(options: KeyIdOptions = {}): Promise<boolean> {
    return (await this.getKey(options)) !== null
  }

  /** The public key as a JWK, ready to POST to device registration. */
  async getPublicKeyJwk(options: KeyIdOptions = {}): Promise<SecureKey['publicKey'] | null> {
    return (await this.getKey(options))?.publicKey ?? null
  }

  /**
   * Sign raw bytes, returning a 64-byte IEEE P1363 `r‖s` signature.
   *
   * Prefer {@link signCompactJws} — this is the escape hatch for callers that
   * build their own signing input.
   */
  signRaw(signingInput: Uint8Array, options: SignOptions = {}): Promise<Uint8Array> {
    return this.backend.sign({
      keyId: options.keyId ?? DEFAULT_KEY_ID,
      payload: signingInput,
      reason: options.reason,
    })
  }

  /**
   * Sign `payload` and return a compact ES256 JWS: `header.payload.signature`.
   *
   * This is meant for a hot path — a request interceptor that signs every
   * authenticated call — which is why `keyId` defaults to the ambient key that
   * never prompts.
   *
   * For an operation that should demand a live human, pass
   * {@link DEFAULT_USER_PRESENT_KEY_ID} and a localized `reason`.
   *
   * `payload` is serialized here, in TypeScript, and never re-serialized by
   * Rust: routing it through another JSON implementation could reorder its keys,
   * and a payload whose key order differs between what the caller sees and what
   * was signed fails verification with nothing useful in the logs.
   */
  async signCompactJws(
    payload: Record<string, unknown>,
    options: SignOptions = {}
  ): Promise<string> {
    const signingInput = `${PROTECTED_HEADER}.${b64.encodeText(JSON.stringify(payload))}`
    const signature = await this.signRaw(new TextEncoder().encode(signingInput), options)
    return `${signingInput}.${b64.encode(signature)}`
  }

  /** Delete the device key. The device must re-enrol afterwards. */
  deleteKey(options: KeyIdOptions = {}): Promise<void> {
    return this.backend.deleteKey(options.keyId ?? DEFAULT_KEY_ID)
  }
}

export { TauriBackend, WebCryptoBackend }
