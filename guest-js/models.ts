/**
 * The wire vocabulary shared with Rust, Kotlin and Swift.
 *
 * The IPC can only carry JSON, so these cross as strings — but each string is
 * written in exactly one place and parsed in exactly one place, and every
 * comparison elsewhere is on the union type. These must stay in step with
 * `src/models.rs`, `src/error.rs`, `android/.../Wire.kt` and
 * `ios/Sources/SignKeypair/Wire.swift`.
 */

/** Where the private key actually lives, in decreasing order of assurance. */
export const KeyBacking = {
  /** Android StrongBox — a discrete, tamper-resistant security chip. */
  strongBox: 'strongbox',
  /** Apple Secure Enclave — a separate coprocessor. P-256 only. */
  secureEnclave: 'secure_enclave',
  /** Android TEE — key material held by secure-world firmware. */
  trustedExecutionEnvironment: 'tee',
  /** Apple Keychain, hardware-protected but not the Secure Enclave itself. */
  keychain: 'keychain',
  /** In-process key. The scalar is reachable from process memory. */
  software: 'software',
} as const

export type KeyBacking = (typeof KeyBacking)[keyof typeof KeyBacking]

/**
 * True when the private key cannot be read out of the device.
 *
 * `keychain` is deliberately excluded: a keychain item is OS-protected but is
 * not held by a secure element, and the scalar can in principle be exported.
 *
 * An unrecognised tag answers `false`. **Under-reporting strength is safe,
 * over-reporting is a false security claim** — a newer native build that
 * reports a backing this package has never heard of must not be counted as
 * hardware on the strength of a string nobody validated.
 */
export function isHardwareBacked(backing: string): boolean {
  return (
    backing === KeyBacking.strongBox ||
    backing === KeyBacking.secureEnclave ||
    backing === KeyBacking.trustedExecutionEnvironment
  )
}

/** What the secure element demands before it will sign with a key. */
export const KeyProtection = {
  /**
   * No user-presence binding. Never prompts. Signs the low- and medium-risk
   * operations that happen silently, in the background, or on every request.
   */
  ambient: 'ambient',
  /**
   * Bound to a live biometric or the device credential. Prompts on every use.
   *
   * In-process code can still *use* an ambient key, because a secure element
   * signs whatever it is asked to; it cannot use this one.
   */
  userPresent: 'user_present',
} as const

export type KeyProtection = (typeof KeyProtection)[keyof typeof KeyProtection]

/** An EC P-256 public key in JWK form (RFC 7517 / RFC 7518 §6.2). */
export interface EcPublicJwk {
  /** Always `"P-256"`. */
  crv: 'P-256'
  /** Always `"EC"`. */
  kty: 'EC'
  /** base64url, unpadded, X coordinate. */
  x: string
  /** base64url, unpadded, Y coordinate. */
  y: string
}

/**
 * A handle to a key held by the platform.
 *
 * Deliberately does **not** carry private key material — on the hardware paths
 * there is none to carry, and the web fallback keeps its `CryptoKey` in
 * IndexedDB, unexportable.
 */
export interface SecureKey {
  /** Stable identifier used to address this key on later calls. */
  keyId: string
  /** The public half, ready to send to a backend for device registration. */
  publicKey: EcPublicJwk
  /** Where the private half actually lives, as reported by the platform. */
  backing: KeyBacking
  /**
   * Whether the private key is non-extractable.
   *
   * A `false` here is not an error — it is the fallback working as designed —
   * but it is a fact worth logging.
   */
  hardwareBacked: boolean
}

/** Both of a device's two-key-model keys, as produced by one enrolment. */
export interface DeviceKeyPair {
  /** The silent, no-prompt key. */
  ambient: SecureKey
  /** The prompting key. */
  userPresent: SecureKey
  /**
   * True only when *both* halves are held by a secure element.
   *
   * Deliberately an `&&`: the pair is as trustworthy as its weaker key, and a
   * caller logging "hardware-backed" on the strength of one of them would be
   * recording something false about the other.
   */
  hardwareBacked: boolean
}

/** What the current platform can actually do, probed at runtime. */
export interface SignerCapabilities {
  /** Platform tag: `android`, `ios`, `rust-software`, `web`. */
  platform: string
  /** The strongest backing a `generateKey` call would produce right now. */
  bestAvailableBacking: KeyBacking
  /** Whether a key generated now would be non-extractable. */
  hardwareBacked: boolean
}

/** Why a signer operation failed. Switch on `SignKeypairError.code`. */
export const SignerErrorCode = {
  /** No key exists under the requested id. */
  keyNotFound: 'key_not_found',
  /** A key already exists under that id and `overwrite` was not set. */
  keyAlreadyExists: 'key_already_exists',
  /** Hardware backing was required but the device cannot provide it. */
  hardwareUnavailable: 'hardware_unavailable',
  /** The platform keystore refused the operation. */
  keystoreFailure: 'keystore_failure',
  /**
   * A user-present key was requested or used, but the device has no biometric
   * enrolled and no screen lock set. Recoverable by the user in Settings, which
   * is why it does not share a code with `hardwareUnavailable`.
   */
  userAuthenticationRequired: 'user_authentication_required',
  /**
   * The user dismissed the prompt, or it timed out. Treat as a cancelled
   * action — never as a reason to re-enrol or log out.
   */
  userAuthenticationCancelled: 'user_authentication_cancelled',
  /**
   * The key was destroyed by a change to the device's biometric enrolment.
   * Recovery is to generate a fresh user-present key and register its
   * thumbprint — not a full re-enrolment, and not a logout.
   */
  keyInvalidated: 'key_invalidated',
  /** This platform has no native implementation of the requested operation. */
  unsupportedPlatform: 'unsupported_platform',
  /** A code this build does not know. Read `rawCode`. */
  unknown: 'unknown',
} as const

export type SignerErrorCode = (typeof SignerErrorCode)[keyof typeof SignerErrorCode]

const KNOWN_CODES: readonly string[] = Object.values(SignerErrorCode)

/** Raised when the platform cannot satisfy a request. */
export class SignKeypairError extends Error {
  /** Machine-readable reason. Switch on this. */
  readonly code: SignerErrorCode
  /**
   * The code exactly as the platform sent it.
   *
   * Equal to `code` for everything this package understands, and the raw
   * unrecognised string when `code` is `unknown` — so an unfamiliar failure is
   * still diagnosable instead of being flattened away.
   */
  readonly rawCode: string

  constructor(code: string, message: string) {
    super(message)
    this.name = 'SignKeypairError'
    this.rawCode = code
    this.code = (KNOWN_CODES.includes(code) ? code : SignerErrorCode.unknown) as SignerErrorCode
  }

  /**
   * Normalise whatever a backend threw into a `SignKeypairError`.
   *
   * Tauri rejects with the serialized `Error` from `src/error.rs`, which is
   * `{ code, message }`. Anything else — a DOMException from WebCrypto, a
   * string from a transport failure — becomes `unknown` with its text kept.
   */
  static from(raised: unknown): SignKeypairError {
    if (raised instanceof SignKeypairError) return raised
    if (typeof raised === 'object' && raised !== null) {
      const shape = raised as { code?: unknown; message?: unknown }
      if (typeof shape.code === 'string') {
        return new SignKeypairError(
          shape.code,
          typeof shape.message === 'string' ? shape.message : shape.code
        )
      }
      if (raised instanceof Error) {
        return new SignKeypairError(SignerErrorCode.unknown, raised.message)
      }
    }
    return new SignKeypairError(SignerErrorCode.unknown, String(raised))
  }
}

/** The contract both backends implement. */
export interface SignKeypairBackend {
  capabilities(): Promise<SignerCapabilities>
  generateKey(options: {
    keyId: string
    requireHardware: boolean
    overwrite: boolean
    protection: KeyProtection
  }): Promise<SecureKey>
  getKey(keyId: string): Promise<SecureKey | null>
  sign(options: { keyId: string; payload: Uint8Array; reason?: string }): Promise<Uint8Array>
  deleteKey(keyId: string): Promise<void>
}
