import {
  KeyBacking,
  SignKeypairError,
  SignerErrorCode,
  type EcPublicJwk,
  type KeyProtection,
  type SecureKey,
  type SignKeypairBackend,
  type SignerCapabilities,
} from './models'

/**
 * WebCrypto fallback, for a build running in a plain browser rather than in a
 * Tauri WebView.
 *
 * It exists so the same frontend code runs in `vite dev` in a tab, in a
 * Storybook, and in the shipped app — not because a browser can offer what a
 * secure element does.
 *
 * ### What it does and does not buy
 *
 * The `CryptoKey` is generated with `extractable: false`, so `exportKey` on it
 * throws and JavaScript on the page cannot read the scalar. That is a real
 * property and it is stronger than a pure-JS signer holding a `BigInt`. It is
 * still **not** hardware backing: the key is held by the browser, for this
 * origin, subject to the browser's own storage eviction, and anything with
 * script execution on the origin can *use* it freely. So every key here reports
 * `backing: 'software'` and `hardwareBacked: false`.
 *
 * Reporting a distinct `webcrypto` backing was considered and rejected: the
 * classification callers act on is "can the private key be read out of the
 * device", and the honest answer for a browser profile is no better than
 * software. Under-reporting strength is safe; over-reporting is a false
 * security claim.
 *
 * ### Two refusals, deliberately
 *
 * * `requireHardware` fails outright. There is no hardware here to require.
 * * `userPresent` fails outright. WebCrypto has no user-presence binding and
 *   there is no prompt to raise, so `sign` would return happily with nobody at
 *   the keyboard. Handing that back as a user-present key would make every
 *   downstream check that compares protection against key id — an audit log, a
 *   risk score, a backend that demands the prompting key for a sensitive
 *   operation — assert something untrue about how the signature was produced.
 *
 *   The practical consequence is that a browser cannot do user-present
 *   operations at all. That is the correct outcome: a degraded target, not a
 *   quietly-equivalent one. (WebAuthn is the right primitive for user presence
 *   on the web, and it is a different protocol with a different registration
 *   ceremony — not something this plugin can substitute in behind the caller's
 *   back.)
 */
export class WebCryptoBackend implements SignKeypairBackend {
  private static readonly DB_NAME = 'tauri-sign-keypair'
  private static readonly STORE_NAME = 'keys'
  private static readonly ALGORITHM: EcKeyGenParams = {
    name: 'ECDSA',
    namedCurve: 'P-256',
  }

  async capabilities(): Promise<SignerCapabilities> {
    return {
      platform: 'web',
      bestAvailableBacking: KeyBacking.software,
      hardwareBacked: false,
    }
  }

  async generateKey(options: {
    keyId: string
    requireHardware: boolean
    overwrite: boolean
    protection: KeyProtection
  }): Promise<SecureKey> {
    if (options.requireHardware) {
      throw new SignKeypairError(
        SignerErrorCode.hardwareUnavailable,
        'A browser cannot produce a hardware-backed key'
      )
    }
    if (options.protection === 'user_present') {
      throw new SignKeypairError(
        SignerErrorCode.hardwareUnavailable,
        'WebCrypto cannot enforce user presence — user-present operations require a device ' +
          'with a secure element'
      )
    }
    if (!options.overwrite && (await this.read(options.keyId)) !== undefined) {
      throw new SignKeypairError(
        SignerErrorCode.keyAlreadyExists,
        `A key already exists under "${options.keyId}"`
      )
    }

    // `extractable: false` on the *pair*: it applies to the private half, and
    // the public half is derived from it below via `exportKey`, which WebCrypto
    // permits on a public key regardless.
    const pair = await crypto.subtle.generateKey(WebCryptoBackend.ALGORITHM, false, ['sign'])
    const jwk = await this.publicJwk(pair.publicKey)
    await this.write(options.keyId, { privateKey: pair.privateKey, publicKey: jwk })
    return this.describe(options.keyId, jwk)
  }

  async getKey(keyId: string): Promise<SecureKey | null> {
    const record = await this.read(keyId)
    return record === undefined ? null : this.describe(keyId, record.publicKey)
  }

  async sign(options: {
    keyId: string
    payload: Uint8Array
    /** Accepted and ignored: this backend never holds a user-present key. */
    reason?: string
  }): Promise<Uint8Array> {
    const record = await this.read(options.keyId)
    if (record === undefined) {
      throw new SignKeypairError(
        SignerErrorCode.keyNotFound,
        `No key stored under "${options.keyId}"`
      )
    }
    try {
      // WebCrypto's ECDSA output is already IEEE P1363 `r‖s`, fixed width —
      // the DER conversion the Kotlin and Swift sides must perform is simply
      // not needed here.
      const signature = await crypto.subtle.sign(
        { name: 'ECDSA', hash: 'SHA-256' },
        record.privateKey,
        // Copied into a fresh buffer rather than cast: a `Uint8Array` can be
        // backed by a `SharedArrayBuffer`, which `BufferSource` excludes, and
        // silencing that with an assertion would hide a real hazard for the
        // price of one small allocation on a path that already does a signature.
        new Uint8Array(options.payload)
      )
      return new Uint8Array(signature)
    } catch (raised) {
      throw new SignKeypairError(
        SignerErrorCode.keystoreFailure,
        `WebCrypto refused to sign: ${String(raised)}`
      )
    }
  }

  async deleteKey(keyId: string): Promise<void> {
    const db = await this.open()
    await this.transact(db, 'readwrite', (store) => store.delete(keyId))
  }

  // MARK: - helpers

  private describe(keyId: string, publicKey: EcPublicJwk): SecureKey {
    return { keyId, publicKey, backing: KeyBacking.software, hardwareBacked: false }
  }

  private async publicJwk(publicKey: CryptoKey): Promise<EcPublicJwk> {
    const jwk = await crypto.subtle.exportKey('jwk', publicKey)
    if (typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
      throw new SignKeypairError(
        SignerErrorCode.keystoreFailure,
        'WebCrypto returned a public key with no x/y coordinates'
      )
    }
    // Rebuilt rather than passed through: `exportKey` returns key_ops, ext and
    // other members that are not part of the canonical RFC 7638 thumbprint
    // input, and a caller that thumbprints what we hand back must get the same
    // digest a native platform's JWK would produce.
    return { crv: 'P-256', kty: 'EC', x: jwk.x, y: jwk.y }
  }

  private async read(keyId: string): Promise<StoredKey | undefined> {
    const db = await this.open()
    const record = await this.transact<StoredKey | undefined>(db, 'readonly', (store) =>
      store.get(keyId)
    )
    return record ?? undefined
  }

  private async write(keyId: string, record: StoredKey): Promise<void> {
    const db = await this.open()
    await this.transact(db, 'readwrite', (store) => store.put(record, keyId))
  }

  private open(): Promise<IDBDatabase> {
    return new Promise((resolve, reject) => {
      if (typeof indexedDB === 'undefined') {
        reject(
          new SignKeypairError(
            SignerErrorCode.unsupportedPlatform,
            'This environment has no IndexedDB, so a WebCrypto key cannot be persisted'
          )
        )
        return
      }
      const request = indexedDB.open(WebCryptoBackend.DB_NAME, 1)
      request.onupgradeneeded = () => {
        request.result.createObjectStore(WebCryptoBackend.STORE_NAME)
      }
      request.onsuccess = () => resolve(request.result)
      request.onerror = () =>
        reject(
          new SignKeypairError(
            SignerErrorCode.keystoreFailure,
            `Could not open IndexedDB: ${request.error?.message ?? 'unknown error'}`
          )
        )
    })
  }

  private transact<T>(
    db: IDBDatabase,
    mode: IDBTransactionMode,
    body: (store: IDBObjectStore) => IDBRequest
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(WebCryptoBackend.STORE_NAME, mode)
      const request = body(transaction.objectStore(WebCryptoBackend.STORE_NAME))
      request.onsuccess = () => resolve(request.result as T)
      request.onerror = () =>
        reject(
          new SignKeypairError(
            SignerErrorCode.keystoreFailure,
            `IndexedDB rejected the operation: ${request.error?.message ?? 'unknown error'}`
          )
        )
    })
  }
}

/**
 * What IndexedDB holds per key.
 *
 * The `CryptoKey` is stored directly — it is structured-cloneable, and storing
 * the handle rather than any exported form is the whole point: there is no
 * exported form, because the key is not extractable.
 */
interface StoredKey {
  privateKey: CryptoKey
  publicKey: EcPublicJwk
}
