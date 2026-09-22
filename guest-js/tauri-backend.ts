import { invoke } from '@tauri-apps/api/core'

import * as b64 from './base64url'
import {
  SignKeypairError,
  type KeyProtection,
  type SecureKey,
  type SignKeypairBackend,
  type SignerCapabilities,
} from './models'

/**
 * Talks to the Rust plugin, which talks to AndroidKeyStore, the Secure Enclave,
 * or the desktop software fallback.
 *
 * Bytes cross as base64url rather than as an array of numbers: the IPC carries
 * JSON, and a numeric array triples the payload for no gain.
 */
export class TauriBackend implements SignKeypairBackend {
  async capabilities(): Promise<SignerCapabilities> {
    return this.call<SignerCapabilities>('capabilities')
  }

  async generateKey(options: {
    keyId: string
    requireHardware: boolean
    overwrite: boolean
    protection: KeyProtection
  }): Promise<SecureKey> {
    return this.call<SecureKey>('generate_key', {
      keyId: options.keyId,
      requireHardware: options.requireHardware,
      overwrite: options.overwrite,
      protection: options.protection,
    })
  }

  async getKey(keyId: string): Promise<SecureKey | null> {
    return this.call<SecureKey | null>('get_key', { keyId })
  }

  async sign(options: {
    keyId: string
    payload: Uint8Array
    reason?: string
  }): Promise<Uint8Array> {
    const signature = await this.call<string>('sign', {
      keyId: options.keyId,
      payload: b64.encode(options.payload),
      reason: options.reason ?? null,
    })
    return b64.decode(signature)
  }

  async deleteKey(keyId: string): Promise<void> {
    await this.call<null>('delete_key', { keyId })
  }

  /**
   * The one place a Tauri rejection becomes a typed error.
   *
   * The Rust side serializes its `Error` as `{ code, message }` precisely so
   * the code survives this boundary — a frontend that cannot tell
   * `user_authentication_cancelled` from `key_invalidated` will handle both
   * wrongly.
   */
  private async call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
    try {
      return await invoke<T>(`plugin:sign-keypair|${command}`, args)
    } catch (raised) {
      throw SignKeypairError.from(raised)
    }
  }
}
