/**
 * base64url without padding, as RFC 7515 requires.
 *
 * One module rather than an inline `btoa(...).replace(...)` at each call site,
 * because a single padded or standard-alphabet encoding slipping in produces a
 * JWS that verifiers reject, or a JWK whose thumbprint does not match the one
 * the same key produced elsewhere.
 */

/** Encode bytes as unpadded base64url. */
export function encode(bytes: Uint8Array): string {
  let binary = ''
  // Chunked rather than `String.fromCharCode(...bytes)`: spreading a large
  // array into an argument list overflows the call stack, and a signing input
  // is unbounded because the caller chooses the payload.
  const CHUNK = 0x8000
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK))
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Decode unpadded base64url, tolerating padding a caller may have added. */
export function decode(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='))
  const out = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i)
  return out
}

/** UTF-8 encode, then base64url. */
export function encodeText(text: string): string {
  return encode(new TextEncoder().encode(text))
}
