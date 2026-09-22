import { describe, expect, it } from 'vitest'

import * as b64 from './base64url'

describe('base64url', () => {
  it('uses the URL alphabet and drops padding, as RFC 7515 requires', () => {
    // 0xfb 0xff picks out both substituted characters: standard base64 would
    // emit `+/` here, and a JWS carrying those is rejected by strict verifiers.
    expect(b64.encode(new Uint8Array([0xfb, 0xff, 0xfe]))) .toBe('-__-')
    expect(b64.encode(new Uint8Array([1]))).toBe('AQ')
    expect(b64.encode(new Uint8Array([]))).toBe('')
  })

  it('round trips arbitrary bytes', () => {
    const bytes = new Uint8Array(257)
    for (let i = 0; i < bytes.length; i += 1) bytes[i] = i % 256
    expect(b64.decode(b64.encode(bytes))).toEqual(bytes)
  })

  it('accepts padding a caller added', () => {
    expect(b64.decode('AQ==')).toEqual(new Uint8Array([1]))
    expect(b64.decode('AQ')).toEqual(new Uint8Array([1]))
  })

  /**
   * A signing input is unbounded because the caller chooses the payload, and
   * `String.fromCharCode(...bytes)` overflows the call stack somewhere around
   * 100k arguments. This is the regression test for the chunking that avoids it.
   */
  it('encodes a payload far larger than the argument limit', () => {
    const bytes = new Uint8Array(300_000).fill(0x41)
    const encoded = b64.encode(bytes)
    expect(b64.decode(encoded)).toEqual(bytes)
  })

  it('encodes text as UTF-8 before base64url', () => {
    // Accented text exercises multi-byte UTF-8, which a `charCodeAt`-based
    // encoder would silently truncate — and a truncated payload produces a JWS
    // whose signature covers different bytes than the server parses.
    expect(b64.decode(b64.encodeText('é'))).toEqual(new Uint8Array([0xc3, 0xa9]))
  })
})
