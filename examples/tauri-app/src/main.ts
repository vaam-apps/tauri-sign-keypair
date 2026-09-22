import {
  DEFAULT_KEY_ID,
  SignKeypair,
  SignKeypairError,
  type EcPublicJwk,
} from 'tauri-plugin-sign-keypair-api'

const signer = new SignKeypair()
const out = document.querySelector<HTMLPreElement>('#log')!

/** The last JWS produced, so the verify button has something to check. */
let lastJws: string | undefined
let lastJwk: EcPublicJwk | undefined

function log(line: string, kind?: 'ok' | 'bad') {
  const span = document.createElement('span')
  span.textContent = `${line}\n`
  if (kind) span.className = kind
  out.append(span)
  out.scrollTop = out.scrollHeight
}

/**
 * Run an action, printing whatever it produces — including the failures, which
 * on this platform are half the demonstration.
 *
 * A `SignKeypairError` is printed with its `code`, because that is the thing a
 * caller switches on: `user_authentication_cancelled` means do nothing,
 * `key_invalidated` means register a fresh key, `hardware_unavailable` means
 * this target cannot do what was asked at all.
 */
function action(id: string, label: string, body: () => Promise<void>) {
  document.querySelector<HTMLButtonElement>(`#${id}`)!.addEventListener('click', async () => {
    // Serialised, and the buttons disabled meanwhile. Two of these in flight at
    // once interleave their output under one heading, which makes the log read
    // as though one action produced another's error — and `generateDeviceKeys`
    // racing `generateKey` would genuinely collide on the same alias.
    if (busy) return
    busy = true
    setButtonsEnabled(false)
    log(`\n▸ ${label}`)
    try {
      await body()
    } catch (raised) {
      const error = SignKeypairError.from(raised)
      log(`  ✗ ${error.code}`, 'bad')
      log(`    ${error.message}`, 'bad')
    } finally {
      busy = false
      setButtonsEnabled(true)
    }
  })
}

let busy = false

function setButtonsEnabled(enabled: boolean) {
  for (const button of document.querySelectorAll('button')) button.disabled = !enabled
}

void (async () => {
  const c = await signer.capabilities()
  document.querySelector('#platform')!.textContent =
    `platform: ${c.platform} · best backing: ${c.bestAvailableBacking} · ` +
    `hardware-backed: ${c.hardwareBacked}`
  log(`capabilities() → ${JSON.stringify(c)}`)
  if (!c.hardwareBacked) {
    log(
      'This target has no secure element, so every key below is extractable\n' +
        'and reports itself as such. That is the fallback working as designed —\n' +
        'but it is a fact worth logging, which is why the flag exists.'
    )
  }
})()

action('enrol', 'generateDeviceKeys()', async () => {
  const keys = await signer.generateDeviceKeys()
  log(`  ✓ ambient      ${keys.ambient.backing}`, 'ok')
  log(`  ✓ user-present ${keys.userPresent.backing}`, 'ok')
  log(`  hardwareBacked (both halves): ${keys.hardwareBacked}`)
})

action('enrol-ambient', 'generateKey() — ambient only', async () => {
  const key = await signer.generateKey({ overwrite: true })
  lastJwk = key.publicKey
  log(`  ✓ ${key.keyId} · ${key.backing} · hardwareBacked=${key.hardwareBacked}`, 'ok')
  log(`  JWK → ${JSON.stringify(key.publicKey)}`)
})

action('sign', 'signCompactJws()', async () => {
  const payload = {
    timestamp_ms: Date.now(),
    device_id: 'demo-device',
    method: 'POST',
    path: '/v1/payments/transfer',
  }
  lastJws = await signer.signCompactJws(payload)
  lastJwk = (await signer.getPublicKeyJwk()) ?? undefined
  const [header, body, signature] = lastJws.split('.')
  log(`  ✓ header    ${header}`, 'ok')
  log(`    payload   ${body}`)
  log(`    signature ${signature}`)
})

action('verify', 'verify the last JWS', async () => {
  if (!lastJws || !lastJwk) {
    log('  nothing signed yet — press signCompactJws() first')
    return
  }
  const [header, body, signature] = lastJws.split('.')
  // Verified in the WebView with WebCrypto, against the JWK the plugin
  // reported — not against anything the plugin produced internally. A
  // coordinate-encoding bug would fail here rather than at a server weeks later.
  const key = await crypto.subtle.importKey(
    'jwk',
    { ...lastJwk, ext: true, key_ops: ['verify'] },
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['verify']
  )
  const raw = b64uDecode(signature!)
  const verified = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new Uint8Array(raw),
    new TextEncoder().encode(`${header}.${body}`)
  )
  log(`  signature is ${raw.length} bytes (ES256 requires exactly 64)`)
  log(
    verified ? '  ✓ verified against the reported JWK' : '  ✗ DID NOT VERIFY',
    verified ? 'ok' : 'bad'
  )
  log(`  payload → ${new TextDecoder().decode(b64uDecode(body!))}`)
})

action('inspect', 'getKey()', async () => {
  const key = await signer.getKey()
  log(key ? `  ✓ ${JSON.stringify(key)}` : '  null — this device is not enrolled', key ? 'ok' : undefined)
})

action('delete', 'deleteKey()', async () => {
  await signer.deleteKey({ keyId: DEFAULT_KEY_ID })
  log('  ✓ deleted — the backend registration for it is now stale', 'ok')
})

function b64uDecode(value: string): Uint8Array {
  const padded = value.replace(/-/g, '+').replace(/_/g, '/')
  const binary = atob(padded.padEnd(Math.ceil(padded.length / 4) * 4, '='))
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i)
  return bytes
}
