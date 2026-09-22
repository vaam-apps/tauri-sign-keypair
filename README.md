# tauri-plugin-sign-keypair

Hardware-backed ECDSA P-256 (ES256) signing for device-bound authentication in
Tauri v2 apps.

The private key is generated **inside** AndroidKeyStore or the Apple Secure
Enclave and never leaves it. Signing happens in the secure element; the raw
private scalar never enters the WebView, the Rust process, or app memory.

---

## Why this exists

A device-bound authentication scheme needs to sign requests with a key that is
provably tied to one device. The common approach — generate an EC key pair in
JavaScript (or in Rust) and put it in storage — has two weaknesses this plugin
exists to remove.

### 1. The key stops being extractable

An in-process signer has to pull the raw private scalar into memory on every
signature, because that is the only place it can compute with it. For a
device-bound credential that is the wrong posture: anything that can read the
process — a debugger, a heap dump, a memory-disclosure bug, a compromised
dependency running in the WebView — sees the credential.

With this plugin there is nothing to read. The keystore hands back an opaque
handle whose `getEncoded()` is `null` on Android, and the signature is computed
by the secure element on both mobile platforms.

This is proven, not asserted — see [Verification](#verification).

### 2. Signing is off the UI thread and out of JavaScript

A request-signing key is asked to sign on every authenticated call, including
from background timers and polling loops. Doing that arithmetic in the WebView
costs the same thread that paints the UI. Moving signing into the platform's own
keystore lets the secure element — or, on a real TEE/StrongBox device, dedicated
silicon — do that work instead.

No benchmark is claimed here: the number depends heavily on the device, the
build, and whether the platform is running on real hardware or an emulator with
a software keymaster. Moving the arithmetic out of JavaScript is the right
direction on any device where it matters.

### Existing devices

A hardware key **cannot be imported** — it must be generated inside the element,
which means a new public key, which means re-enrolment. This plugin therefore
does not and cannot silently upgrade an already-enrolled device. See
[`MIGRATION.md`](MIGRATION.md).

---

## Platform support

| Platform | Implementation | Backing reported | Status |
|---|---|---|---|
| **Android** | `AndroidKeyStore` + `java.security.Signature`, `BiometricPrompt` | `strongbox` → `tee` → `software` | Implemented, tested on emulator |
| **iOS** | `SecKeyCreateSignature`, Secure Enclave, `LAContext` | `secure_enclave` / `keychain` | Implemented, tested on simulator |
| **Web** (browser, no Tauri) | WebCrypto, non-extractable `CryptoKey` in IndexedDB | `software` | Implemented, unit-tested |
| **macOS / Windows / Linux** | Rust `p256` software signer, per-key file in the app data dir | `software` | Implemented, unit-tested |

The Secure Enclave supports exactly one curve — NIST P-256 — which is also the
curve JWS ES256 requires, so there is no protocol mismatch to work around.

### The desktop and web paths are deliberately loud

They exist so the app runs everywhere. Their keys are not held by a secure
element, so every key they produce reports `backing: "software"` and
`hardwareBacked: false`. Log that flag; do not assume.

Two things they **refuse** rather than fake:

* `requireHardware: true` fails with `hardware_unavailable`. There is no
  hardware to require.
* `protection: 'user_present'` fails with `hardware_unavailable`. There is no
  secure element to withhold a signature and no platform prompt to raise, so a
  "user-present" key would sign happily with nobody at the keyboard. Issuing one
  would make every downstream check that compares protection against key id — an
  audit log, a risk score, a backend that demands the prompting key for a
  sensitive operation — assert something untrue about how the signature was
  produced.

  The practical consequence is that a browser or a desktop build cannot do
  user-present operations at all. That is the correct outcome: a degraded
  target, not a quietly-equivalent one. (WebAuthn is the right primitive for
  user presence on the web; it is a different protocol with a different
  registration ceremony, and not something this plugin can substitute in behind
  the caller's back.)

### What the WebCrypto fallback does and does not buy

The `CryptoKey` is generated with `extractable: false`, so `exportKey` on it
throws and script on the page cannot read the scalar. That is a real property,
and it is stronger than a pure-JS signer holding a `BigInt`.

It is still not hardware backing: the key is held by the browser, for that
origin, subject to the browser's own storage eviction, and anything with script
execution on the origin can *use* it freely. There is no `webcrypto` backing
value for that reason — the classification callers act on is "can the private
key be read out of the device", and the honest answer for a browser profile is
no better than `software`.

### The desktop store is a file, and says so

The Rust fallback writes one JSON file per key under the app's local data
directory (`0600` on Unix). The scalar is in that file in the clear. That is
inherent to a software key rather than a flaw in this implementation, and it is
why the key reports `software` — but it is a fact worth knowing before shipping
a desktop build that treats the key as a strong credential.

One file per key, not one file holding a map of them: a single file would make
every write a read-modify-write of the whole store, so two instances of the same
app — Tauri's single-instance behaviour is opt-in, so this is a thing users do —
would race, and the loser's device key would silently disappear.

---

## The two-key model, and why the split exists

`generateDeviceKeys()` creates two keys, not one:

- **`ambient`** — no user-presence binding. Never prompts. Meant to be signed
  with on every request, including from a background interceptor or a polling
  timer, where there is no opportunity to show a prompt at all.
- **`user_present`** — bound to a live biometric or the device credential.
  Prompts on every use. Meant for the operations that justify interrupting the
  user: a high-value transfer, a security-sensitive change, anything where you
  want cryptographic proof a human was present, not just that the app was
  running.

The reason for two keys instead of one is not that biometrics are hard to wire
up — it is that a single key cannot correctly serve both populations of request.
Requiring user presence on every signature means prompting on every background
poll, in a context where no UI is available to show a prompt. Not requiring it
at all means a compromised or automated process in the app can sign a sensitive
operation exactly as easily as a routine one. A backend that wants to require
the stronger key for a sensitive endpoint needs that key to actually mean
something — which is what the split buys: in-process code can still *use* the
ambient key (a secure element signs whatever it is asked to), but it cannot
produce a signature from the user-present key without a human authenticating.

`generateDeviceKeys()` creates both as one unit and rolls the ambient key back
if the user-present one cannot be created — so a device is never left holding a
key your backend has never seen. A *pre-existing* ambient key is never rolled
back this way, since deleting a device's already-registered identity because a
later upgrade failed would turn a failed enrolment into a lockout.

The flag that makes a re-enrolled biometric not silently inherit the old key's
authority — `setInvalidatedByBiometricEnrollment` on Android,
`.biometryCurrentSet` on iOS — is carried by the **user-present key alone**.
Losing that flag would mean anyone who can add a new fingerprint to the device
gains the authority that key represents. Carrying it only on that key also means
a fresh biometric enrolment invalidates only the prompting key, not the whole
device: the ambient key is untouched, so the device can still authenticate
itself while the user-present key is regenerated and re-registered.

Both platforms also accept the device credential (passcode / screen lock)
alongside biometrics for the user-present key, because a meaningful share of
real hardware has no working biometric sensor. That does not weaken the
biometric-invalidation property: both platforms require the *existing*
credential before they will accept a newly enrolled biometric, so an attacker
who can add a fingerprint already holds what the device-credential branch would
have asked for anyway.

## Key backing, and why unknown maps down to software

`KeyBacking` is ordered by decreasing assurance: `strongbox`, `secure_enclave`
and `tee` (all non-extractable, hardware-isolated), then `keychain`
(OS-protected but not secure-element-held, so in principle exportable), then
`software` (the scalar is reachable from process memory).

Every place a backing tag crosses the IPC and is parsed back into an enum, an
unrecognised tag becomes `software` rather than throwing or guessing something
stronger. That direction is deliberate and load-bearing: **under-reporting
strength is safe, over-reporting is a false security claim.** If a newer native
build reports a backing level the Rust or TypeScript side has never heard of,
falling back to `software` means a caller that checks `hardwareBacked` gets a
conservative answer instead of a wrong one.

`KeyProtection` has the opposite rule on purpose: an unrecognised protection tag
has **no safe default** and fails to parse. Guessing `ambient` for a caller that
asked for the prompting key would hand back a key that signs silently; guessing
`user_present` would make a background signer start prompting on every poll.
Neither wrong guess is safe, so there is no default — a mismatched version
pairing fails loudly at the call instead of producing a key with the wrong
policy baked in.

---

## Installing

```bash
cargo add tauri-plugin-sign-keypair --git https://github.com/vaam-apps/tauri-sign-keypair
npm install github:vaam-apps/tauri-sign-keypair
```

Register the plugin in `src-tauri/src/lib.rs`:

```rust
tauri::Builder::default()
    .plugin(tauri_plugin_sign_keypair::init())
    // ...
```

Grant the frontend access in `src-tauri/capabilities/default.json`:

```json
{
  "permissions": ["sign-keypair:default"]
}
```

`sign-keypair:default` allows every command. None of them can leak key material
— they return public halves, a backing tag and signatures — but `delete_key`
does have a real blast radius: it strands a device whose backend registration
points at the deleted key. An app that never needs to unenrol from the frontend
should list the individual `allow-*` permissions it wants instead.

### Android

The plugin needs the host activity to be a `FragmentActivity` for
`BiometricPrompt`. Tauri's generated activity extends `AppCompatActivity`, which
is one, so nothing is required of you — but a project that has replaced its
activity must keep that. A user-present `sign()` on a non-`FragmentActivity`
fails with `keystore_failure` rather than prompting.

No manifest permissions are needed. AndroidKeyStore needs none, and
`androidx.biometric` has not needed `USE_BIOMETRIC` since it moved to the
unified prompt.

### iOS

Nothing to configure. The plugin does not use `NSFaceIDUsageDescription`-gated
APIs directly — the Security framework raises the prompt during
`SecKeyCreateSignature` — but an app that shows Face ID should carry that
`Info.plist` key anyway, as Apple requires.

---

## Usage

```ts
import { SignKeypair, DEFAULT_USER_PRESENT_KEY_ID } from 'tauri-plugin-sign-keypair-api'

const signer = new SignKeypair()

// Once, at enrolment. Both keys or neither — if the user-present key cannot be
// created, the ambient one is rolled back rather than leaving the device
// half-enrolled.
const keys = await signer.generateDeviceKeys()
await registerDeviceWithBackend({
  ambient: keys.ambient.publicKey,          // {crv, kty, x, y}
  userPresent: keys.userPresent.publicKey,
})

if (!keys.hardwareBacked) {
  console.warn('a device key is software-backed')
}

// On every authenticated request — the ambient key, which never prompts.
const jws = await signer.signCompactJws({
  timestamp_ms: Date.now(),
  device_id: deviceId,
  method: 'POST',
  path: '/v1/payments/transfer',
})

// For a sensitive operation — device management, a security-relevant change, a
// high-value transfer. This one raises a biometric / passcode prompt every
// time, so pass your own localized reason string.
const sensitive = await signer.signCompactJws(
  { amount: 500_00, to: recipient },
  { keyId: DEFAULT_USER_PRESENT_KEY_ID, reason: 'Confirm this transfer' },
)
```

`SignKeypairError.code` distinguishes the three ways a user-present signature
fails, and they need different handling: `user_authentication_cancelled` is a
person changing their mind (do nothing), `user_authentication_required` is a
device with no screen lock (send them to Settings), and `key_invalidated` means
a biometric was re-enrolled (generate a fresh user-present key and register its
thumbprint). **None of the three is a reason to log the user out or to re-run
the enrolment ceremony.**

The API is shaped around one specific job — build a JSON payload, wrap it in a
fixed `{"alg":"ES256","typ":"JWT"}` header, sign, emit compact JWS — rather than
a general-purpose crypto surface. If you need a raw signature over your own
signing input instead, use `signRaw`.

### From Rust

```rust
use tauri_plugin_sign_keypair::{jws, KeyProtection, SignKeypairExt, DEFAULT_KEY_ID};

let signer = app.sign_keypair();
let key = signer.generate_key(DEFAULT_KEY_ID, false, false, KeyProtection::Ambient)?;

let payload = r#"{"nonce":"abc"}"#;
let signing_input = jws::signing_input(payload);
let signature = signer.sign(DEFAULT_KEY_ID, signing_input.as_bytes(), None)?;
let compact = jws::compact(&signing_input, &signature);
```

`jws::signing_input` takes the payload as an already-serialized string rather
than a `serde_json::Value`, and the plugin exposes no `sign_compact_jws` IPC
command. Both are the same decision: re-encoding a map reorders its keys, and a
payload whose key order differs between what the caller sees and what was signed
fails verification on the server with nothing useful in the logs.

### The default biometric prompt copy is a placeholder — override it

The Android prompt's default title (`"Authentication required"`) and cancel
button (`"Cancel"`) are used **only** when a `sign()` call for a user-present
key omits `reason`. Every call site should pass its own localized `reason`,
which both the Android `BiometricPrompt` and the iOS `LAContext.localizedReason`
show in its place. Treat seeing the default string in production as a bug: a
call that forgot to localize its prompt.

### Signatures are not stable

The Rust fallback uses RFC 6979 deterministic `k`; AndroidKeyStore, the Secure
Enclave and WebCrypto use a random `k`. All are valid ES256. Signing the same
payload twice will usually give two different signatures — never treat a
signature as a cache key or an idempotency token.

---

## Verification

### Signature correctness

Each backend's signature is verified **against the public key it reported**,
with a third-party verifier rather than with this project's own code:

* `tests/desktop_signer.rs` verifies the Rust fallback's output with `p256`'s
  verifier, rebuilding the public key from the base64url JWK coordinates the
  plugin hands out — so a coordinate-encoding bug fails there rather than at a
  customer's device registration.
* `guest-js/web-backend.test.ts` does the same for WebCrypto, importing the
  reported JWK with `crypto.subtle.importKey` and verifying with
  `crypto.subtle.verify`.
* `android/src/androidTest/.../SecureKeyStoreTest.kt` does the same on a real
  AndroidKeyStore, converting the P1363 signature back to DER for
  `java.security`'s verifier.

All three also assert the signature is exactly 64 bytes. A DER signature would
be 70–72 bytes and would fail verification roughly 1 time in 256 rather than
every time, which is the kind of bug that ships.

### What an emulator can and cannot prove

An Android emulator ships a **software keymaster**, so `capabilities()` there
reports `backing: "software"` and `hardwareBacked: false`. That is the plugin
being honest, not a bug — and it is worth knowing before reading an emulator run
as evidence of hardware backing. What an emulator *does* prove is everything
except residency: that the key is created in AndroidKeyStore rather than in
process memory, that `getEncoded()` is null, that the DER→P1363 conversion is
right, that `BiometricPrompt` is raised with the authenticators the key was
created with, and that the signature verifies against the reported JWK.

Hardware residency is asserted only by the instrumented suite, and only on a
physical device — on an emulator that assertion is *skipped*, not passed.

### Non-extractability

Claims are checked, not assumed:

- The Android instrumented suite asserts `PrivateKey.getEncoded() == null` and
  `getFormat() == null` (true on every Android device, including an emulator)
  and, **where the device has a real secure element**, that `KeyInfo.securityLevel`
  is `TRUSTED_ENVIRONMENT`, `STRONGBOX` or `UNKNOWN_SECURE`. On an emulator that
  assertion is *skipped*, not passed — an emulator ships a software keymaster and
  cannot prove hardware residency.
- The WebCrypto suite asserts the stored `CryptoKey` has `extractable === false`
  and that `exportKey` on it rejects.
- `KeyBacking::from_wire` maps an unrecognised native backing tag to `software`,
  never optimistically to hardware, and `tests/wire_contract.rs` asserts that
  for five different unrecognised strings.

### DER → IEEE P1363, in two languages

Every platform ECDSA API on mobile emits ASN.1 DER; JWS ES256 requires IEEE
P1363 (`r‖s`, 32 bytes each). The conversion exists twice — Kotlin and Swift —
and **each has its own isolated unit tests**, driven by the *same* known-answer
vectors, which cross-validates the two implementations against one another.
(Rust and WebCrypto need no conversion: `p256` and `SubtleCrypto` both emit
P1363 directly.)

The vectors are genuine P-256 signatures produced by `openssl dgst -sha256
-sign`, selected to hit the shapes that occur only ~1 time in 256. Each expected
value was computed independently, re-encoded to DER, and confirmed with
`openssl dgst -sha256 -verify` against the real public key — so the expectations
are anchored to a third-party implementation rather than to our own output.
Known answers, not round-trips: a round-trip can be self-consistently wrong (an
encoder and decoder sharing a padding bug cancel out).

Covered in each language: a short `r`, a short `s`, both components short, a
high-bit component carrying DER's `0x00` sign byte, the `r=1, s=2` extreme, a
zero component, long-form lengths, an always-64-bytes property check, and
several malformed inputs (empty, truncated, wrong tag, overrunning length,
zero-length INTEGER, trailing bytes) that must fail cleanly rather than read out
of bounds.

### The wire contract

Strings cross the IPC because that is all JSON can carry, but each language maps
wire↔enum in exactly one place (`src/models.rs` and `src/error.rs`, `Wire.kt`,
`Wire.swift`, `guest-js/models.ts`) and compares on enums everywhere else.

An unrecognised wire value is handled deliberately, not incidentally:

| Unknown value | Result | Why |
|---|---|---|
| backing tag | `software` | Fail-safe. Under-reporting strength is harmless; over-reporting is a false security claim. |
| protection tag | hard failure | **No safe default.** Guessing either way produces a key with the wrong policy baked in permanently. |
| error code | `unknown`, raw string kept on `rawCode` | Diagnosable rather than flattened into a generic failure. |

The same vectors are asserted in `tests/wire_contract.rs`, `WireContractTest.kt`
and `WireContractTests.swift`, which is what stops the three mappings drifting
apart.

### Running the tests

```bash
# Rust: wire contract, plus the desktop fallback end to end through a mock app.
cargo test
cargo clippy --all-targets -- -D warnings

# TypeScript: the facade, base64url, and the WebCrypto backend.
npm install && npm test && npm run typecheck

# Swift codec + wire tests — pure SwiftPM, no simulator, no Tauri, ~1 second.
# The sources are symlinks to the files the plugin ships, so this exercises the
# real code rather than a copy that could drift.
cd darwin_tests && swift test

# Kotlin JVM unit tests (DER -> P1363, BigInteger -> coordinate, wire contract).
#
# Run from the EXAMPLE's generated Android project, not from `android/` — that
# directory is a Gradle subproject with no wrapper and no settings of its own.
# `tauri android init` writes a `tauri.settings.gradle` that includes it as
# `:tauri-plugin-sign-keypair` alongside Tauri's own `:tauri-android`, which is
# what supplies its `app.tauri.*` dependencies.
cd examples/tauri-app && npm install && npx tauri android init
cd src-tauri/gen/android && ./gradlew :tauri-plugin-sign-keypair:testDebugUnitTest

# Kotlin instrumented tests (real AndroidKeyStore). Needs a booted device.
./gradlew :tauri-plugin-sign-keypair:connectedDebugAndroidTest
```

---

## The example app

`examples/tauri-app/` is a minimal Tauri v2 app wired to this plugin — enrol,
sign, verify, delete, with the output of every call printed.

```bash
npm install && npm run build      # the example consumes the built JS package
cd examples/tauri-app && npm install && npm run tauri dev
```

Its **verify** button re-verifies the JWS in the WebView with
`crypto.subtle.verify` against the JWK the plugin reported, which is the same
discipline the test suites follow: check the signature against the key the
caller was handed, not against anything the signer produced internally.

Running `npm run dev` alone and opening `http://localhost:5173` in an ordinary
browser loads the identical page against the WebCrypto backend instead, since
`isTauri()` is false there. It is the quickest way to see that both backends
refuse the same two things.

---

## Design notes

### Why bytes cross the IPC as base64url

The Tauri IPC carries JSON. A `Uint8Array` serializes as an array of numbers,
which roughly triples a signing input for no gain, so `sign` takes and returns
unpadded base64url. `guest-js/base64url.ts` is the only place that encoding is
implemented on the frontend, and its chunked encoder exists because
`String.fromCharCode(...bytes)` overflows the call stack on a payload the caller
chose the size of.

### Why every command is `async` on the Rust side

`sign` for a user-present key blocks until BiometricPrompt resolves, and
BiometricPrompt needs the Android main thread to draw itself. A synchronous
Tauri command runs on that thread, so it would deadlock on the prompt it is
waiting for.

### Why the codec has no Tauri import

`EcdsaSignatureCodec` (Swift) and `EcdsaSignatureCodec` (Kotlin) are free of any
Tauri, Security-framework or Android import, precisely so they can be tested
without a simulator, a device or a running app. Getting DER→P1363 wrong is
silent *and* intermittent — the signature is valid ECDSA and the failure
surfaces as an unexplained rejection, roughly 1 time in 256 — so these are the
two files that most need a fast, unconditional test.

---

## Origin

Ported from
[`vaam-apps/flutter-sign-keypair`](https://github.com/vaam-apps/flutter-sign-keypair),
which is itself a fork of
[`webank_secure_signer`](https://github.com/ADORSYS-GIS/webank-mobile/tree/master/packages/webank_secure_signer),
licensed MIT. The Kotlin and Swift keystore code is a direct port; the Rust,
TypeScript and WebCrypto sides are new. Fixes do not flow automatically between
these projects.
