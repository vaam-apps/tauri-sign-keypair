# sign-keypair example

A minimal Tauri v2 app that exercises the plugin: enrol, sign, verify, delete.

```bash
# From the repository root, once: the example depends on the built JS package.
npm install && npm run build

cd examples/tauri-app
npm install
npm run tauri dev
```

## What it shows

The **verify** button is the interesting one. It re-verifies the JWS in the
WebView with `crypto.subtle.verify`, against the JWK the plugin reported — not
against anything the plugin produced internally. A coordinate-encoding bug would
fail there rather than at a server, weeks later, roughly 1 request in 256.

On desktop, `generateDeviceKeys()` **fails** with `hardware_unavailable`, and
`getKey()` immediately afterwards returns `null`. That is not a broken demo: it
is the enrolment rollback working. The ambient key is created, the user-present
key is refused because there is no secure element to enforce presence, and the
ambient key is then deleted so the device is left exactly as it started rather
than holding a key the backend has never seen.

Press `generateKey() — ambient only` to get a usable key on this platform.

## Running the same page in a plain browser

```bash
npm run dev          # then open http://localhost:5173 in a normal browser
```

`isTauri()` is false there, so the frontend picks the WebCrypto backend instead
of the Tauri one, with no change to the page. The header line tells you which
you are on. It is a quick way to see that the two backends behave identically
apart from the platform tag — including refusing the same two things.

## On a device

```bash
npm run tauri android dev
npm run tauri ios dev
```

Those need the Android SDK / Xcode, and are where the plugin actually does what
it exists to do: `generateDeviceKeys()` succeeds, `hardwareBacked` is true, and
signing with the user-present key raises a biometric prompt.
