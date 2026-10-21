---
title: tauri-plugin-sign-keypair
layout: home

hero:
  name: tauri-plugin-sign-keypair
  text: Device keys that never leave the device
  tagline: Hardware-backed ECDSA P-256 (ES256) signing for device-bound authentication in Tauri v2 apps, via AndroidKeyStore and the Apple Secure Enclave.
  image:
    src: /logo.svg
    alt: tauri-plugin-sign-keypair
  actions:
    - theme: brand
      text: Get started
      link: /getting-started
    - theme: alt
      text: Read the explainer
      link: /README
    - theme: alt
      text: GitHub
      link: https://github.com/vaam-apps/tauri-sign-keypair

features:
  - icon: 🔒
    title: The key stays in the secure element
    details: The private key is generated inside AndroidKeyStore or the Secure Enclave and signing happens there. The raw scalar never enters the WebView, the Rust process or app memory.
    link: /02-how-it-works
    linkText: How it works
  - icon: 🪜
    title: Honest about its backing
    details: Desktop and web fallbacks report software and hardwareBacked false. An unrecognised backing tag maps down to software, never up to hardware.
    link: /03-platforms
    linkText: Six platforms, compared
  - icon: 🗝️
    title: Two keys, two jobs
    details: An ambient key that never prompts, for every request, and a user-present key bound to a biometric or the device credential, for the operations that need a human.
    link: /04-two-key-model
    linkText: The two-key model
  - icon: ✅
    title: Checked by someone else's verifier
    details: Every backend's signature is verified against the JWK it reported, with p256, WebCrypto or java.security, and the DER to P1363 codec has known-answer tests in Kotlin and Swift.
    link: /05-verification
    linkText: How we know it works
---

## Where to start

- **Adding it to an app?** [Getting started](./getting-started.md) covers installing,
  registering the plugin, permissions and a first sign-and-verify.
- **New to device keys, secure elements or JWS?** The [explainer](./README.md) starts
  from "what is a signature" and is meant to be read in order, one through eight.
- **Already have enrolled devices?** A hardware key cannot be imported, so moving a
  device onto one means re-enrolment. [Migrating existing devices](./migration.md)
  sets out the options.

## Related project

This plugin is a port of
[vaam-apps/flutter-sign-keypair](https://github.com/vaam-apps/flutter-sign-keypair),
the same hardware-backed signer for Flutter apps. The Kotlin and Swift keystore code
is a direct port; the Rust, TypeScript and WebCrypto sides are new. Fixes do not flow
automatically between the two projects.
