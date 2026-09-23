# Changelog

## [0.2.1](https://github.com/vaam-apps/tauri-sign-keypair/compare/v0.2.0...v0.2.1) (2026-09-23)


### Documentation

* pin the install to v0.2.0, and write up the attestation gap ([45eb062](https://github.com/vaam-apps/tauri-sign-keypair/commit/45eb062d532667e3d7148ddf6a1d8d113aabba61))

## [0.2.0](https://github.com/vaam-apps/tauri-sign-keypair/compare/v0.1.0...v0.2.0) (2026-09-22)


### Features

* **example:** add a Tauri app that exercises the plugin end to end ([022692f](https://github.com/vaam-apps/tauri-sign-keypair/commit/022692f1d82ff8bf506bc6358a349213d2f43fc0))
* hardware-backed ES256 signing plugin for Tauri v2 ([bbda23b](https://github.com/vaam-apps/tauri-sign-keypair/commit/bbda23bd3a8160430d4d01e0714d34fbb321803b))
* **linux:** TPM 2.0 backend behind an off-by-default `linux-tpm` feature ([90ef4e0](https://github.com/vaam-apps/tauri-sign-keypair/commit/90ef4e01cb88a464d76a0c5534687be7241c2676))
* **macos:** Secure Enclave backend, with an honest fall-back ([6190025](https://github.com/vaam-apps/tauri-sign-keypair/commit/6190025edd5fb2f4fe11cd53ca96f0314df941d5))
* **windows:** CNG backend against the TPM, and a refusal for user-presence ([0dbac71](https://github.com/vaam-apps/tauri-sign-keypair/commit/0dbac71e4fa4b588e2599fe24da1231417e031e9))


### Bug Fixes

* **ci:** format the cfg-gated modules, and stop fighting setup-android ([de766d6](https://github.com/vaam-apps/tauri-sign-keypair/commit/de766d6957ef929d2cfd091adf61c5440a21aafb))
* **ci:** run a real Android build so Gradle gets tauri.settings.gradle ([7c43719](https://github.com/vaam-apps/tauri-sign-keypair/commit/7c43719d08469173adda41c26112d868b28d81f9))
* **example:** build for mobile, and add a user-present signing button ([81448ed](https://github.com/vaam-apps/tauri-sign-keypair/commit/81448ed5e8ce07e3b77317419d03147ec28ec2f8))
* **linux:** complete the half-applied TPM fixes ([c63fbf6](https://github.com/vaam-apps/tauri-sign-keypair/commit/c63fbf63f5c215993bbc29dde0bbd794604bead4))
* **linux:** six compile errors the CI job found in the TPM backend ([513c331](https://github.com/vaam-apps/tauri-sign-keypair/commit/513c331091288e82d41b68e1a1530963deb3419f))
* **tests:** clean up test keys on panic, not just on success ([08d1607](https://github.com/vaam-apps/tauri-sign-keypair/commit/08d16072c2a89d6b976eab3983d271e17386916a))


### Refactoring

* **desktop:** split the desktop signer behind a Backend trait ([db01a4f](https://github.com/vaam-apps/tauri-sign-keypair/commit/db01a4ffa5e8db7e046e96b15160ab1a495d7a37))


### Documentation

* a six-part explainer for someone new to the domain ([52af6b1](https://github.com/vaam-apps/tauri-sign-keypair/commit/52af6b17c5d21606d6879e5d2225e2f648939fc9))
* Linux TPM design note, and platform docs for the Windows backend ([097e3df](https://github.com/vaam-apps/tauri-sign-keypair/commit/097e3df4be001b305abd2586a8a202d1523411a8))


### Continuous Integration

* require the Linux TPM compile, and give Gradle the file it needs ([0586be5](https://github.com/vaam-apps/tauri-sign-keypair/commit/0586be5497dcd15ef84006d03b5d9fca799bff6d))
