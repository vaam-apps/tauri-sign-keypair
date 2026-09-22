# 3 · Platforms

[← how it works](02-how-it-works.md) · [index](README.md) · next: [Two-key model →](04-two-key-model.md)

---

## The ladder

`KeyBacking` is ordered by **decreasing assurance**. The only question it really
answers is: *can the private key be read out of this device?*

```mermaid
flowchart TB
    SB["<b>strongbox</b><br/>Android · discrete tamper-resistant chip"] --> TEE
    TEE["<b>tee</b><br/>Android · secure-world firmware"] --> SE
    SE["<b>secure_enclave</b><br/>Apple · separate coprocessor"] --> KC
    KC["<b>keychain</b><br/>Apple · OS-protected, <i>no</i> secure element"] --> SW
    SW["<b>software</b><br/>scalar reachable from process memory"]

    SB -.-> H["hardwareBacked: <b>true</b>"]
    TEE -.-> H
    SE -.-> H
    KC -.-> N["hardwareBacked: <b>false</b>"]
    SW -.-> N

    style SB fill:#c8e6c9,stroke:#2e7d32
    style TEE fill:#c8e6c9,stroke:#2e7d32
    style SE fill:#c8e6c9,stroke:#2e7d32
    style KC fill:#fff9c4,stroke:#f9a825
    style SW fill:#ffcdd2,stroke:#c62828
```

**`keychain` is deliberately on the `false` side.** A keychain item is protected
by the OS, but no secure element is *holding* it — in principle it can be
exported. Putting it on the `true` side would be a claim the plugin cannot back.

---

## What each target actually gets you

| Target | Backend | Backing | `hardwareBacked` | Verified? |
|---|---|---|---|---|
| **Android** | AndroidKeyStore + BiometricPrompt | `strongbox` → `tee` → `software` | true on real hardware | ✅ emulator (reports `software` — correct, see below) |
| **iOS** | Secure Enclave, `SecKeyCreateSignature` | `secure_enclave` / `keychain` | **true** | ✅ simulator, real Secure Enclave |
| **macOS** | Security.framework FFI | `secure_enclave` / `keychain` → `software` | true *if signed & entitled* | ⚠️ fall-back path only |
| **Windows** | — not implemented — | `software` | false | ✅ via software tests |
| **Linux** | — not implemented — | `software` | false | ✅ via software tests |
| **Web** | WebCrypto, non-extractable `CryptoKey` | `software` | false | ✅ unit tests |

---

## The decision the plugin makes at startup

```mermaid
flowchart TB
    START(["plugin init"]) --> MOB{"mobile?"}
    MOB -->|"Android"| A["register Kotlin plugin<br/>➜ AndroidKeyStore"]
    MOB -->|"iOS"| I["register Swift plugin<br/>➜ Secure Enclave"]
    MOB -->|"no · desktop"| MAC{"macOS?"}
    MAC -->|"yes"| PROBE{"probe: can we<br/><b>write</b> a key to the<br/>data-protection keychain?"}
    PROBE -->|"yes · signed + entitled"| ENC["Secure Enclave backend"]
    PROBE -->|"no · -34018"| SOFT
    MAC -->|"Windows / Linux"| SOFT["software backend<br/><i>reports 'software'</i>"]

    style ENC fill:#c8e6c9,stroke:#2e7d32
    style A fill:#c8e6c9,stroke:#2e7d32
    style I fill:#c8e6c9,stroke:#2e7d32
    style SOFT fill:#ffcdd2,stroke:#c62828
```

The probe runs **once**. Re-probing per call would mean a machine whose secure
element became unavailable mid-session could silently start issuing software
keys *under the same key id* — the caller would see a key id it recognises with
a backing it did not expect, which is exactly the confusion `hardwareBacked`
exists to prevent.

---

## Two refusals, everywhere there is no secure element

The software and WebCrypto backends **refuse** rather than pretend:

```mermaid
flowchart LR
    R1["requireHardware: true"] --> X1["❌ hardware_unavailable<br/><i>there is no hardware to require</i>"]
    R2["protection: 'user_present'"] --> X2["❌ hardware_unavailable<br/><i>nothing can withhold a signature,<br/>no prompt can be raised</i>"]

    style X1 fill:#fff3e0,stroke:#e65100
    style X2 fill:#fff3e0,stroke:#e65100
```

The second one deserves the emphasis. There is no secure element to withhold a
signature and no platform prompt to raise, so a "user-present" key would sign
happily with **nobody at the keyboard**. Issuing one would make every downstream
check that compares protection against key id — an audit log, a risk score, a
backend that demands the prompting key for a transfer — assert something untrue
about how the signature was produced.

The consequence is that a browser or a Windows build **cannot do user-present
operations at all**. That is the correct outcome: a degraded target, not a
quietly-equivalent one.

---

## Two traps worth knowing

### An emulator cannot prove hardware backing

An Android emulator ships a **software keymaster**. `capabilities()` there
reports `software` and `hardwareBacked: false` — the plugin being honest, not
broken. What an emulator *does* prove is everything except residency: that the
key is created in AndroidKeyStore rather than process memory, that
`getEncoded()` is null, that the DER→P1363 conversion is right, that
BiometricPrompt is raised with the authenticators the key was created with, and
that the signature verifies.

An iOS simulator on Apple silicon is different — it exposes a **real** Secure
Enclave, which is why the iOS test shows `hardwareBacked: true`.

### macOS silently degrades without an entitlement

A Secure Enclave key on macOS must live in the data-protection keychain, and
writing there needs a code-signed app with `keychain-access-groups`:

```mermaid
flowchart LR
    U["unsigned / unentitled build"] --> E["errSecMissingEntitlement<br/>(-34018) on every write"]
    E --> P["probe declines"]
    P --> S["software backend<br/><i>reports 'software' honestly</i>"]

    G["signed + entitled build"] --> OK["Secure Enclave<br/><i>reports 'secure_enclave'</i>"]

    style S fill:#ffcdd2,stroke:#c62828
    style OK fill:#c8e6c9,stroke:#2e7d32
```

The probe deliberately performs a **write**, not a read: an unsigned binary is
allowed to read that keychain, so a read-based probe passes and then every real
call fails. See the [build log](06-build-log.md) — that was a real bug.

---

[← how it works](02-how-it-works.md) · [index](README.md) · next: [Two-key model →](04-two-key-model.md)
