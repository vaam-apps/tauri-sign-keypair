# 2 · How it works

[← the problem](01-the-problem.md) · [index](README.md) · next: [Platforms →](03-platforms.md)

---

## The layers

A Tauri app is a **web frontend** talking to a **Rust backend** over a message
bus (the "IPC"). On mobile, Rust in turn talks to native Kotlin or Swift. So one
`signCompactJws()` call crosses three boundaries.

```mermaid
flowchart TB
    subgraph L1["① Frontend · TypeScript"]
        TS["SignKeypair class<br/><i>guest-js/</i>"]
    end
    subgraph L2["② Plugin core · Rust"]
        CMD["commands.rs<br/><i>five IPC commands</i>"]
        DISP["backend dispatcher"]
    end
    subgraph L3["③ Platform"]
        KT["Kotlin<br/>AndroidKeyStore"]
        SW["Swift<br/>Secure Enclave"]
        MAC["Rust FFI<br/>macOS keychain"]
        SOFT["Rust p256<br/>software file"]
    end

    TS -->|"IPC · JSON only"| CMD
    CMD --> DISP
    DISP --> KT & SW & MAC & SOFT

    style L1 fill:#e3f2fd,stroke:#1565c0
    style L2 fill:#fff3e0,stroke:#e65100
    style L3 fill:#e8f5e9,stroke:#2e7d32
```

**Why so many layers?** Each one exists because the layer below it cannot be
reached directly. The WebView cannot call AndroidKeyStore. Rust cannot draw a
biometric prompt. Kotlin cannot be compiled into a macOS binary. Every boundary
is forced, not chosen.

---

## What actually travels: a worked example

You call:

```ts
await signer.signCompactJws({ device_id: 'abc', method: 'POST' })
```

Here is every step, with the actual data.

```mermaid
sequenceDiagram
    autonumber
    participant JS as TypeScript
    participant RS as Rust
    participant NAT as Kotlin / Swift
    participant SE as 🔒 Secure element

    JS->>JS: header = {"alg":"ES256","typ":"JWT"}
    JS->>JS: signingInput =<br/>base64url(header) + "." + base64url(payload)
    Note over JS: "eyJhbGci…J9.eyJkZXZpY2VfaWQ…"

    JS->>RS: invoke("sign", {keyId, payload: base64url(bytes)})
    Note over JS,RS: bytes cross as base64url —<br/>the IPC is JSON, and a number<br/>array would triple the size

    RS->>NAT: run_mobile_plugin("sign", …)
    NAT->>SE: sign these bytes with key "device"
    SE-->>NAT: DER signature (70–72 bytes)
    NAT->>NAT: DER ➜ IEEE P1363 (exactly 64 bytes)
    NAT-->>RS: {signature: base64url}
    RS-->>JS: base64url string

    JS->>JS: jws = signingInput + "." + signature
    Note over JS: "eyJhbGci…J9.eyJkZXZpY2Vf….MEUCIQ…"
```

The result is one string with three dot-separated parts — that is all a compact
JWS is:

```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9 . eyJkZXZpY2VfaWQiOiJhYmMifQ . G7c819mlr7KMg…
└──────── header ────────┘             └────── payload ──────┘      └── signature ──┘
        base64url of the JSON            base64url of your JSON       base64url of 64 bytes
```

Your backend hands that string to any standard JWS library plus the public key
it stored at enrolment, and gets back yes or no.

---

## The one conversion that causes real bugs

Every platform's crypto API returns a signature in **ASN.1 DER**. JWS `ES256`
requires **IEEE P1363**. They encode the same two numbers differently.

```mermaid
flowchart TB
    subgraph DER["ASN.1 DER — what the platform gives you"]
        D1["30 44 &nbsp; 02 20 [r…32 bytes]  02 20 [s…32 bytes]"]
        D2["<i>variable length: 70–72 bytes</i>"]
    end
    subgraph P["IEEE P1363 — what JWS needs"]
        P1["[r…exactly 32] [s…exactly 32]"]
        P2["<i>always 64 bytes, no wrapper</i>"]
    end
    DER -->|"der_to_p1363()"| P

    style DER fill:#fff3e0,stroke:#e65100
    style P fill:#e8f5e9,stroke:#2e7d32
```

### Why this is dangerous rather than merely fiddly

DER encodes integers **minimally**. If `r` happens to start with a zero byte, DER
stores 31 bytes instead of 32. P1363 always wants 32, left-padded with zero.

- That happens roughly **1 time in 256** per component.
- A naive conversion produces a signature that is *valid ECDSA* and that a JWS
  verifier *rejects*.
- So the bug ships, works for weeks, and then one request in ~128 fails with no
  useful error.

```mermaid
flowchart LR
    A["r = 00 2952 02…<br/><i>DER stores 31 bytes</i>"] --> B{"pad where?"}
    B -->|"LEFT ✅"| C["00 2952 02…<br/><i>same number</i>"]
    B -->|"RIGHT ❌"| D["2952 02… 00<br/><i>number × 256</i>"]
    D --> E["🐛 valid ECDSA,<br/>rejected by verifier,<br/>1 request in 256"]

    style C fill:#e8f5e9,stroke:#2e7d32
    style E fill:#ffebee,stroke:#c62828
```

This is why the conversion exists **three times** (Kotlin, Swift, Rust) and each
copy is tested against the *same* known-answer vectors — see
[verification](05-verification.md).

---

## The wire vocabulary, and the asymmetry that matters

The IPC carries JSON, so enums cross as strings. Each language maps
string↔enum in exactly one place and compares on the enum everywhere else.

What a language does with a string it does **not** recognise differs on purpose:

```mermaid
flowchart TB
    subgraph B["Unknown <b>backing</b> tag<br/>e.g. a newer native build says 'titan'"]
        B1["degrade to <code>software</code>"]
        B2["✅ under-reporting strength is safe<br/>❌ over-reporting is a false security claim"]
    end
    subgraph P["Unknown <b>protection</b> tag<br/>e.g. 'elevated'"]
        P1["hard failure — no default"]
        P2["guess 'ambient' ⇒ caller who asked for a prompt<br/>gets a key that signs silently<br/>guess 'user_present' ⇒ background poller<br/>prompts on every tick<br/><b>both directions are harmful</b>"]
    end

    style B fill:#e8f5e9,stroke:#2e7d32
    style P fill:#fff3e0,stroke:#e65100
```

That asymmetry is the single most load-bearing design decision in the plugin.

---

## Where things live in the repo

```
src/                    Rust plugin core
 ├── lib.rs             registration, the SignKeypairExt trait
 ├── commands.rs        the five IPC commands
 ├── models.rs          the wire vocabulary (KeyBacking, KeyProtection, …)
 ├── error.rs           SignerErrorCode + the {code, message} wire error
 ├── asn1.rs            DER ➜ P1363  (Rust copy)
 ├── mobile.rs          adapter to the Kotlin / Swift plugins
 └── desktop/
     ├── mod.rs         Backend trait + one-time probe/dispatch
     ├── macos.rs       Secure Enclave via Security.framework FFI
     └── software.rs    p256, one file per key

android/…/              Kotlin: SecureKeyStore, BiometricPrompt, Wire, codec
ios/Sources/SignKeypair/ Swift: Plugin, Wire, codec
guest-js/               TypeScript API + WebCrypto fallback
darwin_tests/           standalone SwiftPM tests (symlinks to the real sources)
examples/tauri-app/     runnable demo for all targets
```

---

[← the problem](01-the-problem.md) · [index](README.md) · next: [Platforms →](03-platforms.md)
