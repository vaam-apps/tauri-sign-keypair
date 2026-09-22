# 1 · The problem

[← index](README.md) · next: [How it works →](02-how-it-works.md)

---

## Start with the goal

Your backend receives a request. It wants to answer one question:

> Did this really come from the device I enrolled, or from someone replaying
> traffic / running a script / using a stolen token?

A password or bearer token cannot answer that. A token is **a secret you send**,
so anyone who captures it becomes you. What you want is **a secret you prove you
have, without sending it.** That is what a signature does.

```mermaid
sequenceDiagram
    participant D as Device
    participant B as Backend

    Note over D,B: ❌ Bearer token — the secret travels
    D->>B: Authorization: Bearer abc123
    Note right of B: anyone who sniffs<br/>this line is now the device

    Note over D,B: ✅ Signature — the secret stays put
    D->>D: signature = sign(request, privateKey)
    D->>B: request + signature
    B->>B: verify(request, signature, publicKey) ✓
    Note right of B: the private key<br/>was never transmitted
```

Capturing a signature gets an attacker nothing: it is valid for *that exact
request* and no other. (Include a timestamp and a nonce in the payload and it is
not even replayable.)

---

## Enrolment, then use

Two phases. Get this shape in your head and the API makes sense.

```mermaid
flowchart TB
    subgraph Once["ENROLMENT · once per device"]
        G["generateDeviceKeys()"] --> K["key pair created<br/>inside the secure element"]
        K --> PUB["public key (JWK)"]
        PUB --> REG["POST to your backend<br/>'this device is key X'"]
    end

    subgraph Every["EVERY REQUEST · thousands of times"]
        S["signCompactJws(payload)"] --> SIG["signature"]
        SIG --> SEND["send with the request"]
        SEND --> V["backend verifies<br/>against stored key X"]
    end

    Once ==> Every

    style Once fill:#fff3e0,stroke:#e65100
    style Every fill:#e3f2fd,stroke:#1565c0
```

The private key never appears in either phase. Only the **public** half is ever
transmitted, and a public key is not a secret — publishing it costs you nothing.

---

## So why is this hard? Where does the key live?

This is the entire problem. You have a private key. It has to persist across app
restarts. Where do you put it?

### Attempt 1 — a variable in JavaScript

Gone when the page reloads. And any script on the page can read it: one
compromised npm dependency and your device credential is exfiltrated.

### Attempt 2 — a file on disk

Survives restarts. But the bytes are *right there*. Malware, a backup, a heap
dump, someone with the laptop — all get the key. And every time you sign, the
key must be loaded into memory, so anything that can read the process sees it.

```mermaid
flowchart LR
    F["🗄️ key file<br/>d = 4f2a9c…"] -->|"read on every signature"| M["process memory"]
    M --> SIGN["sign()"]

    ATT["😈 debugger<br/>heap dump<br/>backup<br/>malicious dependency"] -.->|"all of these<br/>can read it"| M
    ATT -.-> F

    style F fill:#ffebee,stroke:#c62828
    style M fill:#ffebee,stroke:#c62828
    style ATT fill:#fff,stroke:#c62828,stroke-dasharray: 4 4
```

### Attempt 3 — the secure element ✅

Modern phones have a chip (or an isolated CPU mode) that:

1. **Generates** the key internally — the key is *born* in there
2. **Signs** on request — you hand it bytes, it hands back a signature
3. Has **no export function** — not "export is protected", but *there is no such
   API at all*

```mermaid
flowchart LR
    App["your app"] -->|"sign these bytes"| SE
    SE["🔒 secure element<br/>─────────<br/>d = ???<br/><i>no API returns this</i>"] -->|"signature"| App

    ATT["😈 debugger<br/>heap dump<br/>root access"] -.->|"nothing to read —<br/>the key was never<br/>in the OS's memory"| X["🚫"]

    style SE fill:#e8f5e9,stroke:#2e7d32,stroke-width:3px
    style X fill:#e8f5e9,stroke:#2e7d32
```

That is the property this plugin delivers. Android calls it AndroidKeyStore
(backed by TEE or StrongBox); Apple calls it the Secure Enclave.

---

## The catch that shapes everything else

**A hardware key cannot be imported.** You cannot take an existing key and move
it into the secure element — if you could, it would have been extractable, which
defeats the point.

So:

```mermaid
flowchart LR
    OLD["device already enrolled<br/>with a software key"] --> Q{"upgrade to<br/>hardware?"}
    Q -->|"import the old key"| NO["🚫 impossible<br/>by design"]
    Q -->|"generate a new one"| NEW["new key ⇒ new public key<br/>⇒ backend's record is stale<br/>⇒ <b>re-enrolment required</b>"]

    style NO fill:#ffebee,stroke:#c62828
    style NEW fill:#fff3e0,stroke:#e65100
```

This is why the plugin has no `importKey`, and why
[`MIGRATION.md`](../MIGRATION.md) describes migration *strategies* rather than
providing a migration *function*. Moving a fleet onto hardware keys is a
product decision (do you force it? offer it? gate a new feature on it?), not
something a library can do behind your back.

---

## And the catch that creates the two-key model

A secure element signs **whatever it is asked to sign**. It proves the request
came from this device. It does *not* prove a human was involved.

For that you add a second condition: *the element refuses to sign until a
biometric or passcode is presented*. But you cannot put that condition on the
key that signs every background poll — there is no screen to prompt on.

Hence two keys. That is [document 4](04-two-key-model.md).

---

[← index](README.md) · next: [How it works →](02-how-it-works.md)
