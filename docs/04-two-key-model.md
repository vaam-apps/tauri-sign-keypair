# 4 · The two-key model

[← platforms](03-platforms.md) · [index](README.md) · next: [Verification →](05-verification.md)

---

## The problem one key cannot solve

Your app signs two very different kinds of request:

```mermaid
flowchart LR
    subgraph Hot["Hot path · thousands per session"]
        H1["every API call"]
        H2["background polling timer"]
        H3["push-notification handler"]
        H4["app in the background, screen off"]
    end
    subgraph Rare["Deliberate actions · a few per month"]
        R1["transfer £500"]
        R2["add a payee"]
        R3["change security settings"]
    end
```

Now try to serve both with **one** key:

```mermaid
flowchart TB
    Q{"one key —<br/>require a biometric?"}
    Q -->|"YES"| A["🚫 every background poll<br/>tries to prompt…<br/>…with no screen to prompt on"]
    Q -->|"NO"| B["🚫 malware in your app signs<br/>a £500 transfer exactly as<br/>easily as a status ping"]

    style A fill:#ffebee,stroke:#c62828
    style B fill:#ffebee,stroke:#c62828
```

Neither is acceptable. So: **two keys**, with different rules baked in at
creation time.

---

## The split

```mermaid
flowchart TB
    subgraph Amb["🔑 ambient · key id 'device'"]
        A1["no user-presence binding"]
        A2["<b>never prompts</b>"]
        A3["survives biometric re-enrolment"]
        A4["for: every request, background timers"]
    end
    subgraph UP["🔐 user-present · key id 'device_user_present'"]
        U1["bound to a live biometric<br/>OR the device passcode"]
        U2["<b>prompts on every use</b>"]
        U3["destroyed if biometrics are re-enrolled"]
        U4["for: transfers, security changes"]
    end

    style Amb fill:#e3f2fd,stroke:#1565c0
    style UP fill:#fff3e0,stroke:#e65100
```

### Why two key *ids* rather than a flag

The platform stores the policy **with the key**. One alias cannot be both
prompting and silent, and rewriting it to switch would destroy the key. So the
protection level is permanent from the moment of creation — which is also why an
unrecognised protection tag is a hard failure rather than a default.

### What the split actually buys

In-process malware can still *use* the ambient key — a secure element signs
whatever it is asked to. It **cannot** use the user-present one without a human
authenticating. So your backend can require the stronger key for a sensitive
endpoint and that requirement means something.

---

## Enrolment is all-or-nothing

```mermaid
sequenceDiagram
    participant C as generateDeviceKeys()
    participant P as platform

    C->>P: does 'device' already exist?
    Note over C: remember the answer — it decides<br/>whether rollback is safe

    C->>P: create ambient key
    P-->>C: ✅
    C->>P: create user-present key
    alt success
        P-->>C: ✅
        C-->>C: return both
    else fails — no screen lock, no biometric, keymaster refuses
        P-->>C: ❌
        alt ambient did NOT pre-exist
            C->>P: delete the ambient key
            Note right of C: device is exactly as it started
        else ambient DID pre-exist
            Note right of C: leave it — it is the device's<br/>live identity. Deleting it turns a<br/>failed upgrade into a full lockout.
        end
        C-->>C: rethrow the original error
    end
```

**The hazard this closes:** a device holding an ambient key the backend has never
seen is *worse* than a device holding neither. It looks enrolled to itself and
unknown to the server, so every request is rejected — and the client cannot tell
that from a revocation.

---

## Biometric invalidation, and why only one key carries it

Both platforms can destroy a key when the biometric enrolment changes:
`setInvalidatedByBiometricEnrollment(true)` on Android, `.biometryCurrentSet` on
Apple. The plugin puts that flag on the **user-present key alone**.

```mermaid
flowchart TB
    E["😈 attacker adds their own fingerprint"] --> INV["user-present key is destroyed"]
    INV --> OK["✅ ambient key untouched"]
    OK --> REC["device can still authenticate itself<br/>while it regenerates and re-registers<br/>the user-present key"]

    ALT["if BOTH keys carried the flag"] -.-> BAD["❌ the device loses its whole identity<br/>and needs a full out-of-band<br/>re-enrolment ceremony"]

    style OK fill:#e8f5e9,stroke:#2e7d32
    style BAD fill:#ffebee,stroke:#c62828
```

### Being precise about what the flag buys

Less than it first reads. Both platforms accept the **device credential**
(passcode / screen lock) alongside biometrics, and neither invalidates a key on
the credential branch. So the flag only bites on the biometry branch.

That does not open a hole, and the reason is worth internalising: **both
platforms require the existing credential before they will accept a newly
enrolled biometric.** An attacker who can add a fingerprint already holds what
the surviving branch would have asked for. The flag is a statement of intent
that costs nothing and helps on the branch where it applies.

The credential branch exists because a meaningful share of real hardware has no
working biometric sensor. Requiring biometrics specifically would lock those
users out of your sensitive operations entirely.

---

## Three failures, three different responses

`SignKeypairError.code` distinguishes them, and **none of the three is a reason
to log the user out**:

```mermaid
flowchart TB
    C1["user_authentication_cancelled"] --> A1["they changed their mind<br/><b>do nothing</b>"]
    C2["user_authentication_required"] --> A2["no screen lock configured<br/><b>send them to Settings</b>"]
    C3["key_invalidated"] --> A3["biometrics were re-enrolled<br/><b>generate a fresh user-present key<br/>and register its thumbprint</b>"]

    style A1 fill:#e3f2fd,stroke:#1565c0
    style A2 fill:#fff3e0,stroke:#e65100
    style A3 fill:#fff3e0,stroke:#e65100
```

Flatten these into one generic error and you will send someone through a full
re-enrolment ceremony because they tapped "Cancel".

---

[← platforms](03-platforms.md) · [index](README.md) · next: [Verification →](05-verification.md)
