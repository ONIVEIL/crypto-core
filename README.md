# ONIVEIL – crypto core (request for review)

ONIVEIL is a Tor-based messenger in development for Android (iOS planned). This repository contains only the security-relevant core: the session layer (a simplified Double Ratchet), identity/key handling, encrypted local storage, attachment encryption and the wire framing.

**Why not libsignal?** ONIVEIL is serverless P2P over Tor with manual key exchange (a contact code). libsignal assumes X3DH with server-distributed prekey bundles and has no official React Native binding, so the session layer is a custom Double-Ratchet-style design on `@noble/*` primitives: static X25519 ECDH with Ed25519 signatures for the initial agreement, then a DH ratchet. Known trade-off: there are no X3DH ephemeral/one-time prekeys, so the initial step is weaker than Signal's (see [`THREAT_MODEL.md`](THREAT_MODEL.md)). Whether this design is sound is the main question for reviewers ([`AUDIT_QUESTIONS.md`](AUDIT_QUESTIONS.md)).

**How this was built:** ONIVEIL is developed by a single developer, using AI coding assistants as a tool alongside their own design decisions and testing. The design has not yet been independently reviewed; that is the purpose of this repository. Feedback, disagreement and hard questions are genuinely welcome — the goal here is to learn where the design is wrong and go deeper into the subject, not to defend it. See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to reach out.

**What exists:** only `@noble/*` primitives (no custom ciphers), 475 test cases in 20 suites (including 200 seed-based property-based runs of the ratchet state machine, parser fuzzing, and independent test vectors from RFC 7748, the IETF XChaCha20-Poly1305 draft and `node:crypto`), and a written threat model.

**Status:** not production-ready, no security guarantees. Transport and UI are intentionally not included. Reports: see [`SECURITY.md`](SECURITY.md).

## Where to start

| If you want to look at… | Read |
| --- | --- |
| the ratchet / session protocol | `src/crypto/session.ts` (the module header documents the design), `__tests__/session.test.ts`, `__tests__/sessionStateMachine.property.test.ts` |
| the initial key agreement and first-message authentication | `src/crypto/session.ts` (`createSession`, `buildInitialAuthTranscript`, `upgradeChainKeyWithFreshness`), `src/storage/consumedInitialFreshness.ts` |
| key storage and the app lock | `src/crypto/identity.ts`, `src/crypto/keychainOptions.ts`, `src/storage/vaultKey.ts`, `src/security/appLock.ts` |
| encrypted local storage | `src/storage/encryptedStore.ts`, `src/storage/encryptedCollection.ts`, `src/storage/sessions.ts` |
| attachment encryption | `src/crypto/attachmentCrypto.ts` |
| parsing of untrusted input | `src/crypto/messageContent.ts`, `src/crypto/validation.ts`, `src/transport/wireProtocol.ts`, `src/crypto/contactCode.ts` |
| independent verification of the primitives | `__tests__/independentTestVectors.test.ts`, `__tests__/x25519EdgeCases.test.ts` |

### Suggested reading order

1. [`THREAT_MODEL.md`](THREAT_MODEL.md) — what is protected against what, and the known limitations.
2. `src/crypto/session.ts` — the protocol; the module header explains the design step by step.
3. `__tests__/session.test.ts` — the scenarios (ping-pong, lost acknowledgements, tampering, compromise cases).
4. Everything else on demand, using the table above.

### A 30-minute route

- `src/crypto/session.ts` (about 650 lines, roughly half of it comments) and `src/crypto/attachmentCrypto.ts` (about 80 lines).
- In `__tests__/session.test.ts`: the "Ed25519 freshness binding" and "forward-secrecy proof with exact message index" blocks, which show the weakest part of the design (the initial step).
- Then the questions in [`AUDIT_QUESTIONS.md`](AUDIT_QUESTIONS.md), sections 0–2.

### Why so many files?

The repository looks bigger than it is: of the 54 files, 19 are source files (about 3,000 lines, a good part of it comments), 20 are test suites, and the rest is documentation and configuration. The modules are kept small and single-purpose on purpose, and each has a test file of the same name.

## Running the tests

```
npm ci
npm test          # 20 suites, 475 tests
npm run typecheck
```

Node 18 or newer. The tests run under plain Node/Jest; `react-native-keychain` and `@react-native-async-storage/async-storage` are replaced by in-memory mocks, so the real Android Keystore and biometric behavior is **not** exercised by them.

## What is and is not in this repository

Included: `src/crypto`, `src/storage` (encrypted store, per-item collections, sessions, vault key, replay-freshness store), `src/security/appLock.ts`, `src/transport/wireProtocol.ts`, `src/diagnostics.ts` (a tiny logging switch that the storage code imports), and the corresponding tests.

Not included (and therefore **not covered** by anything here): the Tor/Orbot transport, group chat, the messaging layer that wires the pieces together, the UI, and the Android/iOS projects. The repository cannot be built into an app. See [`PUBLIC_CODE_MANIFEST.md`](PUBLIC_CODE_MANIFEST.md) for exactly what was exported, what was changed for the export, and what was verified.

## Language note

Comments and test titles are in English. A number of runtime strings (error messages, diagnostic log lines, UI-facing labels) are still German, because the code lines are kept identical to the original.

## License

MIT — see [`LICENSE`](LICENSE). Contributions and reviews are welcome, see [`CONTRIBUTING.md`](CONTRIBUTING.md). Note that this license covers only the code in this repository, not the rest of the ONIVEIL app.
