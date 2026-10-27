# Public code manifest

## Provenance

- Exported from the private ONIVEIL repository at commit `f0b7350897df57b57046f74b2549d900007759fd` (branch `master`, working tree clean at export time).
- **The git history is not included and was not reviewed for export.** This repository starts without history on purpose.
- Export date: 2026-09-24.
- Updated 2026-10-27 from the same private repository at commit `7112c0a` (branch `audit/hardening-2026-10`). Twelve source files changed since the first export: `crypto/{session,attachmentCrypto,identity,validation,textCodec,contactCode,messageContent}.ts`, `storage/{consumedInitialFreshness,sessions,encryptedCollection,encryptedStore}.ts` and `transport/wireProtocol.ts`. Main additions: authenticated delivery acknowledgements, protection against silently replacing the identity, atomic session + replay-freshness commit, strict UTF-8 decoding, a broader invisible-character filter, strict envelope format checks, and legacy contact-code prefix support.
- Deliberate difference from the private repository in `storage/sessions.ts`: the private app additionally waits for a one-time protocol-epoch migration before touching sessions; that migration code is app-specific and not part of this repository.

## What is included

| Path | Role |
| --- | --- |
| `src/crypto/session.ts` | Double-Ratchet-style session: initial derivation, DH/chain ratchet, first-message signature, replay window |
| `src/crypto/identity.ts`, `keychainOptions.ts` | Identity key generation; Keystore/Keychain options (hardware-backed; app-lock access control) |
| `src/crypto/onionAddress.ts` | Tor v3 onion address derivation from an Ed25519 key |
| `src/crypto/attachmentCrypto.ts` | Per-attachment XChaCha20-Poly1305 encryption |
| `src/crypto/messageContent.ts` | Encoding/decoding and validation of decrypted message content |
| `src/crypto/contactCode.ts`, `fingerprint.ts`, `validation.ts`, `textCodec.ts` | Contact code, safety number, input validation/sanitizing, non-throwing UTF-8 decoder |
| `src/storage/encryptedStore.ts`, `encryptedCollection.ts` | Encrypted key-value store and per-item encrypted collections (with AAD binding) |
| `src/storage/sessions.ts`, `vaultKey.ts`, `consumedInitialFreshness.ts`, `schemaVersion.ts` | Per-contact session persistence, storage master key, replay-freshness store, schema marker |
| `src/security/appLock.ts` | Optional biometric/device-credential app lock |
| `src/transport/wireProtocol.ts` | Length-prefixed frame encoding/decoding and validation (no transport code) |
| `src/diagnostics.ts` | Small logging switch imported by the storage code; included unchanged so imports resolve |
| `__tests__/*.test.ts`, `__tests__/testUtils/keychainMock.ts` | 20 test suites and the in-memory Keychain mock |
| `package.json`, `package-lock.json`, `jest.config.js`, `babel.config.js`, `tsconfig.json` | Minimal, pinned tooling created for this export (the original app uses the React Native toolchain) |
| `.github/workflows/test.yml` | CI: typecheck and tests on Node 20/22 (the minimum the `@noble/*` dependencies require is 20.19) |
| `README.md`, `THREAT_MODEL.md`, `AUDIT_QUESTIONS.md`, `SECURITY.md`, `LICENSE` | Documentation written for this export |

## What is deliberately not included

Tor/Orbot transport (client, onion server, senders, registry), group chat, the messaging layer, all UI and i18n, the Android/iOS projects and signing material, build scripts, the internal development changelog, git history and any development notes. As a result the repository cannot be built into a working application, and the integration between the included pieces is **not covered**.

## Changes made for the export

Relative to the original files:

1. **Comments translated to English** and rewritten where they referred to internal development process. Technical rationale ("this fix exists because of attack X") was kept.
2. **Test titles translated to English** (`describe`/`it` names).
3. **One test log message translated** (`console.log` in `session.test.ts`, forward-secrecy case A).
4. **Test vector replaced in `validation.test.ts`:** the original used the public key/onion address of a real Orbot service as an example. It was replaced by the synthetic key `00 01 02 … 1f`; the expected onion address was computed independently with a separate Python implementation of the Tor rend-spec-v3 procedure (SHA3-256 checksum, Base32, version byte 0x03).
5. **Project renamed to ONIVEIL** in this export: every occurrence of the former working name in code strings, protocol labels (HKDF `info` strings, AAD prefixes, contact-code prefix), storage/keychain service names, tests and docs was replaced. The code is otherwise identical to the original apart from this systematic rename, so an export session is not wire-compatible with an app build that still uses the former labels.
6. New tooling files (see above). Runtime behavior of the source files is unchanged.

Unchanged on purpose: all code lines of the `src/` files, including German error messages, diagnostic log strings and UI-facing labels (for example the biometry type labels in `appLock.ts`) and German test data strings. A handful of test-data strings also contain identifiers from development (for example `runde0-alice` in a message body).

## Verification performed

- **Code identity:** for every exported `src/` file and test file, the original and the exported version were transpiled with comments removed (TypeScript `removeComments`) and compared token-for-token after applying the same rename to the original. Re-run for the 2026-10-27 update against commit `7112c0a`: differences in `src/`: only `storage/sessions.ts` (the protocol-epoch import and wait described under Provenance); in tests only the deliberate ones listed above (test titles are excluded from the comparison; items 3 and 4 were reviewed by hand).
- **Tests:** `npm ci && npm test` → 20 suites, 518 tests passing (the 2026-10-27 update added tests for the new behavior; the type check passes as well).
- **Type check:** `npm run typecheck` (`tsc --noEmit`, strict) passes.
- **Leak scan:** searched `src/` and `__tests__/` for development-process terms, personal names/e-mail addresses, absolute local paths, tool/vendor names and device names; the only remaining hits are the test-data identifier noted above.

## Limitations of this export

- Not independently reviewed or audited; see `THREAT_MODEL.md`.
- Tests run against mocks of the Android Keystore/Keychain and AsyncStorage.
- The exported code depends on behavior of the messaging layer that is not visible here (for example how callers handle exceptions thrown by `createSession`, how a peer reset is detected, and how attachment sizes are enforced against received bytes).
- The English comments were translated from German by the author with tooling assistance; wording errors are possible, and comments were checked against the code but not exhaustively proven.
