# Threat model (crypto core)

Status: written by the author, **not independently reviewed**. Everything below describes intent and observed behavior of the code in this repository; it is not a security claim.

## 1. Assets

- Confidentiality and integrity of message plaintext and attachments.
- Authenticity of the peer: a message attributed to a contact really comes from that contact.
- The long-term identity keys (Ed25519 signing key, X25519 encryption key) and the storage master key (`vaultKey`).
- Local data at rest: contacts, messages, sessions.

## 2. Adversaries considered

| Adversary | Capabilities assumed |
| --- | --- |
| Network observer / Tor exit or relay | Sees, records, drops, delays and replays the bytes of a message envelope. Cannot break Tor's transport encryption on the hidden-service path (out of scope here). |
| Malicious contact | Is a legitimate, authenticated peer and may send arbitrary, malformed or oversized content, replay old envelopes, or hand out a crafted contact code. |
| Attacker with a copy of the stored session state | Sees the full serialized `Session` of one side at one point in time. |
| Attacker with one long-term static key | Owns one side's static X25519 key (but not the signing key), possibly plus recorded traffic. |
| Attacker with short physical access to an unlocked device | Opens the app; the app lock is meant to stop exactly this. |

Not considered: a fully compromised, rooted device or a malicious app with the same privileges; side channels; traffic-analysis/metadata attacks on the transport; endpoint malware.

## 3. Mechanisms and where they live

| Goal | Mechanism | Code |
| --- | --- | --- |
| Per-message confidentiality + integrity | XChaCha20-Poly1305, random 24-byte nonce, sequence number as AEAD associated data | `session.ts` |
| Initial shared secret | Static X25519 ECDH; HKDF-SHA256 with sorted public keys as salt yields root key + one chain key per direction | `session.ts` (`deriveInitialKeys`) |
| Forward secrecy / post-compromise healing | DH ratchet (fresh X25519 pair) triggered by receiving a new peer ratchet key; HMAC-SHA256 chain step per message; one side (`amLower`) forces the first rotation | `session.ts` |
| Impersonation resistance on the first message of each direction | Ed25519 signature over `("oniveil-initial-auth", freshness, senderStaticKey, receiverStaticKey)`; the freshness is also mixed into the chain key | `session.ts` |
| Replay of a re-used first message after a contact was deleted and re-added | Persistent per-peer list of consumed `initialFreshness` values, independent of the session object | `consumedInitialFreshness.ts` |
| Replay / reorder protection | Strict expected sequence number; only a bounded window of already consumed message keys is tolerated, and only for exact AEAD-authenticated repeats | `session.ts` |
| Attachment confidentiality | One random 32-byte key per attachment, XChaCha20-Poly1305 over the whole blob, `transferId` as associated data; the key travels inside a ratchet-encrypted message | `attachmentCrypto.ts`, `messageContent.ts` |
| Storage at rest | XChaCha20-Poly1305 under a random 32-byte `vaultKey` kept in the Android Keystore; per-record associated data binds ciphertext to its logical location | `encryptedStore.ts`, `encryptedCollection.ts`, `sessions.ts`, `vaultKey.ts` |
| Key custody | Identity private keys and `vaultKey` are stored via `react-native-keychain` with `SECURITY_LEVEL.SECURE_HARDWARE` | `identity.ts`, `keychainOptions.ts` |
| Contact verification | Manual comparison of a SHA-256 based safety number over both parties' public keys | `fingerprint.ts` |
| Robustness against hostile input | Size limits checked before parsing, strict ID formats (path-traversal protection), bidi/zero-width stripping, frame-length limits, chunk-count limits | `messageContent.ts`, `validation.ts`, `wireProtocol.ts` |

## 4. Known limitations and open design questions

These are stated deliberately; several are the main things reviewers are asked to assess (see `AUDIT_QUESTIONS.md`).

1. **Weaker initial step than X3DH.** The initial secret is static–static ECDH only, with no ephemeral or one-time prekeys. Messages sent before the first real DH rotation on a given sending direction are therefore not forward secret against a later compromise of a long-term static key: an attacker with one static key plus recorded traffic can recompute those message keys (the freshness value is sent in the clear). `__tests__/session.test.ts` demonstrates exactly this boundary ("forward-secrecy proof with exact message index"). Which messages are affected depends on which side is `amLower`.
2. **The static key doubles as the first ratchet key.** A new session starts with the own static X25519 key as its ratchet key until the first rotation.
3. **Only the first message of each direction is signed.** Later messages are authenticated implicitly through possession of the ratchet/chain state. There is no per-message signature. The signature does not cover `ratchetPublicKey` (this is intentional and documented in the tests; the ratchet key enters the derivation instead).
4. **Receiving side retains recent message keys.** The last `MAX_RECENTLY_CONSUMED_KEYS = 10` consumed message keys are kept in the stored session so that a retried, already processed envelope can be acknowledged again. An attacker with the stored session state can decrypt those (up to ten) already received messages. This is a bounded, deliberate trade-off for reliability over Tor.
5. **No skipped-message keys.** Delivery is strictly in order. A skipped sequence number is rejected; the design relies on the transport/outbox to deliver reliably and in order.
6. **Contact exchange is not authenticated by the protocol.** The contact code carries the keys. Protection against a man-in-the-middle during contact exchange rests on the user comparing the safety number over an independent channel.
7. **App lock is a gate, not a key.** The vault key and identity keys are stored with hardware-backed Keystore options but **without** `accessControl`, so they are not cryptographically bound to the biometric/device-credential check of the app lock. The lock protects against casual physical access to an unlocked device, not against an attacker with deeper access.
8. **Diagnostic logging (off by default).** When switched on, storage code logs lengths and a ~17-bit position-dependent fingerprint of the vault key, and the frame decoder logs the raw frame text if JSON parsing fails. No key material or plaintext messages are logged, but the switch should be considered a debugging aid, not a production feature.
9. **Tests use mocks for Keystore and storage.** They demonstrate logic, not the behavior of the real Android Keystore, biometric APIs or AsyncStorage.
10. **Custom protocol.** The composition of standard primitives is the author's own design and has no formal proof or external audit. The implementation-correctness tests (independent test vectors) do not establish that the composition is secure.
11. **`createSession` throws on low-order peer keys** (rejected inside `@noble/curves`, not by a check in this code base). A caller that does not catch this could see an availability problem; the calling layer is not part of this repository.

## 5. Issues found and fixed during development

Listed neutrally so that reviewers know what was already considered:

- Key-compromise impersonation on the first message of each direction (statically derived keys only) → Ed25519 signature over freshness and both static keys, plus mixing the freshness into the chain key.
- Bit-identical key reuse after deleting and re-adding the same contact → per-message random freshness, plus a persistent consumed-freshness store against replay of an old, validly signed first message.
- Chain-key mismatch when both sides send before either has received (unconditional rotation on every send) → receive-driven rotation with one deterministic side forcing the first rotation.
- Permanent rejection of a retried envelope after a lost acknowledgement → bounded window of consumed keys, accepted only for exact AEAD-authenticated repeats.
- Ciphertext of one storage record being accepted under another record's key → per-record associated data, plus an independent `id` check after decryption.
- Silent regeneration of the vault key when the Keystore transiently reports "not found" → creation is refused once a "was created" marker exists.
- `TextDecoder` missing on Hermes / `RangeError` on invalid UTF-8 → own non-throwing UTF-8 decoder.
- Parser hardening: content size checked before `JSON.parse`, member-list and chunk-count bounds, strict ID patterns, a fixed upper bound on the announced attachment size (enforcing it against the bytes actually received happens in the transport layer, which is not part of this repository).

## 6. Not covered by this repository

Tor/Orbot transport and onion-service handling, group chat semantics (ownership, member lists, fan-out), the messaging layer (session recovery after a peer reset, contact sender matching, outbox), UI, platform projects, and the build/release pipeline.
