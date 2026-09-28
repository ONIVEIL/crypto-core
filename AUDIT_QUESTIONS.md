# Questions for reviewers

The most useful review is a critical reading of the protocol design, not only of the implementation. Questions are ordered by how much the author would like an outside opinion. Please open an issue (or use the private reporting route in `SECURITY.md` for anything that looks exploitable).

## 0. Why not libsignal, and is the custom design acceptable?

Reasons for a custom design: serverless P2P over Tor with manual key exchange (a contact code), so there is no server that could distribute X3DH prekey bundles; libsignal has no official React Native binding; migrating existing sessions would have been a hard break. The cost is a weaker initial step (no ephemeral or one-time prekeys).

- Is there a well-established construction that fits "no server, manual key exchange, no prekeys" better than this one (for example a Noise handshake pattern such as IK/XX between two known static keys, followed by a ratchet)?
- Given the constraints, would you consider the current design a reasonable engineering compromise, or is there a change you would consider necessary before real use?

## 1. Initial key agreement (`createSession`, `deriveInitialKeys`)

- Static–static X25519 ECDH, HKDF-SHA256 with the sorted concatenation of both static public keys as salt and info `oniveil-session-init`, 96 bytes split into root key and two chain keys. Is the derivation sound (salt/info usage, key separation between directions, use of the sorted order)?
- Which messages lose forward secrecy against a later compromise of a static key, and is the trade-off documented accurately in `THREAT_MODEL.md` (limitation 1)?
- The first message of each direction carries a 16-byte freshness value in the clear plus an Ed25519 signature over `("oniveil-initial-auth", freshness, senderStatic, receiverStatic)`; the freshness is mixed into the chain key by HKDF (`oniveil-initial-chain-auth`). Does this actually prevent key-compromise impersonation of the first message? Is signing this transcript with the identity signing key (a different key from the X25519 key) a problem?
- The signature does not cover `ratchetPublicKey` or the ciphertext. Is a gap left there that matters?
- `consumedInitialFreshness` remembers every freshness ever accepted per peer to stop replay of a validly signed first message after a contact is deleted and re-added. Are there cases where it rejects a legitimate first message, or where the persistence model (a separate store from the session) can be bypassed?

## 2. Ratchet state machine (`encryptMessage`, `decryptMessage`)

- Rotation is receive-driven (rotate on the next own send after a new peer ratchet key arrived), and exactly one side (`amLower`, chosen by comparing the hex-encoded static public keys as strings) forces a rotation on its first send. Is this rule correct and free of dead states or desynchronization for any interleaving of sends/receives with a strictly ordered, reliable transport?
- Any issue with using the own static key as the initial ratchet key, and with the receiver performing the mirror-image DH step against its *current* (possibly not yet rotated) ratchet private key?
- Failed decryption returns no new session, so the caller's session stays unchanged (relied on by callers that guess which contact sent a message). Do you see any path in which a failed attempt leaves observable state changes or a timing/error oracle?
- `__tests__/sessionStateMachine.property.test.ts` and `session.test.ts` exercise the state machine. Which invariants or attack scenarios are missing from them?

## 3. Nonce handling and AEAD usage

- Message encryption uses a fresh random 24-byte nonce per message with XChaCha20-Poly1305 and the 8-byte big-endian sequence number as associated data; the message key is single-use (derived per message from the chain). Attachment and storage encryption also use random 24-byte nonces. Are there any nonce/key reuse paths, in particular around session resets, duplicate delivery, and app crashes between "state advanced" and "state persisted"?
- Is authenticating only the sequence number (not the ratchet public key, freshness, or full header) sufficient, given that the header fields influence the key derivation?

## 4. Replay window of 10 (`recentlyConsumedKeys`)

- The last 10 consumed message keys are retained per session to allow exact retransmissions. Is 10 a sensible bound, is the acceptance rule (must decrypt authentically under the cached key, session unchanged) safe, and do you see a way to make a stored session leak more than intended?
- Is the resulting weakening of forward secrecy (limitation 4) acceptable and described clearly enough?

## 5. Key storage and the app lock

- Identity private keys and the vault key are stored via `react-native-keychain` with `SECURITY_LEVEL.SECURE_HARDWARE` and `AES_GCM_NO_AUTH`, without `accessControl`; the biometric/device-credential app lock is a separate keychain entry that only gates the UI. Is this the right split, or should the vault key be bound to the user-authentication check?
- The vault key is a single random 256-bit key used for every stored record, with per-record associated data. Would per-record key derivation be worth the complexity?
- Refusing to regenerate the vault key when a "was created" marker exists but the Keystore reports nothing: is fail-closed the right call?

## 6. Parsing of untrusted input

- `decodeMessageContent`, `wireProtocol` frame decoding, `parseContactCode`, `sanitizeUserText`. Any way through the size/format checks, or a denial-of-service path (memory, CPU, storage growth)?

## 7. Anything else

Assumptions that look wrong, primitives used in a non-standard way, misleading comments, or tests that pass for the wrong reason are all welcome.
