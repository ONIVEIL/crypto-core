// session.ts — Encryption/authentication of individual messages between two contacts, plus
// replay protection. Builds on the X25519 encryption keys from identity.ts.
//
// Design (Double Ratchet, simplified for a reliable, strictly ordered transport — see the
// security properties below):
//   1. A one-time static X25519 ECDH exchange at session setup yields a shared initial root key
//      AND two initial chain keys (one per direction). Both sides arrive at the same values
//      independently, without exchanging any message (sorted derivation, see deriveInitialKeys).
//      This matters: the FIRST messages in each direction can be sent and decrypted independently
//      of each other (e.g. simultaneously, before either side has heard anything from the other)
//      without a DH ratchet step with fresh key material having to happen first.
//   2. A real DH ratchet step (fresh, single-use X25519 key pair) does NOT happen on every
//      message, but is **receive-driven, at the next own send**: if, since the last own ratchet
//      step, a NEW ratchet public key from the peer has been received (i.e. the peer has replied
//      or sent something in the meantime), the next own send generates a fresh key pair, combines
//      it via ECDH with that new peer key and derives a new root key + a new sending chain from
//      it via HKDF. If NOTHING new has arrived from the peer since the last own ratchet step, the
//      existing sending chain is only advanced one step via HMAC (no new key pair). An earlier,
//      naive design generated a fresh key pair unconditionally on EVERY sent message; when both
//      sides send independently before either has received anything from the other, that led to
//      an irrecoverable chain-key mismatch (AEAD "invalid tag" on decryption) — see the test
//      case "works independently in both directions at the same time".
//   3. To still GUARANTEE that a real DH ratchet step eventually happens (not only when someone
//      happens to receive something — otherwise purely one-way traffic would never rotate),
//      EXACTLY ONE of the two sides (the one with the lexicographically smaller static key,
//      `amLower`, computable deterministically and independently by both sides) forces a ratchet
//      step on its FIRST sent message, even without having received anything before. The other
//      side rotates at the latest on its first reply afterwards (receive-driven, see point 2).
//      This breaks the symmetry deterministically instead of via a race, and remains compatible
//      with point 1 (independent first messages in both directions work without a prior ratchet
//      step), because only ONE side forces.
//   4. When decrypting, the receiver performs the same DH ratchet step in mirror image as soon
//      as the envelope carries a ratchet public key of the sender that it does not know yet: own
//      (at that time CURRENT, possibly not yet rotated) ratchet private key × the sender's
//      ratchet public key sent along → same ECDH value → same new root key + same new chain. If
//      it already knows the ratchet public key sent along (no new key round), only the existing
//      receiving chain is advanced via HMAC.
//   5. From the current chain, a single-use message key is derived via HMAC (one-way function).
//   6. Each message carries a strictly increasing sequence number as authenticated data; the
//      receiver accepts only exactly the next expected number.
//
// Security properties:
//   - Confidentiality + integrity per message (XChaCha20-Poly1305, authenticated encryption).
//   - Implicit authentication: only someone holding the matching private X25519 key can
//     reproduce the respective ECDH step.
//   - Replay/reorder protection: a sequence number that was already processed or skipped is
//     rejected (strict in-order delivery — fits a reliable transport).
//   - Forward secrecy: both the HMAC chain step and the DH ratchet step are one-way functions —
//     a compromised current key does not reveal earlier message keys. LIMITATION (see
//     `recentlyConsumedKeys` below): this principle no longer holds without restriction on the
//     receiving side — the last at most `MAX_RECENTLY_CONSUMED_KEYS` already used receiving
//     message keys are deliberately kept as part of the (encrypted-at-rest) session, so that a
//     repeatedly delivered, already processed message can be acknowledged again. An attacker who
//     compromises the complete stored session state can therefore additionally decrypt the last
//     (up to ten) already RECEIVED messages — a deliberate, tightly bounded trade-off in favour
//     of reliability (see the rationale there), not a restriction on the confidentiality of
//     FUTURE messages or of the sending side.
//   - Post-compromise security (self-healing): if an attacker compromises the complete session
//     state of one side, the next reply of that side AFTER receiving a new ratchet key from the
//     peer restores confidentiality (a new key pair unknown to the attacker feeds into the new
//     root key) — provided the attacker does not also observe that specific new send. As usual
//     with the Double Ratchet, complete healing in BOTH directions needs a message exchange in
//     both directions. This is not a weakness of this implementation but an inherent property of
//     DH ratcheting.
//   - Tolerance for REPEATED delivery of the same, already successfully processed message (not to
//     be confused with real out-of-order/skip-ahead, see below): a bounded window of the last
//     `MAX_RECENTLY_CONSUMED_KEYS` already used message keys is kept together with their
//     sequence numbers (see `recentlyConsumedKeys`). Observed on a real device over Tor: if the
//     receiver's acknowledgement (ack) is lost — e.g. because the Tor connection drops right
//     afterwards, independent of any bug in this code —, the sender's outbox resends the same,
//     already created envelope (the envelope is kept unchanged for retries, not re-encrypted).
//     Without this window, decryptMessage would permanently reject that retry even though the
//     message was already processed successfully — the sender never learns of the success, and
//     because delivery is strictly sequential per contact (the sender aborts on the first
//     failure), this one undeliverable retry blocks all later messages of the same contact
//     permanently. A repeat is only accepted as such if it decrypts with the exact cached message
//     key with authentication (AEAD tag check as always) — no trust based on the sequence number
//     alone, no oracle for an attacker without the real key. There is still NO support for real
//     skip-ahead (a sequence number GREATER than expected is still rejected) — the transport
//     stays strictly ordered, only exact repeats of an already consumed number are tolerated.
import {x25519} from '@noble/curves/ed25519.js';
import {xchacha20poly1305} from '@noble/ciphers/chacha.js';
import * as ed from '@noble/ed25519';
import {hkdf} from '@noble/hashes/hkdf.js';
import {hmac} from '@noble/hashes/hmac.js';
import {sha256, sha512} from '@noble/hashes/sha2.js';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
  utf8ToBytes,
} from '@noble/hashes/utils.js';
import {bytesToUtf8} from './textCodec';
import {HEX_32_BYTES_PATTERN} from './validation';

// @noble/ed25519 v2 needs a SHA-512 implementation supplied from outside (library design, not a
// bug) — same pattern as in crypto/identity.ts. The same assignment is already made there, but
// without a GUARANTEED load order (which module is imported first depends on the caller) —
// assigning the same function twice is harmless, hence done defensively again here.
ed.hashes.sha512Async = (m: Uint8Array) => Promise.resolve(sha512(m));

const KEY_LENGTH = 32;
const NONCE_LENGTH = 24; // XChaCha20 — safe for random nonces

export interface Session {
  rootKey: string; // hex — updated on every DH ratchet step (sending and receiving)
  sendingChainKey: string; // hex
  receivingChainKey: string; // hex
  // The own and the peer's IMMUTABLE static X25519 identity encryption key of this session — set
  // once in createSession, NEVER changed afterwards (unlike myRatchetPublicKey/
  // theirRatchetPublicKey, which rotate during the session). Hardening against key-compromise
  // impersonation / bit-identical session reset: serves as a stable reference point for the
  // Ed25519-signed freshness component on the first message of each direction (see
  // buildInitialAuthTranscript) — without an immutable anchor the signature would not be bound to
  // "exactly these two identities".
  myStaticPublicKey: string; // hex
  theirStaticPublicKey: string; // hex
  sendCounter: number; // next sequence number to assign when sending
  receiveCounter: number; // next expected sequence number when receiving
  myRatchetPrivateKey: string; // hex — current own X25519 ratchet key pair (private)
  myRatchetPublicKey: string; // hex — ... (public; sent along with every message)
  theirRatchetPublicKey: string; // hex — last known ratchet public key of the peer
  // Peer ratchet public key against which the current sendingChainKey/own ratchet key pair was
  // derived — as long as `theirRatchetPublicKey` matches it, nothing new has been received from
  // the peer since the last own ratchet rotation; encryptMessage then does NOT rotate again but
  // only advances the existing chain via HMAC (see module documentation).
  sendingChainRatchetedForTheirKey: string; // hex
  // Analogous for the receiving side: peer ratchet public key against which the current
  // receivingChainKey was derived.
  receivingChainRatchetedForTheirKey: string; // hex
  // Which side performs the forced first rotation (see module documentation, point 3) — determined
  // once in createSession from the comparison of the two static keys and carried unchanged over the
  // lifetime of the session (the current myRatchetPublicKey changes during the session, so without
  // this field the original comparison could no longer be reconstructed).
  amLower: boolean;
  // Window of the most recently used receiving message keys (see module documentation,
  // "Tolerance for REPEATED delivery") — DELIBERATELY optional: a session stored before this
  // feature simply lacks the field, but must NOT be treated like an invalid/missing session (see
  // isValidSession — unlike the other, always-required fields, this one is deliberately not
  // checked there). If absent, it is treated as an empty list everywhere.
  recentlyConsumedKeys?: RecentlyConsumedKey[];
}

interface RecentlyConsumedKey {
  sequenceNumber: number;
  messageKey: string; // hex
}

// Small enough to cause no noticeable memory/storage load, generous enough for several lost
// acknowledgements IN A ROW (in practice single lost acks were observed, not many at once) — no
// substitute for real skip-ahead, just a short replay window. Exported so that tests need not
// duplicate the window size as a magic number.
export const MAX_RECENTLY_CONSUMED_KEYS = 10;

export interface OutgoingEnvelope {
  sequenceNumber: number;
  nonce: string; // hex
  ciphertext: string; // hex
  ratchetPublicKey: string; // hex — sender ratchet public key for THIS message
  // Only set/expected when sequenceNumber===0 (KCI/reset hardening, see the documentation at
  // buildInitialAuthTranscript below): a one-time, fresh random component that adds freshness to
  // the static-static ECDH starting point of the very first message of this direction.
  initialFreshness?: string; // hex, 16 bytes
  // Ed25519 signature over the freshness component + both static keys — proves that EXACTLY the
  // owner of the private Ed25519 signing key (not just anyone with the static X25519 key)
  // produced this first message.
  initialAuth?: string; // hex, Ed25519 signature
}

export class ReplayOrOutOfOrderError extends Error {
  constructor(expected: number, received: number) {
    super(
      `Erwartete Sequenznummer ${expected}, erhalten ${received} — mögliche Replay- oder Reorder-Attacke.`,
    );
    this.name = 'ReplayOrOutOfOrderError';
  }
}

// KCI/reset hardening: until the first real DH rotation, the first message of each direction
// (sequenceNumber===0) rests on purely static-static X25519 ECDH — without this signature check,
// someone who loses their own static key could impersonate the RESPECTIVE OTHER party towards the
// peer (key-compromise impersonation) without knowing the other party's key. The Ed25519
// signature instead proves real possession of the claimed peer's signing key.
export class InvalidInitialAuthError extends Error {
  constructor() {
    super(
      'Fehlende oder ungültige Ed25519-Signatur auf der ersten Nachricht dieser Sitzungsrichtung.',
    );
    this.name = 'InvalidInitialAuthError';
  }
}

// Structural runtime check for a session state read from local storage (which is itself already
// encrypted) — TypeScript does not really check `readEncrypted<Session>(...)` at runtime, that is
// only a type assumption. Important above all as migration protection: a session stored before
// the Double-Ratchet changeover (or before the rotation-logic correction) simply lacks the new
// fields — used unchecked, it would crash at the first hexToBytes(undefined). getSession()
// (src/storage/sessions.ts) treats a session that fails here like a non-existent one — the caller
// then builds a fresh session as usual, exactly as for a new contact.
//
// myStaticPublicKey/theirStaticPublicKey are deliberately REQUIRED here (unlike the optional
// recentlyConsumedKeys) — KCI/reset hardening: a session stored BEFORE that change lacks these
// fields and should therefore count as invalid on next access, so that it is rebuilt once and
// automatically via createSession through exactly the same migration mechanism
// (getSession/getOrCreateSessionForContact) — only that way does it get a static anchor for the
// new signature check at all.
export function isValidSession(value: unknown): value is Session {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.rootKey === 'string' &&
    HEX_32_BYTES_PATTERN.test(v.rootKey) &&
    typeof v.sendingChainKey === 'string' &&
    HEX_32_BYTES_PATTERN.test(v.sendingChainKey) &&
    typeof v.receivingChainKey === 'string' &&
    HEX_32_BYTES_PATTERN.test(v.receivingChainKey) &&
    typeof v.myStaticPublicKey === 'string' &&
    HEX_32_BYTES_PATTERN.test(v.myStaticPublicKey) &&
    typeof v.theirStaticPublicKey === 'string' &&
    HEX_32_BYTES_PATTERN.test(v.theirStaticPublicKey) &&
    typeof v.sendCounter === 'number' &&
    Number.isInteger(v.sendCounter) &&
    v.sendCounter >= 0 &&
    typeof v.receiveCounter === 'number' &&
    Number.isInteger(v.receiveCounter) &&
    v.receiveCounter >= 0 &&
    typeof v.myRatchetPrivateKey === 'string' &&
    HEX_32_BYTES_PATTERN.test(v.myRatchetPrivateKey) &&
    typeof v.myRatchetPublicKey === 'string' &&
    HEX_32_BYTES_PATTERN.test(v.myRatchetPublicKey) &&
    typeof v.theirRatchetPublicKey === 'string' &&
    HEX_32_BYTES_PATTERN.test(v.theirRatchetPublicKey) &&
    typeof v.sendingChainRatchetedForTheirKey === 'string' &&
    HEX_32_BYTES_PATTERN.test(v.sendingChainRatchetedForTheirKey) &&
    typeof v.receivingChainRatchetedForTheirKey === 'string' &&
    HEX_32_BYTES_PATTERN.test(v.receivingChainRatchetedForTheirKey) &&
    typeof v.amLower === 'boolean'
  );
}

// Derives the initial root key, computable identically and independently by both sides, plus the
// two initial chain keys (one per sending direction). The sorted concatenation of the two static
// public keys serves as salt, so both sides independently arrive at the same values (same
// principle as in crypto/fingerprint.ts).
function deriveInitialKeys(
  sharedSecret: Uint8Array,
  lowerPublicKey: Uint8Array,
  higherPublicKey: Uint8Array,
): {
  rootKey: Uint8Array;
  lowerToHigherChain: Uint8Array;
  higherToLowerChain: Uint8Array;
} {
  const salt = concatBytes(lowerPublicKey, higherPublicKey);
  const info = utf8ToBytes('oniveil-session-init');
  const output = hkdf(sha256, sharedSecret, salt, info, KEY_LENGTH * 3);
  return {
    rootKey: output.subarray(0, KEY_LENGTH),
    lowerToHigherChain: output.subarray(KEY_LENGTH, KEY_LENGTH * 2),
    higherToLowerChain: output.subarray(KEY_LENGTH * 2),
  };
}

// Creates a new session from the own private and the peer's public X25519 key. Deterministic:
// both sides independently arrive at the same initial root key and the same two initial chain
// keys (one per direction).
export function createSession(
  myEncryptionPrivateKey: string,
  myEncryptionPublicKey: string,
  theirEncryptionPublicKey: string,
): Session {
  const sharedSecret = x25519.getSharedSecret(
    hexToBytes(myEncryptionPrivateKey),
    hexToBytes(theirEncryptionPublicKey),
  );

  const myPublicKeyBytes = hexToBytes(myEncryptionPublicKey);
  const theirPublicKeyBytes = hexToBytes(theirEncryptionPublicKey);
  const amLower = myEncryptionPublicKey < theirEncryptionPublicKey;
  const lowerPublicKey = amLower ? myPublicKeyBytes : theirPublicKeyBytes;
  const higherPublicKey = amLower ? theirPublicKeyBytes : myPublicKeyBytes;

  const {rootKey, lowerToHigherChain, higherToLowerChain} = deriveInitialKeys(
    sharedSecret,
    lowerPublicKey,
    higherPublicKey,
  );
  const sendingChainKey = amLower ? lowerToHigherChain : higherToLowerChain;
  const receivingChainKey = amLower ? higherToLowerChain : lowerToHigherChain;

  return {
    rootKey: bytesToHex(rootKey),
    sendingChainKey: bytesToHex(sendingChainKey),
    receivingChainKey: bytesToHex(receivingChainKey),
    myStaticPublicKey: myEncryptionPublicKey,
    theirStaticPublicKey: theirEncryptionPublicKey,
    sendCounter: 0,
    receiveCounter: 0,
    // The own static key is the starting point for the own ratchet key — the peer already knows it
    // (contact entry). A real DH ratchet step replaces it only once rotation actually happens (see
    // module documentation).
    myRatchetPrivateKey: myEncryptionPrivateKey,
    myRatchetPublicKey: myEncryptionPublicKey,
    theirRatchetPublicKey: theirEncryptionPublicKey,
    // Both initial chains are already (deterministically) derived against the respective static
    // peer key — until the first real rotation this corresponds exactly to the currently known
    // theirRatchetPublicKey.
    sendingChainRatchetedForTheirKey: theirEncryptionPublicKey,
    receivingChainRatchetedForTheirKey: theirEncryptionPublicKey,
    amLower,
  };
}

// One chain ratchet step: derives a single-use message key from the current chain key and
// advances the chain key one step via HMAC (one-way function).
function chainRatchetStep(chainKey: Uint8Array): {
  messageKey: Uint8Array;
  nextChainKey: Uint8Array;
} {
  return {
    messageKey: hmac(sha256, chainKey, new Uint8Array([0x01])),
    nextChainKey: hmac(sha256, chainKey, new Uint8Array([0x02])),
  };
}

// One DH ratchet step: combines the current root key with a fresh ECDH result into a new root key
// + a new chain (sending or receiving chain, depending on the caller). `dhOutput` is the HKDF
// input material (it supplies the actual new entropy for self-healing), `rootKey` is the salt
// (chained with the session history so far) — the output is split into two halves instead of two
// separate HKDF calls, saving one SHA-256 round.
function dhRatchetStep(
  rootKey: Uint8Array,
  dhOutput: Uint8Array,
): {nextRootKey: Uint8Array; chainKey: Uint8Array} {
  const output = hkdf(
    sha256,
    dhOutput,
    rootKey,
    utf8ToBytes('oniveil-ratchet-step'),
    KEY_LENGTH * 2,
  );
  return {
    nextRootKey: output.subarray(0, KEY_LENGTH),
    chainKey: output.subarray(KEY_LENGTH),
  };
}

function sequenceNumberToBytes(sequenceNumber: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(sequenceNumber), false);
  return bytes;
}

// KCI/reset hardening: the transcript that is signed on the first message of each direction.
// Binds the freshness component firmly to BOTH static keys (sender first) — an attacker who knows
// only one of the two static keys cannot produce a valid Ed25519 signature for this transcript,
// even if they could otherwise (lacking freshness binding in the purely static-static ECDH)
// impersonate the respective other party.
function buildInitialAuthTranscript(
  freshness: Uint8Array,
  senderStaticPublicKey: Uint8Array,
  receiverStaticPublicKey: Uint8Array,
): Uint8Array {
  return concatBytes(
    utf8ToBytes('oniveil-initial-auth'),
    freshness,
    senderStaticPublicKey,
    receiverStaticPublicKey,
  );
}

// KCI/reset hardening: upgrades the chain key (derived up to here purely from static-static ECDH)
// ONCE with the signed random component — afterwards the normal HMAC chain continues unchanged,
// but now from a starting point that is no longer predictable from static keys alone. It also
// addresses a second issue: two independent createSession calls with the same static keys (e.g.
// deleteContact + adding the same contact again) still yield the same rootKey/initial chain, but
// because of the respectively NEW random freshness they yield two different message keys actually
// used for message 0 — no more bit-identical reset.
function upgradeChainKeyWithFreshness(
  chainKey: Uint8Array,
  freshness: Uint8Array,
): Uint8Array {
  return hkdf(
    sha256,
    chainKey,
    freshness,
    utf8ToBytes('oniveil-initial-chain-auth'),
    KEY_LENGTH,
  );
}

export async function encryptMessage(
  session: Session,
  plaintext: string,
  mySigningPrivateKey: string,
): Promise<{envelope: OutgoingEnvelope; nextSession: Session}> {
  let rootKey = hexToBytes(session.rootKey);
  let sendingChainKey = hexToBytes(session.sendingChainKey);
  let myRatchetPrivateKey = session.myRatchetPrivateKey;
  let myRatchetPublicKey = session.myRatchetPublicKey;
  let sendingChainRatchetedForTheirKey =
    session.sendingChainRatchetedForTheirKey;
  const sequenceNumber = session.sendCounter;

  // Rotation condition (see module documentation, points 2+3): either a NEW ratchet public key of
  // the peer has arrived since the last own rotation, or this is the own very first sent message
  // AND the own side is responsible for the forced initial rotation (amLower) — otherwise nothing
  // would ever rotate if neither side ever receives anything.
  const receivedSomethingNew =
    session.theirRatchetPublicKey !== sendingChainRatchetedForTheirKey;
  const forcedInitialRotation = session.sendCounter === 0 && session.amLower;
  if (receivedSomethingNew || forcedInitialRotation) {
    const freshRatchetKeyPair = x25519.keygen();
    const dhOutput = x25519.getSharedSecret(
      freshRatchetKeyPair.secretKey,
      hexToBytes(session.theirRatchetPublicKey),
    );
    const step = dhRatchetStep(rootKey, dhOutput);
    rootKey = step.nextRootKey;
    sendingChainKey = step.chainKey;
    myRatchetPrivateKey = bytesToHex(freshRatchetKeyPair.secretKey);
    myRatchetPublicKey = bytesToHex(freshRatchetKeyPair.publicKey);
    sendingChainRatchetedForTheirKey = session.theirRatchetPublicKey;
  }

  // KCI/reset hardening (see module documentation): only the FIRST message of this direction
  // carries a fresh, Ed25519-signed random component that upgrades the chain key once — from
  // message 1 on, the normal HMAC chain continues unchanged.
  let initialFreshness: string | undefined;
  let initialAuth: string | undefined;
  if (sequenceNumber === 0) {
    const freshnessBytes = randomBytes(16);
    const transcript = buildInitialAuthTranscript(
      freshnessBytes,
      hexToBytes(session.myStaticPublicKey),
      hexToBytes(session.theirStaticPublicKey),
    );
    const signature = await ed.signAsync(
      transcript,
      hexToBytes(mySigningPrivateKey),
    );
    initialFreshness = bytesToHex(freshnessBytes);
    initialAuth = bytesToHex(signature);
    sendingChainKey = upgradeChainKeyWithFreshness(
      sendingChainKey,
      freshnessBytes,
    );
  }

  const {messageKey, nextChainKey} = chainRatchetStep(sendingChainKey);
  const nonce = randomBytes(NONCE_LENGTH);
  const ciphertext = xchacha20poly1305(
    messageKey,
    nonce,
    sequenceNumberToBytes(sequenceNumber),
  ).encrypt(utf8ToBytes(plaintext));

  return {
    envelope: {
      sequenceNumber,
      nonce: bytesToHex(nonce),
      ciphertext: bytesToHex(ciphertext),
      ratchetPublicKey: myRatchetPublicKey,
      initialFreshness,
      initialAuth,
    },
    nextSession: {
      ...session,
      rootKey: bytesToHex(rootKey),
      sendingChainKey: bytesToHex(nextChainKey),
      sendCounter: sequenceNumber + 1,
      myRatchetPrivateKey,
      myRatchetPublicKey,
      sendingChainRatchetedForTheirKey,
    },
  };
}

export async function decryptMessage(
  session: Session,
  envelope: OutgoingEnvelope,
  theirSigningPublicKey: string,
): Promise<{plaintext: string; nextSession: Session; duplicate: boolean}> {
  // See module documentation "Tolerance for REPEATED delivery": a sequence number BELOW the
  // expected next value is not necessarily an attack — it can also be the (identical) repeat of a
  // message that WE already processed successfully but whose acknowledgement never reached the
  // sender. Accepted only exactly from the short window of the most recently used message keys,
  // and only after a renewed successful AEAD check (no trust based on the sequence number alone)
  // — everything else remains a rejection as before.
  if (envelope.sequenceNumber < session.receiveCounter) {
    const cached = (session.recentlyConsumedKeys ?? []).find(
      k => k.sequenceNumber === envelope.sequenceNumber,
    );
    if (!cached) {
      // Too old (dropped out of the window) or never actually consumed — just as unsafe as an
      // ordinary replay attempt, handled in exactly the same way.
      throw new ReplayOrOutOfOrderError(
        session.receiveCounter,
        envelope.sequenceNumber,
      );
    }
    let plaintextBytes: Uint8Array;
    try {
      plaintextBytes = xchacha20poly1305(
        hexToBytes(cached.messageKey),
        hexToBytes(envelope.nonce),
        sequenceNumberToBytes(envelope.sequenceNumber),
      ).decrypt(hexToBytes(envelope.ciphertext));
    } catch {
      // Sequence number known, but content/tag does not match the cached key — not a genuine
      // repeat of our own envelope (e.g. tampered, or a random collision of a sequence number
      // from another, long outdated session epoch). Reject like any other replay attempt.
      throw new ReplayOrOutOfOrderError(
        session.receiveCounter,
        envelope.sequenceNumber,
      );
    }
    // Deliberately UNCHANGED session: a repeat must not advance the ratchet state again — that
    // already happened when this sequence number was first processed successfully.
    return {
      plaintext: bytesToUtf8(plaintextBytes),
      nextSession: session,
      duplicate: true,
    };
  }

  // Sequence-number check deliberately BEFORE any cryptographic work — a skipped envelope
  // (sequence number GREATER than expected, real skip-ahead) is still rejected without any ECDH
  // operation (unchanged from before, see ReplayOrOutOfOrderError) — only the "less than
  // expected" case handled above now has an exception.
  if (envelope.sequenceNumber !== session.receiveCounter) {
    throw new ReplayOrOutOfOrderError(
      session.receiveCounter,
      envelope.sequenceNumber,
    );
  }

  // KCI/reset hardening (see module documentation): the first message of this direction must
  // carry a valid Ed25519 signature of the peer over the freshness component + both static keys —
  // deliberately checked BEFORE any ECDH/chain derivation for THIS message (same principle as the
  // sequence-number check above: no `session` field is modified before a possible throw, so a
  // failed attempt leaves no traces in the session state held by the caller).
  if (envelope.sequenceNumber === 0) {
    if (!envelope.initialFreshness || !envelope.initialAuth) {
      throw new InvalidInitialAuthError();
    }
    const transcript = buildInitialAuthTranscript(
      hexToBytes(envelope.initialFreshness),
      hexToBytes(session.theirStaticPublicKey), // sender of this message = the peer
      hexToBytes(session.myStaticPublicKey),
    );
    const valid = await ed.verifyAsync(
      hexToBytes(envelope.initialAuth),
      transcript,
      hexToBytes(theirSigningPublicKey),
    );
    if (!valid) {
      throw new InvalidInitialAuthError();
    }
  }

  let rootKey = hexToBytes(session.rootKey);
  let receivingChainKey = hexToBytes(session.receivingChainKey);
  let receivingChainRatchetedForTheirKey =
    session.receivingChainRatchetedForTheirKey;

  // If the envelope carries a ratchet public key of the sender that the receiving side does not
  // know yet, this performs a mirror-image DH ratchet step: own CURRENT (at that time possibly
  // not yet rotated) ratchet private key × the sender's ratchet public key sent along. Read-only
  // on `session` up to here — if the AEAD decryption below then fails, NO nextSession is
  // returned, so the original session held by the caller stays unchanged (important for callers
  // that try several contacts in turn when guessing the sender of an incoming message: a failed
  // attempt against the wrong contact leaves no traces).
  if (envelope.ratchetPublicKey !== receivingChainRatchetedForTheirKey) {
    const dhOutput = x25519.getSharedSecret(
      hexToBytes(session.myRatchetPrivateKey),
      hexToBytes(envelope.ratchetPublicKey),
    );
    const step = dhRatchetStep(rootKey, dhOutput);
    rootKey = step.nextRootKey;
    receivingChainKey = step.chainKey;
    receivingChainRatchetedForTheirKey = envelope.ratchetPublicKey;
  }

  // KCI/reset hardening: mirrors the one-time chain-key upgrade from encryptMessage — at this
  // point envelope.initialFreshness is already guaranteed to be present through the signature
  // check above.
  if (envelope.sequenceNumber === 0) {
    receivingChainKey = upgradeChainKeyWithFreshness(
      receivingChainKey,
      hexToBytes(envelope.initialFreshness!),
    );
  }

  const {messageKey, nextChainKey} = chainRatchetStep(receivingChainKey);
  const plaintextBytes = xchacha20poly1305(
    messageKey,
    hexToBytes(envelope.nonce),
    sequenceNumberToBytes(envelope.sequenceNumber),
  ).decrypt(hexToBytes(envelope.ciphertext));

  // Remembers the message key just used in the short replay window (see module documentation) —
  // `.slice(-N)` keeps the list bounded to the last N entries, regardless of how long the session
  // has been running.
  const recentlyConsumedKeys = [
    ...(session.recentlyConsumedKeys ?? []),
    {
      sequenceNumber: envelope.sequenceNumber,
      messageKey: bytesToHex(messageKey),
    },
  ].slice(-MAX_RECENTLY_CONSUMED_KEYS);

  return {
    plaintext: bytesToUtf8(plaintextBytes),
    duplicate: false,
    nextSession: {
      ...session,
      rootKey: bytesToHex(rootKey),
      receivingChainKey: bytesToHex(nextChainKey),
      receiveCounter: session.receiveCounter + 1,
      receivingChainRatchetedForTheirKey,
      theirRatchetPublicKey: envelope.ratchetPublicKey,
      recentlyConsumedKeys,
    },
  };
}
