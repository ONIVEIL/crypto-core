/**
 * @format
 */

// independentTestVectors.test.ts — Independent test vectors.
//
// IMPORTANT METHODOLOGICAL LIMITATION (spelled out here so that it is not lost when reading this
// file): these tests prove ONLY implementation correctness on two levels:
//   - Level 1 (primitives): are X25519/HKDF-SHA256/HMAC-SHA256/XChaCha20-Poly1305 each
//     implemented correctly INDIVIDUALLY — checked against known values or a second, completely
//     independent implementation (here: Node.js' built-in `node:crypto`, OpenSSL-based, entirely
//     different code from the @noble/* libraries used everywhere else in this project)?
//   - Level 2 (protocol derivation): does `src/crypto/session.ts` assemble these primitives
//     exactly as its own specification describes (salt order, info strings, byte split, order of
//     DH ratchet step/chain ratchet step/freshness upgrade)?
// They EXPLICITLY DO NOT prove level 3 (is the resulting composition SECURE? — that is addressed
// by other tests: the KCI hardening including the freshness binding, the forward-secrecy proofs
// with exact message index, the property/model-based testing of the state machine, and the
// low-order-point/edge-case tests). A second implementation that re-builds the same design flaw
// (e.g. because it replicates exactly the same, possibly flawed specification) would confirm a
// SPEC error instead of uncovering it — the agreement shown here between @noble/* and node:crypto
// is NEVER to be understood as an additional security proof, but exclusively as an
// implementation-correctness proof on the two levels named.
//
// Pure test work — src/ is not modified by this file. No new npm dependency: `node:crypto` is
// part of the Node.js standard library.

// session.ts does not import react-native-get-random-values itself, but the underlying @noble
// libraries still need a crypto.getRandomValues source (same pattern as in
// __tests__/session.test.ts and __tests__/sessionStateMachine.property.test.ts).
// @ts-ignore
global.crypto = global.crypto ?? require('crypto').webcrypto;

import {describe, it, expect} from '@jest/globals';
import * as nodeCrypto from 'node:crypto';
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
  utf8ToBytes,
} from '@noble/hashes/utils.js';
import {
  createSession,
  encryptMessage,
  decryptMessage,
  OutgoingEnvelope,
  Session,
} from '../src/crypto/session';
import {bytesToUtf8} from '../src/crypto/textCodec';
import {HEX_32_BYTES_PATTERN} from '../src/crypto/validation';

// @noble/ed25519 v2/v3 needs a SHA-512 implementation supplied from outside (same pattern as in
// crypto/identity.ts, crypto/session.ts itself and the other session-related test files).
ed.hashes.sha512Async = (m: Uint8Array) => Promise.resolve(sha512(m));

function keypair() {
  const {secretKey, publicKey} = x25519.keygen();
  return {privateKey: bytesToHex(secretKey), publicKey: bytesToHex(publicKey)};
}

async function signingKeypair() {
  const {secretKey, publicKey} = await ed.keygenAsync();
  return {privateKey: bytesToHex(secretKey), publicKey: bytesToHex(publicKey)};
}

// -------------------------------------------------------------------------------------------
// Shared helpers: node:crypto as a second, completely independent implementation.
// -------------------------------------------------------------------------------------------

// node:crypto supports X25519 natively, but expects KeyObjects instead of raw 32-byte values —
// the usual way is a thin JWK wrapper (OKP/X25519, RFC 8037) around the raw bytes, base64url
// encoded. Verified empirically against @noble/curves: the same raw key byte sequence yields the
// same shared secret via both routes, including the RFC 7748 test vectors below. Not part of the
// actual crypto logic, only a format conversion — the actual ECDH computation is done by OpenSSL
// via node:crypto.diffieHellman, not by this helper code.
function x25519JwkFromRaw(
  publicKeyHex: string,
  privateKeyHex?: string,
): nodeCrypto.webcrypto.JsonWebKey {
  const jwk: nodeCrypto.webcrypto.JsonWebKey = {
    kty: 'OKP',
    crv: 'X25519',
    x: Buffer.from(publicKeyHex, 'hex').toString('base64url'),
  };
  if (privateKeyHex !== undefined) {
    jwk.d = Buffer.from(privateKeyHex, 'hex').toString('base64url');
  }
  return jwk;
}

// Own (independent) X25519 ECDH via node:crypto — counterpart to x25519.getSharedSecret() from
// @noble/curves, as used by session.ts.
function nodeX25519SharedSecret(
  myPrivateKeyHex: string,
  myPublicKeyHex: string,
  theirPublicKeyHex: string,
): Uint8Array {
  const privateKey = nodeCrypto.createPrivateKey({
    key: x25519JwkFromRaw(myPublicKeyHex, myPrivateKeyHex),
    format: 'jwk',
  });
  const publicKey = nodeCrypto.createPublicKey({
    key: x25519JwkFromRaw(theirPublicKeyHex),
    format: 'jwk',
  });
  return new Uint8Array(nodeCrypto.diffieHellman({privateKey, publicKey}));
}

// Own (independent) HKDF-SHA256 via node:crypto.hkdfSync — counterpart to hkdf() from
// @noble/hashes/hkdf.js, as used by deriveInitialKeys/dhRatchetStep/upgradeChainKeyWithFreshness
// in session.ts.
function nodeHkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  return new Uint8Array(nodeCrypto.hkdfSync('sha256', ikm, salt, info, length));
}

// Own (independent) HMAC-SHA256 via node:crypto.createHmac — counterpart to hmac() from
// @noble/hashes/hmac.js, as used by chainRatchetStep() in session.ts.
function nodeHmacSha256(key: Uint8Array, message: Uint8Array): Uint8Array {
  return new Uint8Array(
    nodeCrypto.createHmac('sha256', key).update(message).digest(),
  );
}

describe('Level 1: primitives against node:crypto (independent implementation)', () => {
  describe('X25519', () => {
    // RFC 7748 §6.1 test vectors — LITERALLY identical to __tests__/x25519EdgeCases.test.ts
    // (verified there twice independently against https://www.rfc-editor.org/rfc/rfc7748.txt, see
    // the module documentation there). Deliberately not retrieved again here — reused instead.
    const ALICE_PRIVATE =
      '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a';
    const ALICE_PUBLIC =
      '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
    const BOB_PRIVATE =
      '5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb';
    const BOB_PUBLIC =
      'de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f';
    const EXPECTED_SHARED_SECRET =
      '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';

    it('node:crypto yields, for the RFC 7748 Alice/Bob vector, exactly the same shared secret as @noble/curves AND as the RFC text itself', () => {
      const nobleResult = bytesToHex(
        x25519.getSharedSecret(hexToBytes(ALICE_PRIVATE), hexToBytes(BOB_PUBLIC)),
      );
      const nodeResult = bytesToHex(
        nodeX25519SharedSecret(ALICE_PRIVATE, ALICE_PUBLIC, BOB_PUBLIC),
      );
      expect(nobleResult).toBe(EXPECTED_SHARED_SECRET);
      expect(nodeResult).toBe(EXPECTED_SHARED_SECRET);
      expect(nodeResult).toBe(nobleResult);
    });

    it('node:crypto yields the same shared secret also from the opposite direction (Bob_priv × Alice_pub)', () => {
      const nobleResult = bytesToHex(
        x25519.getSharedSecret(hexToBytes(BOB_PRIVATE), hexToBytes(ALICE_PUBLIC)),
      );
      const nodeResult = bytesToHex(
        nodeX25519SharedSecret(BOB_PRIVATE, BOB_PUBLIC, ALICE_PUBLIC),
      );
      expect(nodeResult).toBe(EXPECTED_SHARED_SECRET);
      expect(nodeResult).toBe(nobleResult);
    });

    it('20 randomly generated key pairs: @noble/curves and node:crypto yield byte-identical shared secrets for every pair (both directions)', () => {
      for (let i = 0; i < 20; i++) {
        const alice = keypair();
        const bob = keypair();

        const nobleAB = bytesToHex(
          x25519.getSharedSecret(hexToBytes(alice.privateKey), hexToBytes(bob.publicKey)),
        );
        const nodeAB = bytesToHex(
          nodeX25519SharedSecret(alice.privateKey, alice.publicKey, bob.publicKey),
        );
        const nobleBA = bytesToHex(
          x25519.getSharedSecret(hexToBytes(bob.privateKey), hexToBytes(alice.publicKey)),
        );
        const nodeBA = bytesToHex(
          nodeX25519SharedSecret(bob.privateKey, bob.publicKey, alice.publicKey),
        );

        expect(nodeAB).toBe(nobleAB);
        expect(nodeBA).toBe(nobleBA);
        // Sanity: ECDH symmetry holds for both implementations alike.
        expect(nobleAB).toBe(nobleBA);
        expect(nodeAB).toBe(nodeBA);
      }
    });
  });

  describe('HKDF-SHA256', () => {
    // Exactly the same parameter patterns that session.ts actually uses — not generic HKDF test
    // vectors, but the concrete (ikm, salt, info, len) combinations from deriveInitialKeys() and
    // dhRatchetStep().
    it('deriveInitialKeys pattern (info="oniveil-session-init", len=96): node:crypto.hkdfSync and @noble/hashes/hkdf yield byte-identical 96-byte output for 10 random inputs', () => {
      const info = utf8ToBytes('oniveil-session-init');
      for (let i = 0; i < 10; i++) {
        const sharedSecret = crypto.getRandomValues(new Uint8Array(32));
        const lowerPub = crypto.getRandomValues(new Uint8Array(32));
        const higherPub = crypto.getRandomValues(new Uint8Array(32));
        const salt = concatBytes(lowerPub, higherPub);

        const nobleOut = hkdf(sha256, sharedSecret, salt, info, 96);
        const nodeOut = nodeHkdfSha256(sharedSecret, salt, info, 96);

        expect(bytesToHex(nodeOut)).toBe(bytesToHex(nobleOut));
        expect(nodeOut.length).toBe(96);
      }
    });

    it('dhRatchetStep pattern (info="oniveil-ratchet-step", len=64): node:crypto.hkdfSync and @noble/hashes/hkdf yield byte-identical 64-byte output for 10 random inputs', () => {
      const info = utf8ToBytes('oniveil-ratchet-step');
      for (let i = 0; i < 10; i++) {
        const dhOutput = crypto.getRandomValues(new Uint8Array(32));
        const rootKey = crypto.getRandomValues(new Uint8Array(32));

        const nobleOut = hkdf(sha256, dhOutput, rootKey, info, 64);
        const nodeOut = nodeHkdfSha256(dhOutput, rootKey, info, 64);

        expect(bytesToHex(nodeOut)).toBe(bytesToHex(nobleOut));
        expect(nodeOut.length).toBe(64);
      }
    });
  });

  describe('HMAC-SHA256', () => {
    // Exactly the one-byte messages 0x01/0x02 used in chainRatchetStep() (session.ts).
    it('20 random chain keys: node:crypto.createHmac and @noble/hashes/hmac yield byte-identical results for 0x01 AND 0x02', () => {
      for (let i = 0; i < 20; i++) {
        const chainKey = crypto.getRandomValues(new Uint8Array(32));

        const nobleMessageKey = hmac(sha256, chainKey, new Uint8Array([0x01]));
        const nodeMessageKey = nodeHmacSha256(chainKey, new Uint8Array([0x01]));
        expect(bytesToHex(nodeMessageKey)).toBe(bytesToHex(nobleMessageKey));

        const nobleNextChainKey = hmac(sha256, chainKey, new Uint8Array([0x02]));
        const nodeNextChainKey = nodeHmacSha256(chainKey, new Uint8Array([0x02]));
        expect(bytesToHex(nodeNextChainKey)).toBe(bytesToHex(nobleNextChainKey));

        // Sanity, which chainRatchetStep() also implicitly presupposes: 0x01 and 0x02 yield
        // different outputs (otherwise messageKey === nextChainKey).
        expect(bytesToHex(nobleMessageKey)).not.toBe(bytesToHex(nobleNextChainKey));
      }
    });
  });

  describe('XChaCha20-Poly1305', () => {
    // node:crypto does NOT support XChaCha20-Poly1305 natively (only ChaCha20-Poly1305 with a
    // 12-byte nonce, see the Node documentation on supported cipher algorithms) — hence
    // deliberately NO second implementation of our own here (risk of a faulty re-build), but
    // official, PUBLISHED test vectors.
    //
    // SOURCE: draft-irtf-cfrg-xchacha-03 (IETF, Arciszewski, "XChaCha: eXtended-nonce ChaCha and
    // AEAD_XChaCha20_Poly1305"), appendix A.3.1 "AEAD_XCHACHA20_POLY1305". Provenance (same
    // principle as the RFC 7748 vectors in x25519EdgeCases.test.ts — a wrong test vector would be
    // worse than none):
    //   1. A first retrieval through a summarizing fetch tool of
    //      https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt returned a plaintext
    //      value that was ONE byte too short (an 's' in "sunscreen" was missing, 113 instead of
    //      114 bytes) — an alteration by the summarization step of the tool, not an error of the
    //      source itself.
    //   2. Therefore the values below were NOT taken from that retrieval, but from the raw draft
    //      text downloaded directly with curl from the same URL, with the lines around "A.3.1."
    //      counted/assembled by hand (no summarization in between). The length of each field was
    //      additionally checked programmatically against the expected byte count
    //      (plaintext/ciphertext 114 bytes each, tag 16 bytes, key 32 bytes, nonce 24 bytes) — all
    //      correct.
    //   3. The plaintext itself is additionally the literally identical, publicly known RFC 8439
    //      §2.8.2 test-vector text ("Ladies and Gentlemen of the class of '99: ..."), re-encoded
    //      independently from the ASCII text to hex — it matches the value loaded via curl
    //      exactly.
    const PLAINTEXT_HEX =
      '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66' +
      '202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e6520' +
      '74697020666f7220746865206675747572652c2073756e73637265656e20776f756c6420' +
      '62652069742e';
    const AAD_HEX = '50515253c0c1c2c3c4c5c6c7';
    const KEY_HEX =
      '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f';
    const NONCE_HEX = '404142434445464748494a4b4c4d4e4f5051525354555657';
    const CIPHERTEXT_HEX =
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b' +
      '0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945' +
      'b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f6' +
      '15c68b13b52e';
    const TAG_HEX = 'c0875924c1c7987947deafd8780acf49';

    it('the test vectors themselves are well-formed (correct byte lengths) — protection against the copy/retrieval error that occurred once before', () => {
      expect(PLAINTEXT_HEX.length / 2).toBe(114);
      expect(AAD_HEX.length / 2).toBe(12);
      expect(KEY_HEX.length / 2).toBe(32);
      expect(NONCE_HEX.length / 2).toBe(24);
      expect(CIPHERTEXT_HEX.length / 2).toBe(114);
      expect(TAG_HEX.length / 2).toBe(16);
      // The plaintext was independently re-computed from the known RFC 8439 example sentence.
      const expectedAscii =
        "Ladies and Gentlemen of the class of '99: If I could offer you only " +
        'one tip for the future, sunscreen would be it.';
      expect(PLAINTEXT_HEX).toBe(bytesToHex(utf8ToBytes(expectedAscii)));
    });

    it('@noble/ciphers xchacha20poly1305 (as used in session.ts/attachmentCrypto.ts) encrypts exactly to the official ciphertext+tag from draft-irtf-cfrg-xchacha-03', () => {
      const cipher = xchacha20poly1305(
        hexToBytes(KEY_HEX),
        hexToBytes(NONCE_HEX),
        hexToBytes(AAD_HEX),
      );
      const output = cipher.encrypt(hexToBytes(PLAINTEXT_HEX));
      const outputHex = bytesToHex(output);

      expect(outputHex.slice(0, CIPHERTEXT_HEX.length)).toBe(CIPHERTEXT_HEX);
      expect(outputHex.slice(CIPHERTEXT_HEX.length)).toBe(TAG_HEX);
    });

    it('@noble/ciphers xchacha20poly1305 decrypts the same official vector back to the expected plaintext', () => {
      const cipher = xchacha20poly1305(
        hexToBytes(KEY_HEX),
        hexToBytes(NONCE_HEX),
        hexToBytes(AAD_HEX),
      );
      const decrypted = cipher.decrypt(hexToBytes(CIPHERTEXT_HEX + TAG_HEX));
      expect(bytesToHex(decrypted)).toBe(PLAINTEXT_HEX);
    });

    it('a manipulated tag byte is rejected (AEAD integrity, no false acceptance of an otherwise correct official vector)', () => {
      const cipher = xchacha20poly1305(
        hexToBytes(KEY_HEX),
        hexToBytes(NONCE_HEX),
        hexToBytes(AAD_HEX),
      );
      const tamperedHex =
        CIPHERTEXT_HEX + TAG_HEX.slice(0, -2) + (TAG_HEX.slice(-2) === '00' ? '01' : '00');
      expect(() => cipher.decrypt(hexToBytes(tamperedHex))).toThrow();
    });
  });
});

// -------------------------------------------------------------------------------------------
// Level 2: independent node:crypto re-implementation of the KDF construction from session.ts.
// EXPLICITLY NOT re-built: the Ed25519 signature/freshness binding (KCI hardening) — that is
// protocol AUTHENTICATION, not a core piece of the pure KDF chain. encryptMessage/decryptMessage
// are called below as usual with real Ed25519 keys (as in session.test.ts), but ONLY the KDF chain
// itself (rootKey/chainKey/messageKey) is compared, never the signature check.
// -------------------------------------------------------------------------------------------

// Counterpart to deriveInitialKeys() (session.ts) — identical construction (sorted concatenation
// of the two static public keys as salt, info="oniveil-session-init", 3*32=96 bytes of output,
// split into rootKey/lowerToHigherChain/higherToLowerChain), but exclusively with node:crypto
// primitives instead of @noble/hashes/hkdf.
function independentDeriveInitialKeys(
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
  const output = nodeHkdfSha256(sharedSecret, salt, info, 32 * 3);
  return {
    rootKey: output.subarray(0, 32),
    lowerToHigherChain: output.subarray(32, 64),
    higherToLowerChain: output.subarray(64),
  };
}

// Counterpart to chainRatchetStep() (session.ts) — identical construction (HMAC-SHA256 of the
// chain key over 0x01 for the message key, over 0x02 for the next chain key), but with
// node:crypto.createHmac instead of @noble/hashes/hmac.
function independentChainRatchetStep(chainKey: Uint8Array): {
  messageKey: Uint8Array;
  nextChainKey: Uint8Array;
} {
  return {
    messageKey: nodeHmacSha256(chainKey, new Uint8Array([0x01])),
    nextChainKey: nodeHmacSha256(chainKey, new Uint8Array([0x02])),
  };
}

// Counterpart to dhRatchetStep() (session.ts) — identical construction (HKDF-SHA256 with dhOutput
// as IKM, rootKey as salt, info="oniveil-ratchet-step", 2*32=64 bytes of output, split into
// nextRootKey/chainKey), but with node:crypto.hkdfSync instead of @noble/hashes/hkdf.
function independentDhRatchetStep(
  rootKey: Uint8Array,
  dhOutput: Uint8Array,
): {nextRootKey: Uint8Array; chainKey: Uint8Array} {
  const output = nodeHkdfSha256(
    dhOutput,
    rootKey,
    utf8ToBytes('oniveil-ratchet-step'),
    64,
  );
  return {
    nextRootKey: output.subarray(0, 32),
    chainKey: output.subarray(32),
  };
}

// Counterpart to upgradeChainKeyWithFreshness() (session.ts) — required for the KDF-chain match at
// message 0 of each direction (without this step, the independently re-computed chain key would
// already deviate from the very first message). A pure HKDF application like dhRatchetStep — no
// authentication/signature logic (which stays untouched). Without this addition, a 5+-message
// scenario (which inevitably begins at message 0 of each direction) could not be carried out for
// the chain-key comparison at all.
function independentUpgradeChainKeyWithFreshness(
  chainKey: Uint8Array,
  freshness: Uint8Array,
): Uint8Array {
  return nodeHkdfSha256(
    chainKey,
    freshness,
    utf8ToBytes('oniveil-initial-chain-auth'),
    32,
  );
}

function sequenceNumberToBytes(sequenceNumber: number): Uint8Array {
  const bytes = new Uint8Array(8);
  new DataView(bytes.buffer).setBigUint64(0, BigInt(sequenceNumber), false);
  return bytes;
}

// Independently re-computes a SEND step (encryptMessage call): takes the session snapshot BEFORE
// the real call as well as the envelope/nextSession actually returned, and re-derives with
// node:crypto primitives what session.ts must have done internally. After each step it checks
// rootKey and (send-side) chainKey against the session fields actually returned by session.ts,
// AND messageKey indirectly via a successful AEAD decryption attempt of the ciphertext actually
// transmitted (XChaCha20-Poly1305 accepts the tag only for a bit-identical key — already
// verified above against the official test vectors, so here a reliable equality oracle for
// messageKey, without session.ts having to export the internal messageKey itself).
function independentSendStep(
  before: Session,
  envelope: OutgoingEnvelope,
  after: Session,
): {rotated: boolean} {
  const rotated = envelope.ratchetPublicKey !== before.myRatchetPublicKey;
  let rootKey = hexToBytes(before.rootKey);
  let chainKey = hexToBytes(before.sendingChainKey);

  if (rotated) {
    // encryptMessage generated a fresh ratchet key pair (now in
    // after.myRatchetPrivateKey/after.myRatchetPublicKey) and combined it via ECDH with the peer
    // ratchet key known at that time (before.theirRatchetPublicKey).
    const dhOutput = nodeX25519SharedSecret(
      after.myRatchetPrivateKey,
      after.myRatchetPublicKey,
      before.theirRatchetPublicKey,
    );
    const step = independentDhRatchetStep(rootKey, dhOutput);
    rootKey = step.nextRootKey;
    chainKey = step.chainKey;
  }
  expect(bytesToHex(rootKey)).toBe(after.rootKey);

  if (envelope.sequenceNumber === 0) {
    chainKey = independentUpgradeChainKeyWithFreshness(
      chainKey,
      hexToBytes(envelope.initialFreshness!),
    );
  }

  const {messageKey, nextChainKey} = independentChainRatchetStep(chainKey);
  expect(bytesToHex(nextChainKey)).toBe(after.sendingChainKey);

  const plaintextBytes = xchacha20poly1305(
    messageKey,
    hexToBytes(envelope.nonce),
    sequenceNumberToBytes(envelope.sequenceNumber),
  ).decrypt(hexToBytes(envelope.ciphertext));
  expect(plaintextBytes).toBeInstanceOf(Uint8Array);

  return {rotated};
}

// Symmetric counterpart for a RECEIVE step (decryptMessage call).
function independentReceiveStep(
  before: Session,
  envelope: OutgoingEnvelope,
  after: Session,
  expectedPlaintext: string,
): {rotated: boolean} {
  const rotated =
    envelope.ratchetPublicKey !== before.receivingChainRatchetedForTheirKey;
  let rootKey = hexToBytes(before.rootKey);
  let chainKey = hexToBytes(before.receivingChainKey);

  if (rotated) {
    // decryptMessage uses the OWN ratchet private key current at that time (not rotating during
    // receiving itself) — before.myRatchetPrivateKey.
    const dhOutput = nodeX25519SharedSecret(
      before.myRatchetPrivateKey,
      before.myRatchetPublicKey,
      envelope.ratchetPublicKey,
    );
    const step = independentDhRatchetStep(rootKey, dhOutput);
    rootKey = step.nextRootKey;
    chainKey = step.chainKey;
  }
  expect(bytesToHex(rootKey)).toBe(after.rootKey);

  if (envelope.sequenceNumber === 0) {
    chainKey = independentUpgradeChainKeyWithFreshness(
      chainKey,
      hexToBytes(envelope.initialFreshness!),
    );
  }

  const {messageKey, nextChainKey} = independentChainRatchetStep(chainKey);
  expect(bytesToHex(nextChainKey)).toBe(after.receivingChainKey);

  const plaintextBytes = xchacha20poly1305(
    messageKey,
    hexToBytes(envelope.nonce),
    sequenceNumberToBytes(envelope.sequenceNumber),
  ).decrypt(hexToBytes(envelope.ciphertext));
  expect(bytesToUtf8(plaintextBytes)).toBe(expectedPlaintext);

  return {rotated};
}

describe('Level 2: protocol-derivation correctness against an independent node:crypto re-implementation', () => {
  it('deriveInitialKeys: the independent node:crypto re-computation yields, for a fresh key pair, the same rootKey/initial chain keys as createSession()', () => {
    const alice = keypair();
    const bob = keypair();
    const aliceSession = createSession(alice.privateKey, alice.publicKey, bob.publicKey);
    const bobSession = createSession(bob.privateKey, bob.publicKey, alice.publicKey);

    const sharedSecret = nodeX25519SharedSecret(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    const amLower = alice.publicKey < bob.publicKey;
    const lowerPub = hexToBytes(amLower ? alice.publicKey : bob.publicKey);
    const higherPub = hexToBytes(amLower ? bob.publicKey : alice.publicKey);
    const independent = independentDeriveInitialKeys(sharedSecret, lowerPub, higherPub);

    expect(bytesToHex(independent.rootKey)).toBe(aliceSession.rootKey);
    expect(bytesToHex(independent.rootKey)).toBe(bobSession.rootKey);

    const expectedAliceSendChain = amLower
      ? independent.lowerToHigherChain
      : independent.higherToLowerChain;
    const expectedBobSendChain = amLower
      ? independent.higherToLowerChain
      : independent.lowerToHigherChain;
    expect(bytesToHex(expectedAliceSendChain)).toBe(aliceSession.sendingChainKey);
    expect(bytesToHex(expectedBobSendChain)).toBe(bobSession.sendingChainKey);
    // Each side receives on the chain on which the other one sends.
    expect(bytesToHex(expectedAliceSendChain)).toBe(bobSession.receivingChainKey);
    expect(bytesToHex(expectedBobSendChain)).toBe(aliceSession.receivingChainKey);
  });

  it('multi-step scenario (6 messages ping-pong, including at least one real DH rotation): rootKey/chainKey/messageKey of the REAL session.ts implementation match the independent node:crypto re-computation after EVERY single step', async () => {
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    const bobSigning = await signingKeypair();

    let aliceSession = createSession(alice.privateKey, alice.publicKey, bob.publicKey);
    let bobSession = createSession(bob.privateKey, bob.publicKey, alice.publicKey);

    let rotationCount = 0;
    const ROUNDS = 3; // 3 * 2 = 6 messages, >= 5.

    for (let round = 0; round < ROUNDS; round++) {
      const aliceBefore = aliceSession;
      const fromAlice = await encryptMessage(
        aliceSession,
        `alice-${round}`,
        aliceSigning.privateKey,
      );
      const aliceSendResult = independentSendStep(
        aliceBefore,
        fromAlice.envelope,
        fromAlice.nextSession,
      );
      rotationCount += aliceSendResult.rotated ? 1 : 0;
      aliceSession = fromAlice.nextSession;

      const bobBeforeReceive = bobSession;
      const bobReceives = await decryptMessage(
        bobSession,
        fromAlice.envelope,
        aliceSigning.publicKey,
      );
      expect(bobReceives.plaintext).toBe(`alice-${round}`);
      const bobReceiveResult = independentReceiveStep(
        bobBeforeReceive,
        fromAlice.envelope,
        bobReceives.nextSession,
        `alice-${round}`,
      );
      rotationCount += bobReceiveResult.rotated ? 1 : 0;
      bobSession = bobReceives.nextSession;

      const bobBeforeSend = bobSession;
      const fromBob = await encryptMessage(
        bobSession,
        `bob-${round}`,
        bobSigning.privateKey,
      );
      const bobSendResult = independentSendStep(
        bobBeforeSend,
        fromBob.envelope,
        fromBob.nextSession,
      );
      rotationCount += bobSendResult.rotated ? 1 : 0;
      bobSession = fromBob.nextSession;

      const aliceBeforeReceive = aliceSession;
      const aliceReceives = await decryptMessage(
        aliceSession,
        fromBob.envelope,
        bobSigning.publicKey,
      );
      expect(aliceReceives.plaintext).toBe(`bob-${round}`);
      const aliceReceiveResult = independentReceiveStep(
        aliceBeforeReceive,
        fromBob.envelope,
        aliceReceives.nextSession,
        `bob-${round}`,
      );
      rotationCount += aliceReceiveResult.rotated ? 1 : 0;
      aliceSession = aliceReceives.nextSession;
    }

    // Hard confirmation that the scenario actually went through at least one REAL DH rotation —
    // with pure ping-pong that is structurally guaranteed (exactly one side forces a rotation via
    // amLower on its first sent message, see session.ts module documentation, point 3), here
    // additionally confirmed empirically instead of merely assumed.
    expect(rotationCount).toBeGreaterThan(0);
  });
});
