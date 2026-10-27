/**
 * @format
 */

// session.ts does not import react-native-get-random-values itself, but the underlying @noble
// libraries still need a crypto.getRandomValues source.
// @ts-ignore
global.crypto = global.crypto ?? require('crypto').webcrypto;

import {describe, it, expect} from '@jest/globals';
import {x25519} from '@noble/curves/ed25519.js';
import {xchacha20poly1305} from '@noble/ciphers/chacha.js';
import * as ed from '@noble/ed25519';
import {hkdf} from '@noble/hashes/hkdf.js';
import {hmac} from '@noble/hashes/hmac.js';
import {sha256, sha512} from '@noble/hashes/sha2.js';
import {bytesToHex, hexToBytes, utf8ToBytes} from '@noble/hashes/utils.js';
import {
  computeAckMac,
  createSession,
  decryptMessage,
  encryptMessage,
  InvalidInitialAuthError,
  isValidSession,
  MAX_RECENTLY_CONSUMED_KEYS,
  OutgoingEnvelope,
  ReplayOrOutOfOrderError,
  Session,
  verifyAckMac,
} from '../src/crypto/session';
import {bytesToUtf8} from '../src/crypto/textCodec';

// @noble/ed25519 v2 needs a SHA-512 implementation supplied from outside (same pattern as in
// crypto/identity.ts and crypto/session.ts itself).
ed.hashes.sha512Async = (m: Uint8Array) => Promise.resolve(sha512(m));

function keypair() {
  const {secretKey, publicKey} = x25519.keygen();
  return {privateKey: bytesToHex(secretKey), publicKey: bytesToHex(publicKey)};
}

// Second, completely independent key pair per person (Ed25519, signature) — NOT to be confused
// with the X25519 encryption keys above, just as in identity.ts.
async function signingKeypair() {
  const {secretKey, publicKey} = await ed.keygenAsync();
  return {privateKey: bytesToHex(secretKey), publicKey: bytesToHex(publicKey)};
}

describe('session', () => {
  it('derives the same initial root key symmetrically on both parties', () => {
    const alice = keypair();
    const bob = keypair();

    const aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    const bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    expect(aliceSession.rootKey).toBe(bobSession.rootKey);
    // Each side starts with its own static key as the first ratchet key, and knows the peer's
    // correspondingly mirrored.
    expect(aliceSession.myRatchetPublicKey).toBe(
      bobSession.theirRatchetPublicKey,
    );
    expect(bobSession.myRatchetPublicKey).toBe(
      aliceSession.theirRatchetPublicKey,
    );
  });

  it('Alice can send Bob a message that he can decrypt', async () => {
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    const aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    const bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    const {envelope} = await encryptMessage(
      aliceSession,
      'hallo bob',
      aliceSigning.privateKey,
    );
    const {plaintext} = await decryptMessage(
      bobSession,
      envelope,
      aliceSigning.publicKey,
    );

    expect(plaintext).toBe('hallo bob');
  });

  describe('authenticated acknowledgement', () => {
    async function sendOne() {
      const alice = keypair();
      const bob = keypair();
      const aliceSigning = await signingKeypair();
      const aliceSession = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      const bobSession = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );
      const sent = await encryptMessage(aliceSession, 'hi', aliceSigning.privateKey);
      const received = await decryptMessage(
        bobSession,
        sent.envelope,
        aliceSigning.publicKey,
      );
      return {sent, received, bobSession, aliceSigning};
    }

    it('sender and recipient derive the same acknowledgement key', async () => {
      const {sent, received} = await sendOne();
      expect(sent.ackKey).toMatch(/^[0-9a-f]{64}$/);
      expect(received.ackKey).toBe(sent.ackKey);
    });

    it('accepts a MAC of the real recipient and binds it to the sequence number', async () => {
      const {sent} = await sendOne();
      const mac = computeAckMac(sent.ackKey, 0);
      expect(verifyAckMac(sent.ackKey, 0, mac)).toBe(true);
      expect(verifyAckMac(sent.ackKey, 1, mac)).toBe(false);
    });

    it('rejects a MAC computed with a different key and malformed values', async () => {
      const {sent} = await sendOne();
      const other = await sendOne();
      expect(verifyAckMac(sent.ackKey, 0, computeAckMac(other.sent.ackKey, 0))).toBe(false);
      expect(verifyAckMac(sent.ackKey, 0, 'zz')).toBe(false);
      expect(verifyAckMac('zz', 0, computeAckMac(sent.ackKey, 0))).toBe(false);
    });

    it('a repeated delivery of the same envelope yields the same acknowledgement key', async () => {
      const {sent, received, bobSession, aliceSigning} = await sendOne();
      const repeat = await decryptMessage(
        received.nextSession,
        sent.envelope,
        aliceSigning.publicKey,
      );
      expect(repeat.duplicate).toBe(true);
      expect(repeat.ackKey).toBe(sent.ackKey);
      expect(bobSession).toBeDefined();
    });
  });

  it('works independently in both directions at the same time', async () => {
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    const bobSigning = await signingKeypair();
    let aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    let bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    const aliceToBob = await encryptMessage(
      aliceSession,
      'von alice',
      aliceSigning.privateKey,
    );
    aliceSession = aliceToBob.nextSession;
    const bobToAlice = await encryptMessage(
      bobSession,
      'von bob',
      bobSigning.privateKey,
    );
    bobSession = bobToAlice.nextSession;

    const bobReceives = await decryptMessage(
      bobSession,
      aliceToBob.envelope,
      aliceSigning.publicKey,
    );
    const aliceReceives = await decryptMessage(
      aliceSession,
      bobToAlice.envelope,
      bobSigning.publicKey,
    );

    expect(bobReceives.plaintext).toBe('von alice');
    expect(aliceReceives.plaintext).toBe('von bob');
  });

  it('several messages in a row are decrypted correctly in order', async () => {
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    let aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    let bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    const sent: string[] = [];
    for (let i = 0; i < 5; i++) {
      const {envelope, nextSession} = await encryptMessage(
        aliceSession,
        `nachricht ${i}`,
        aliceSigning.privateKey,
      );
      aliceSession = nextSession;
      const {plaintext, nextSession: nextBobSession} = await decryptMessage(
        bobSession,
        envelope,
        aliceSigning.publicKey,
      );
      bobSession = nextBobSession;
      sent.push(plaintext);
    }

    expect(sent).toEqual([
      'nachricht 0',
      'nachricht 1',
      'nachricht 2',
      'nachricht 3',
      'nachricht 4',
    ]);
  });

  it('several messages in both directions in alternation stay in sync (ratchet ping-pong)', async () => {
    // Property-style test for the DH ratchet: alternately sending/receiving in both directions,
    // over several rounds — every message rotates the ratchet public key of the respective sender
    // (see session.ts), yet the sessions must stay in sync.
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    const bobSigning = await signingKeypair();
    let aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    let bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    for (let round = 0; round < 8; round++) {
      const fromAlice = await encryptMessage(
        aliceSession,
        `alice-${round}`,
        aliceSigning.privateKey,
      );
      aliceSession = fromAlice.nextSession;
      const bobDecrypts = await decryptMessage(
        bobSession,
        fromAlice.envelope,
        aliceSigning.publicKey,
      );
      bobSession = bobDecrypts.nextSession;
      expect(bobDecrypts.plaintext).toBe(`alice-${round}`);

      const fromBob = await encryptMessage(
        bobSession,
        `bob-${round}`,
        bobSigning.privateKey,
      );
      bobSession = fromBob.nextSession;
      const aliceDecrypts = await decryptMessage(
        aliceSession,
        fromBob.envelope,
        bobSigning.publicKey,
      );
      aliceSession = aliceDecrypts.nextSession;
      expect(aliceDecrypts.plaintext).toBe(`bob-${round}`);
    }
  });

  it('rotates the own ratchet public key on the next reply after receiving a new peer key (post-compromise security)', async () => {
    // Two consecutive SENDS WITHOUT a receive in between deliberately do NOT rotate (see the module
    // documentation in session.ts — otherwise exactly that would break simultaneity in the test
    // "works independently in both directions at the same time"). Rotation is receive-driven: only
    // a reply AFTER receiving a new peer ratchet key is guaranteed to produce a new own ratchet
    // public key.
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    const bobSigning = await signingKeypair();
    let aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    let bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    const first = await encryptMessage(
      aliceSession,
      'a',
      aliceSigning.privateKey,
    );
    aliceSession = first.nextSession;
    bobSession = (
      await decryptMessage(bobSession, first.envelope, aliceSigning.publicKey)
    ).nextSession;
    const bobReply = await encryptMessage(
      bobSession,
      'antwort',
      bobSigning.privateKey,
    );
    bobSession = bobReply.nextSession;
    aliceSession = (
      await decryptMessage(
        aliceSession,
        bobReply.envelope,
        bobSigning.publicKey,
      )
    ).nextSession;
    const second = await encryptMessage(
      aliceSession,
      'b',
      aliceSigning.privateKey,
    );

    expect(second.envelope.ratchetPublicKey).not.toBe(
      first.envelope.ratchetPublicKey,
    );
  });

  it('post-compromise security: a stolen session state from before an own reply can no longer decrypt a message arriving afterwards', async () => {
    // Simulates an attacker who steals Bob's ENTIRE session state (including the private ratchet
    // key) immediately after receiving Alice's first message — before Bob replies himself. As soon
    // as Bob replies, a fresh key pair unknown to the attacker flows in; Alice's next message
    // (which uses this new key pair as its DH partner) can no longer be decrypted with the stolen
    // OLD state — exactly the self-healing that distinguishes the DH ratchet from the pure HMAC
    // chain ratchet.
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    const bobSigning = await signingKeypair();
    let aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    let bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    const msg1 = await encryptMessage(
      aliceSession,
      'vor der kompromittierung',
      aliceSigning.privateKey,
    );
    aliceSession = msg1.nextSession;
    bobSession = (
      await decryptMessage(bobSession, msg1.envelope, aliceSigning.publicKey)
    ).nextSession;
    const stolenBobSession = bobSession; // the attacker knows exactly this state.

    // Bob replies — internally generating a fresh ratchet key pair unknown to the attacker (see
    // encryptMessage).
    const reply = await encryptMessage(
      bobSession,
      'antwort von bob',
      bobSigning.privateKey,
    );
    bobSession = reply.nextSession;
    aliceSession = (
      await decryptMessage(aliceSession, reply.envelope, bobSigning.publicKey)
    ).nextSession;

    // Alice's next message uses Bob's NEW (to the attacker unknown) ratchet public key as its DH
    // partner.
    const msg3 = await encryptMessage(
      aliceSession,
      'nach der heilung',
      aliceSigning.privateKey,
    );

    await expect(
      decryptMessage(stolenBobSession, msg3.envelope, aliceSigning.publicKey),
    ).rejects.toThrow();
    // The real, advanced Bob can of course still read it.
    const healed = await decryptMessage(
      bobSession,
      msg3.envelope,
      aliceSigning.publicKey,
    );
    expect(healed.plaintext).toBe('nach der heilung');
  });

  it('confirms an exact repeat of an already processed message again, instead of rejecting it (lost ack)', async () => {
    // Observed on a real device over Tor: if the own acknowledgement is lost, the sender's outbox
    // resends the same envelope unchanged — that MUST be acceptable, otherwise this one failure
    // permanently blocks all later messages of the same contact (see the module documentation
    // "Tolerance for REPEATED delivery").
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    const aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    let bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    const {envelope} = await encryptMessage(
      aliceSession,
      'einmalig',
      aliceSigning.privateKey,
    );
    const first = await decryptMessage(
      bobSession,
      envelope,
      aliceSigning.publicKey,
    );
    bobSession = first.nextSession;
    expect(first.duplicate).toBe(false);

    const repeated = await decryptMessage(
      bobSession,
      envelope,
      aliceSigning.publicKey,
    );
    expect(repeated.duplicate).toBe(true);
    expect(repeated.plaintext).toBe('einmalig');
    // A repeat must not advance the ratchet state again.
    expect(repeated.nextSession).toEqual(bobSession);
  });

  it('rejects a manipulated repeat although the sequence number lies in the window', async () => {
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    const aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    let bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    const {envelope} = await encryptMessage(
      aliceSession,
      'einmalig',
      aliceSigning.privateKey,
    );
    bobSession = (
      await decryptMessage(bobSession, envelope, aliceSigning.publicKey)
    ).nextSession;

    const tampered: OutgoingEnvelope = {
      ...envelope,
      ciphertext:
        envelope.ciphertext.slice(0, -1) +
        (envelope.ciphertext.slice(-1) === '0' ? '1' : '0'),
    };
    await expect(
      decryptMessage(bobSession, tampered, aliceSigning.publicKey),
    ).rejects.toThrow(ReplayOrOutOfOrderError);
  });

  it('rejects a repeatedly injected message once it has fallen out of the repeat window (replay protection)', async () => {
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    let aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    let bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    const first = await encryptMessage(
      aliceSession,
      'einmalig',
      aliceSigning.privateKey,
    );
    const firstEnvelope = first.envelope;
    aliceSession = first.nextSession;
    bobSession = (
      await decryptMessage(
        bobSession,
        firstEnvelope,
        aliceSigning.publicKey,
      )
    ).nextSession;

    // Enough further, each immediately processed messages to push the first one out of the
    // bounded repeat window (see MAX_RECENTLY_CONSUMED_KEYS).
    for (let i = 0; i < MAX_RECENTLY_CONSUMED_KEYS; i++) {
      const next = await encryptMessage(
        aliceSession,
        `nachricht ${i}`,
        aliceSigning.privateKey,
      );
      aliceSession = next.nextSession;
      bobSession = (
        await decryptMessage(
          bobSession,
          next.envelope,
          aliceSigning.publicKey,
        )
      ).nextSession;
    }

    await expect(
      decryptMessage(bobSession, firstEnvelope, aliceSigning.publicKey),
    ).rejects.toThrow(ReplayOrOutOfOrderError);
  });

  it('rejects a skipped sequence number (reorder protection)', async () => {
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    let aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    const bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    const first = await encryptMessage(
      aliceSession,
      'erste',
      aliceSigning.privateKey,
    );
    aliceSession = first.nextSession;
    const second = await encryptMessage(
      aliceSession,
      'zweite',
      aliceSigning.privateKey,
    );

    // The first message is "lost" — Bob gets the second one directly.
    await expect(
      decryptMessage(bobSession, second.envelope, aliceSigning.publicKey),
    ).rejects.toThrow(ReplayOrOutOfOrderError);
  });

  it('rejects a manipulated ciphertext (authentication fails)', async () => {
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    const aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    const bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    const {envelope} = await encryptMessage(
      aliceSession,
      'geheim',
      aliceSigning.privateKey,
    );
    const tampered: OutgoingEnvelope = {
      ...envelope,
      ciphertext:
        envelope.ciphertext.slice(0, -1) +
        (envelope.ciphertext.slice(-1) === '0' ? '1' : '0'),
    };

    await expect(
      decryptMessage(bobSession, tampered, aliceSigning.publicKey),
    ).rejects.toThrow();
  });

  it('rejects an envelope with a manipulated ratchet public key (authentication fails)', async () => {
    // The ratchet public key does not enter as AEAD additional data, but it does co-determine the
    // derived message key — a different ratchet public key leads to a different message key, with
    // which the (unchanged) ciphertext no longer authenticates. The Ed25519 signature deliberately
    // does NOT bind to ratchetPublicKey (only to freshness + both static keys), so the signature
    // check does not intervene here — the rejection still comes from the AEAD check.
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    const aliceSession = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );
    const bobSession = createSession(
      bob.privateKey,
      bob.publicKey,
      alice.publicKey,
    );

    const {envelope} = await encryptMessage(
      aliceSession,
      'geheim',
      aliceSigning.privateKey,
    );
    const attacker = keypair();
    const tampered: OutgoingEnvelope = {
      ...envelope,
      ratchetPublicKey: attacker.publicKey,
    };

    await expect(
      decryptMessage(bobSession, tampered, aliceSigning.publicKey),
    ).rejects.toThrow();
  });

  it('advances the chain key after every message (no reuse of the message key)', async () => {
    const alice = keypair();
    const bob = keypair();
    const aliceSigning = await signingKeypair();
    let aliceSession: Session = createSession(
      alice.privateKey,
      alice.publicKey,
      bob.publicKey,
    );

    const first = await encryptMessage(
      aliceSession,
      'a',
      aliceSigning.privateKey,
    );
    aliceSession = first.nextSession;
    const second = await encryptMessage(
      aliceSession,
      'b',
      aliceSigning.privateKey,
    );

    expect(second.envelope.ciphertext).not.toBe(first.envelope.ciphertext);
    expect(aliceSession.sendingChainKey).not.toBe(
      createSession(alice.privateKey, alice.publicKey, bob.publicKey)
        .sendingChainKey,
    );
  });

  describe('isValidSession', () => {
    it('accepts a freshly created session', () => {
      const alice = keypair();
      const bob = keypair();
      const session = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      expect(isValidSession(session)).toBe(true);
    });

    it('rejects a session in the old (pre-Double-Ratchet) format', () => {
      const oldShapeSession = {
        sendingChainKey: '11'.repeat(32),
        receivingChainKey: '22'.repeat(32),
        sendCounter: 3,
        receiveCounter: 5,
      };
      expect(isValidSession(oldShapeSession)).toBe(false);
    });

    it('rejects a session in the pre-KCI-hardening format (without myStaticPublicKey/theirStaticPublicKey)', () => {
      // Migration protection (see the comment at isValidSession in session.ts): a session that
      // already has the Double-Ratchet format but was stored BEFORE the KCI/reset hardening lacks
      // the two new static anchor fields and must therefore also count as invalid, so that it is
      // rebuilt automatically.
      const alice = keypair();
      const bob = keypair();
      const session = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      const {myStaticPublicKey, theirStaticPublicKey, ...withoutStaticKeys} =
        session;
      expect(isValidSession(withoutStaticKeys)).toBe(false);
    });

    it('rejects arbitrary nonsense instead of throwing', () => {
      expect(isValidSession(null)).toBe(false);
      expect(isValidSession(undefined)).toBe(false);
      expect(isValidSession('kaputt')).toBe(false);
      expect(isValidSession({})).toBe(false);
    });
  });

  describe('Ed25519 freshness binding on the first message per direction (KCI/reset hardening)', () => {
    it('Alice→Bob and Bob→Alice: the first message of each direction is encrypted/decrypted normally with a valid signature', async () => {
      const alice = keypair();
      const bob = keypair();
      const aliceSigning = await signingKeypair();
      const bobSigning = await signingKeypair();
      const aliceSession = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      const bobSession = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );

      const {envelope: aliceEnvelope} = await encryptMessage(
        aliceSession,
        'hallo bob',
        aliceSigning.privateKey,
      );
      expect(aliceEnvelope.sequenceNumber).toBe(0);
      expect(aliceEnvelope.initialFreshness).toBeDefined();
      expect(aliceEnvelope.initialAuth).toBeDefined();
      const bobResult = await decryptMessage(
        bobSession,
        aliceEnvelope,
        aliceSigning.publicKey,
      );
      expect(bobResult.plaintext).toBe('hallo bob');

      const {envelope: bobEnvelope} = await encryptMessage(
        bobSession,
        'hallo alice',
        bobSigning.privateKey,
      );
      expect(bobEnvelope.sequenceNumber).toBe(0);
      expect(bobEnvelope.initialFreshness).toBeDefined();
      expect(bobEnvelope.initialAuth).toBeDefined();
      const aliceResult = await decryptMessage(
        aliceSession,
        bobEnvelope,
        bobSigning.publicKey,
      );
      expect(aliceResult.plaintext).toBe('hallo alice');
    });

    it('rejects an envelope with sequenceNumber 0 without initialFreshness/initialAuth', async () => {
      const alice = keypair();
      const bob = keypair();
      const aliceSigning = await signingKeypair();
      const aliceSession = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      const bobSession = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );

      const {envelope} = await encryptMessage(
        aliceSession,
        'hallo bob',
        aliceSigning.privateKey,
      );
      const stripped: OutgoingEnvelope = {...envelope};
      delete stripped.initialFreshness;
      delete stripped.initialAuth;

      const beforeState = JSON.stringify(bobSession);
      await expect(
        decryptMessage(bobSession, stripped, aliceSigning.publicKey),
      ).rejects.toThrow(InvalidInitialAuthError);
      // Negative-state preservation: a rejected attempt must not change the session state held by
      // the receiver (no receiveCounter progress, no changed recentlyConsumedKeys, nothing) — see
      // the comment in session.ts directly above the ratchetPublicKey rotation block on the same
      // principle.
      expect(JSON.stringify(bobSession)).toBe(beforeState);
    });

    it('rejects an envelope with an invalid initialAuth signature', async () => {
      const alice = keypair();
      const bob = keypair();
      const aliceSigning = await signingKeypair();
      const aliceSession = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      const bobSession = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );

      const {envelope} = await encryptMessage(
        aliceSession,
        'hallo bob',
        aliceSigning.privateKey,
      );
      const originalAuth = envelope.initialAuth as string;
      const tampered: OutgoingEnvelope = {
        ...envelope,
        initialAuth:
          originalAuth.slice(0, -1) +
          (originalAuth.slice(-1) === '0' ? '1' : '0'),
      };

      const beforeState = JSON.stringify(bobSession);
      await expect(
        decryptMessage(bobSession, tampered, aliceSigning.publicKey),
      ).rejects.toThrow(InvalidInitialAuthError);
      expect(JSON.stringify(bobSession)).toBe(beforeState);
    });

    it('KCI regression test: an attacker with ONLY Alice\'s static X25519 private key cannot impersonate Bob towards Alice', async () => {
      // Simulates EXACTLY the attack this hardening addresses: before it, the first message of each
      // direction rested on purely static-static X25519 ECDH — someone who loses ONLY their own
      // static key (here: Alice's) can, via ECDH symmetry (X25519(Alice_priv, Bob_pub) ===
      // X25519(Bob_priv, Alice_pub)), derive the same root key/the same chain that Bob would also
      // derive independently — WITHOUT ever owning Bob's private key or Bob's Ed25519 signing
      // key.
      const alice = keypair();
      const bob = keypair();
      const aliceSigning = await signingKeypair();
      const bobSigning = await signingKeypair();
      const attackerSigning = await signingKeypair(); // NOT Bob's key pair

      const aliceSession = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );

      // The attacker knows only Alice's static private key as well as both public keys (public
      // anyway, part of the contact entry) — NOT Bob's private key. They call createSession
      // exactly like Alice herself and arrive (existing, intended property) at the same rootKey.
      const attackerView = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      expect(attackerView.rootKey).toBe(aliceSession.rootKey);

      // attackerView.receivingChainKey is exactly the chain that Alice expects for incoming
      // messages FROM Bob — before this hardening the attacker could have derived a valid message
      // key from it directly for a forged "first message from Bob".
      const forgedSession: Session = {
        ...attackerView,
        sendingChainKey: attackerView.receivingChainKey,
        myStaticPublicKey: bob.publicKey,
        theirStaticPublicKey: alice.publicKey,
        myRatchetPublicKey: bob.publicKey,
        theirRatchetPublicKey: alice.publicKey,
        sendingChainRatchetedForTheirKey: alice.publicKey,
        amLower: false,
        sendCounter: 0,
      };

      // The attacker does not own Bob's Ed25519 signing key — they can only sign with a key pair
      // of their own that does NOT match Bob's signingPublicKey.
      const {envelope: forgedEnvelope} = await encryptMessage(
        forgedSession,
        'gefälschte Nachricht, angeblich von Bob',
        attackerSigning.privateKey,
      );

      const beforeState = JSON.stringify(aliceSession);
      // Alice checks with BOB'S REAL signingPublicKey — the forgery is rejected BEFORE any AEAD
      // operation, the message is not accepted as "from Bob".
      await expect(
        decryptMessage(aliceSession, forgedEnvelope, bobSigning.publicKey),
      ).rejects.toThrow(InvalidInitialAuthError);
      expect(JSON.stringify(aliceSession)).toBe(beforeState);
    });

    it('reset regression test: two independent createSession calls with the same static keys yield different actual message keys for message 0', async () => {
      // Simulates deleteContact() followed by adding the same contact again: two independent
      // createSession calls with exactly the same static keys.
      const alice = keypair();
      const bob = keypair();
      const aliceSigning = await signingKeypair();

      const aliceSessionRun1 = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      const bobSessionRun1 = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );
      const aliceSessionRun2 = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );

      // Existing, UNCHANGED property: same rootKey, same initial sendingChainKey BEFORE the
      // upgrade by the new freshness component.
      expect(aliceSessionRun1.rootKey).toBe(aliceSessionRun2.rootKey);
      expect(aliceSessionRun1.sendingChainKey).toBe(
        aliceSessionRun2.sendingChainKey,
      );

      const {envelope: envelope1} = await encryptMessage(
        aliceSessionRun1,
        'geheime nachricht',
        aliceSigning.privateKey,
      );
      const {envelope: envelope2} = await encryptMessage(
        aliceSessionRun2,
        'geheime nachricht',
        aliceSigning.privateKey,
      );

      // A NEW random freshness on each pass.
      expect(envelope1.initialFreshness).not.toBe(envelope2.initialFreshness);

      // Direct proof that the message keys actually used differ (not just the nonce):
      // envelope1's ciphertext can NOT be decrypted with envelope2's freshness component, although
      // both start from the exactly same, deterministic rootKey/the same sendingChainKey BEFORE
      // the upgrade (see above) — envelope2's initialAuth is a REAL, valid signature (by Alice,
      // over envelope2's own freshness), so the signature check itself does NOT fail here; it is
      // the subsequent AEAD check that fails with the wrong message key (derived from the wrong
      // freshness) — the actual proof that a bit-identical reset is no longer possible.
      const splicedEnvelope: OutgoingEnvelope = {
        ...envelope1,
        initialFreshness: envelope2.initialFreshness,
        initialAuth: envelope2.initialAuth,
      };
      await expect(
        decryptMessage(bobSessionRun1, splicedEnvelope, aliceSigning.publicKey),
      ).rejects.toThrow();

      // For comparison: the unchanged, matching envelope still decrypts correctly.
      const decrypted = await decryptMessage(
        bobSessionRun1,
        envelope1,
        aliceSigning.publicKey,
      );
      expect(decrypted.plaintext).toBe('geheime nachricht');
    });
  });

  describe('forward-secrecy proof with exact message index', () => {
    // This test covers EXCLUSIVELY case A: the long-term static X25519 key of ONE side is
    // compromised (not its running session state), and in addition recorded network traffic is
    // available (the complete OutgoingEnvelope objects as they went over the wire — including
    // initialFreshness/initialAuth, which by the envelope definition in session.ts are sent in
    // the clear). The attacker recomputes PASSIVELY with the recorded, REAL signature/freshness —
    // they forge nothing, they need not forge anything. Not to be confused with:
    //   - Case B (only the running session state compromised, no long-term key): see above,
    //     "post-compromise security: a stolen session state from before an own reply can no longer
    //     decrypt a message arriving afterwards".
    //   - Case C (session state compromised + subsequent rotation): the same test as case B
    //     covers that as well (self-healing after Bob's reply).
    //   - the KCI regression test above ("an attacker with ONLY Alice's static X25519 private key
    //     cannot impersonate Bob towards Alice"): that tests an ACTIVE forgery/impersonation
    //     WITHOUT a prior recording — this test here tests PASSIVE recomputing/decrypting of
    //     recorded, real traffic.
    it('attacker with ONLY Bob\'s static X25519 long-term key + recorded Bob→Alice traffic decrypts exactly the messages BEFORE the first real rotation on Bob\'s send side, and none afterwards', async () => {
      // Deterministic placement of the rotation (instead of hoping for chance): Alice is amLower
      // (see session.ts module documentation, point 3) — her very first sent message THEREBY
      // forces a rotation on HER send side (forcedInitialRotation), regardless of what Bob has
      // done up to then. Bob, on the other hand, is NOT amLower — his send side rotates
      // exclusively RECEIVE-DRIVEN, as soon as he (on his next own send) sees a ratchet public key
      // from Alice that is NEW to him. That lets the rotation point on Bob's send side be placed
      // exactly: Bob first sends two messages BEFORE he has ever received anything from Alice (no
      // rotation possible); then Alice sends her (forcedly rotated) first message, Bob receives
      // it; Bob's NEXT (third) message thereby rotates for real, guaranteed. Reproduces the
      // pattern from sessionStateMachine.property.test.ts (there: keypairsWithBobLower, here
      // mirrored).
      function keypairsWithAliceLower() {
        for (;;) {
          const alice = keypair();
          const bob = keypair();
          if (alice.publicKey < bob.publicKey) {
            return {alice, bob};
          }
        }
      }

      const {alice, bob} = keypairsWithAliceLower();
      const aliceSigning = await signingKeypair();
      const bobSigning = await signingKeypair();
      let aliceSession = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      let bobSession = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );
      expect(aliceSession.amLower).toBe(true);
      expect(bobSession.amLower).toBe(false);

      const recorded: OutgoingEnvelope[] = [];
      const plaintexts: string[] = [];

      // Bob's first two messages: he has received NOTHING from Alice yet — neither
      // forcedInitialRotation (he is not amLower) nor receivedSomethingNew applies, so his send
      // side stays on the purely static-static derived chain key.
      for (let i = 0; i < 2; i++) {
        const plaintext = `bob-vor-rotation-${i}`;
        const {envelope, nextSession} = await encryptMessage(
          bobSession,
          plaintext,
          bobSigning.privateKey,
        );
        bobSession = nextSession;
        recorded.push(envelope);
        plaintexts.push(plaintext);
        // Realistic: Alice processes each message immediately (strict in-order delivery, see the
        // module documentation) — at the same time confirms that the real peer can read each of
        // these messages normally.
        const result = await decryptMessage(
          aliceSession,
          envelope,
          bobSigning.publicKey,
        );
        aliceSession = result.nextSession;
        expect(result.plaintext).toBe(plaintext);
      }

      // Alice sends her OWN first message — forced rotation on HER send side (amLower); her
      // envelope therefore carries a fresh ratchet public key not yet known to Bob.
      const aliceFirst = await encryptMessage(
        aliceSession,
        'alice-erste',
        aliceSigning.privateKey,
      );
      aliceSession = aliceFirst.nextSession;
      const bobReceivesAliceFirst = await decryptMessage(
        bobSession,
        aliceFirst.envelope,
        aliceSigning.publicKey,
      );
      bobSession = bobReceivesAliceFirst.nextSession;

      // Bob's third sent message (index 2 in our 0-based counting of the recorded Bob→Alice
      // envelopes) now satisfies `receivedSomethingNew` — Bob has just seen a new ratchet key from
      // Alice — and therefore rotates FOR REAL.
      const rotationIndex = recorded.length; // expected to be 2, checked hard below
      const bobBeforeRotation = bobSession;
      {
        const plaintext = 'bob-die-rotation-selbst';
        const {envelope, nextSession} = await encryptMessage(
          bobSession,
          plaintext,
          bobSigning.privateKey,
        );
        bobSession = nextSession;
        recorded.push(envelope);
        plaintexts.push(plaintext);
        const result = await decryptMessage(
          aliceSession,
          envelope,
          bobSigning.publicKey,
        );
        aliceSession = result.nextSession;
        expect(result.plaintext).toBe(plaintext);
      }
      // Confirms that a real rotation took place at EXACTLY this position (the same detection
      // logic as isRealRotation() in sessionStateMachine.property.test.ts: a pure HMAC chain
      // advance leaves myRatchetPublicKey unchanged).
      expect(bobBeforeRotation.myRatchetPublicKey).not.toBe(
        bobSession.myRatchetPublicKey,
      );
      expect(recorded[rotationIndex].ratchetPublicKey).not.toBe(
        recorded[rotationIndex - 1].ratchetPublicKey,
      );

      // Three further messages AFTER the rotation — no further rotation, since Bob has received
      // nothing new from Alice since his own rotation.
      for (let i = 0; i < 3; i++) {
        const plaintext = `bob-nach-rotation-${i}`;
        const {envelope, nextSession} = await encryptMessage(
          bobSession,
          plaintext,
          bobSigning.privateKey,
        );
        bobSession = nextSession;
        recorded.push(envelope);
        plaintexts.push(plaintext);
        const result = await decryptMessage(
          aliceSession,
          envelope,
          bobSigning.publicKey,
        );
        aliceSession = result.nextSession;
        expect(result.plaintext).toBe(plaintext);
      }

      expect(recorded).toHaveLength(6);
      expect(rotationIndex).toBe(2);

      // --- Attacker simulation ---
      // The attacker owns ONLY Bob's static X25519 private key (the compromised long-term secret)
      // as well as Alice's public key (public anyway, part of every contact entry) — NOT Bob's
      // running session state, NOT any ratchet private key, NOT Bob's Ed25519 signing key. They
      // compute INDEPENDENTLY, with exactly the same createSession() call that Bob originally made
      // himself, the initial rootKey/the initial sendingChainKey for the Bob→Alice direction.
      const attackerInitialSession = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );
      let attackerChainKey = hexToBytes(attackerInitialSession.sendingChainKey);

      for (let i = 0; i < recorded.length; i++) {
        const envelope = recorded[i];

        // sequenceNumber===0: the same one-time freshness upgrade as in
        // upgradeChainKeyWithFreshness() (session.ts) — the attacker forges NOTHING here, but adopts
        // the REAL initialFreshness already contained in the clear in the recorded envelope. The
        // attacker need not even check its Ed25519 signature (initialAuth) for that — they trust it
        // blindly, as a passive eavesdropper only sees the already flowed, valid traffic anyway.
        if (envelope.sequenceNumber === 0) {
          attackerChainKey = hkdf(
            sha256,
            attackerChainKey,
            hexToBytes(envelope.initialFreshness!),
            utf8ToBytes('oniveil-initial-chain-auth'),
            32,
          );
        }

        // Exactly the same two HMAC calls as chainRatchetStep() in session.ts (not exported, hence
        // deliberately duplicated here instead of additionally exported — session.ts stays
        // unchanged).
        const messageKey = hmac(sha256, attackerChainKey, new Uint8Array([0x01]));
        const nextChainKey = hmac(sha256, attackerChainKey, new Uint8Array([0x02]));

        const sequenceNumberBytes = new Uint8Array(8);
        new DataView(sequenceNumberBytes.buffer).setBigUint64(
          0,
          BigInt(envelope.sequenceNumber),
          false,
        );

        if (i < rotationIndex) {
          // BEFORE the rotation: pure static-static ECDH + pure HMAC chain advance — the attacker
          // reconstructs exactly the same message key as Bob back then and successfully decrypts
          // the recorded ciphertext.
          const plaintextBytes = xchacha20poly1305(
            messageKey,
            hexToBytes(envelope.nonce),
            sequenceNumberBytes,
          ).decrypt(hexToBytes(envelope.ciphertext));
          expect(bytesToUtf8(plaintextBytes)).toBe(plaintexts[i]);
        } else {
          // FROM the rotation on (including the rotation index itself): the REAL chain key at this
          // point results from a `dhOutput` (Bob's fresh, random ratchet private key × Alice's
          // ratchet public key) that the attacker cannot compute WITHOUT Bob's actual session
          // state/ratchet private key — their naively fast-forwarded HMAC chain key is, from here
          // on, a different one than the one actually used. The AEAD check therefore necessarily
          // fails.
          expect(() =>
            xchacha20poly1305(
              messageKey,
              hexToBytes(envelope.nonce),
              sequenceNumberBytes,
            ).decrypt(hexToBytes(envelope.ciphertext)),
          ).toThrow();
        }

        attackerChainKey = nextChainKey;
      }

      // Explicit statement for case A only — no blanket "forward secrecy: yes/no".
      // eslint-disable-next-line no-console
      console.log(
        `Case A (long-term key compromised): messages 0..${
          rotationIndex - 1
        }: exposed by the compromise of the long-term key (index ${rotationIndex} = first real rotation). Messages ${rotationIndex}..${
          recorded.length - 1
        }: protected by the rotation step.`,
      );
    });
  });

  describe('recentlyConsumedKeys: no fallback into the regular processing path', () => {
    // A sharper property than "a repeat is accepted" (already tested above, "confirms an exact
    // repeat ..."): here the point is that an already SUCCESSFULLY processed sequence number is
    // NEVER wrongly treated again as if it were a NEW message (i.e. never ends up in the branch
    // `envelope.sequenceNumber !== 0 && sequenceNumber === session.receiveCounter` below in
    // decryptMessage, which derives freshly from the running chain) — no matter through which
    // combination of consume→ratchet→restart→retry→reorder.

    it('message 2 (in the window) is processed via the duplicate branch on redelivery, receiveCounter stays unchanged', async () => {
      const alice = keypair();
      const bob = keypair();
      const aliceSigning = await signingKeypair();
      let aliceSession = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      let bobSession = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );

      const envelopes: OutgoingEnvelope[] = [];
      for (let i = 0; i < 5; i++) {
        const {envelope, nextSession} = await encryptMessage(
          aliceSession,
          `nachricht-${i}`,
          aliceSigning.privateKey,
        );
        aliceSession = nextSession;
        envelopes.push(envelope);
        const result = await decryptMessage(
          bobSession,
          envelope,
          aliceSigning.publicKey,
        );
        bobSession = result.nextSession;
        expect(result.duplicate).toBe(false);
      }
      expect(bobSession.receiveCounter).toBe(5);

      const bobSessionBeforeRedelivery = bobSession;
      const repeated = await decryptMessage(
        bobSession,
        envelopes[2],
        aliceSigning.publicKey,
      );
      // duplicate branch, NOT the regular path — the regular path would throw
      // `ReplayOrOutOfOrderError(expected 5, received 2)` here (2 !== receiveCounter).
      expect(repeated.duplicate).toBe(true);
      expect(repeated.plaintext).toBe('nachricht-2');
      expect(repeated.nextSession.receiveCounter).toBe(5);
      // "nextSession === session"-style comparison: in the duplicate branch, decryptMessage
      // returns exactly the same reference according to session.ts (`nextSession: session`) —
      // checked here via JSON.stringify equality (robust also against a future, non-referential
      // but content-identical implementation).
      expect(JSON.stringify(repeated.nextSession)).toBe(
        JSON.stringify(bobSessionBeforeRedelivery),
      );
    });

    it('tampering attempt: message 2 with a modified ciphertext (same sequence number/nonce) is rejected, no silent acceptance', async () => {
      const alice = keypair();
      const bob = keypair();
      const aliceSigning = await signingKeypair();
      let aliceSession = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      let bobSession = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );

      const envelopes: OutgoingEnvelope[] = [];
      for (let i = 0; i < 5; i++) {
        const {envelope, nextSession} = await encryptMessage(
          aliceSession,
          `nachricht-${i}`,
          aliceSigning.privateKey,
        );
        aliceSession = nextSession;
        envelopes.push(envelope);
        const result = await decryptMessage(
          bobSession,
          envelope,
          aliceSigning.publicKey,
        );
        bobSession = result.nextSession;
      }

      const tampered: OutgoingEnvelope = {
        ...envelopes[2],
        ciphertext:
          envelopes[2].ciphertext.slice(0, -1) +
          (envelopes[2].ciphertext.slice(-1) === '0' ? '1' : '0'),
      };

      const beforeState = JSON.stringify(bobSession);
      await expect(
        decryptMessage(bobSession, tampered, aliceSigning.publicKey),
      ).rejects.toThrow(ReplayOrOutOfOrderError);
      // Negative-state preservation: a rejected tampering attempt must not change the receiver's
      // session.
      expect(JSON.stringify(bobSession)).toBe(beforeState);
    });

    it('documents the ACTUAL window behavior at the window boundary (MAX_RECENTLY_CONSUMED_KEYS entries, sliding window)', async () => {
      const alice = keypair();
      const bob = keypair();
      const aliceSigning = await signingKeypair();
      let aliceSession = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      let bobSession = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );

      const envelopes: OutgoingEnvelope[] = [];
      // Exactly MAX_RECENTLY_CONSUMED_KEYS (10) messages — the window size filled exactly.
      for (let i = 0; i < MAX_RECENTLY_CONSUMED_KEYS; i++) {
        const {envelope, nextSession} = await encryptMessage(
          aliceSession,
          `fenster-${i}`,
          aliceSigning.privateKey,
        );
        aliceSession = nextSession;
        envelopes.push(envelope);
        const result = await decryptMessage(
          bobSession,
          envelope,
          aliceSigning.publicKey,
        );
        bobSession = result.nextSession;
      }
      expect(bobSession.receiveCounter).toBe(MAX_RECENTLY_CONSUMED_KEYS);

      // ACTUAL behavior (by construction of `.slice(-MAX_RECENTLY_CONSUMED_KEYS)` in session.ts,
      // traced directly instead of guessed): after EXACTLY 10 consecutive insertions into an empty
      // array, the window contains exactly all 10 sequence numbers 0..9 — message 0 (the OLDEST)
      // has therefore NOT yet fallen out.
      const message0Redelivery = await decryptMessage(
        bobSession,
        envelopes[0],
        aliceSigning.publicKey,
      );
      expect(message0Redelivery.duplicate).toBe(true);
      expect(message0Redelivery.plaintext).toBe('fenster-0');

      // A plain (unchanged) repeat adds NO new entry according to session.ts (the duplicate
      // branch returns `nextSession: session` unchanged) — the window stays exactly {0..9}.
      bobSession = message0Redelivery.nextSession;

      // Process message 10 (the 11th) normally — according to the sliding window (FIFO,
      // `.slice(-10)`) this pushes out EXACTLY the oldest entry, i.e. sequence number 0. The window
      // afterwards is {1..10}.
      const eleventh = await encryptMessage(
        aliceSession,
        'fenster-10',
        aliceSigning.privateKey,
      );
      aliceSession = eleventh.nextSession;
      const eleventhResult = await decryptMessage(
        bobSession,
        eleventh.envelope,
        aliceSigning.publicKey,
      );
      bobSession = eleventhResult.nextSession;
      expect(bobSession.receiveCounter).toBe(MAX_RECENTLY_CONSUMED_KEYS + 1);

      // Message 0 has now GUARANTEEDLY fallen out of the window (the window is {1..10}, see
      // above) — redelivery must be finally rejected as a replay.
      await expect(
        decryptMessage(bobSession, envelopes[0], aliceSigning.publicKey),
      ).rejects.toThrow(ReplayOrOutOfOrderError);

      // Message 1, on the other hand, is by the same derivation ({1..10}) still IN the window (it
      // is now the oldest entry, but still present) — so it is still confirmed as a duplicate, NOT
      // rejected. Important for documenting the actual semantics: "fell out of the window" applies,
      // after processing the 11th message, to EXACTLY ONE entry (the oldest at that point in time,
      // here message 0), not already to the second oldest (message 1).
      const message1Redelivery = await decryptMessage(
        bobSession,
        envelopes[1],
        aliceSigning.publicKey,
      );
      expect(message1Redelivery.duplicate).toBe(true);
      expect(message1Redelivery.plaintext).toBe('fenster-1');
    });

    it('no fallback into the regular processing path: a NEWLY encrypted message under an already processed, cached sequence number is checked against the CACHED (not the freshly derived) key and rejected', async () => {
      // Core scenario: an attacker (or a faulty client) tries to inject a MANIPULATED "new" message
      // under an old sequence number that is already in the recentlyConsumedKeys cache. Because
      // the sequence number is < receiveCounter, ONLY the duplicate branch applies from the outset
      // (cache check against the historically cached message key) — the regular path (which would
      // derive a NEW message key from the current chain state and accept the message as "new") is
      // NEVER reached, regardless of with which (possibly even real, freshly derived) key the
      // injected message was actually encrypted.
      const alice = keypair();
      const bob = keypair();
      const aliceSigning = await signingKeypair();
      let aliceSession = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      let bobSession = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );

      // Messages 0..4 normally — bobSession.receiveCounter === 5 afterwards, message 2 lies in the
      // recentlyConsumedKeys cache. Bob deliberately NEVER replies (no DH ratchet step on Alice's
      // send side) — keeps the build-up of the running chain simple and clearly traceable.
      for (let i = 0; i < 5; i++) {
        const {envelope, nextSession} = await encryptMessage(
          aliceSession,
          `nachricht-${i}`,
          aliceSigning.privateKey,
        );
        aliceSession = nextSession;
        const result = await decryptMessage(
          bobSession,
          envelope,
          aliceSigning.publicKey,
        );
        bobSession = result.nextSession;
      }
      expect(bobSession.receiveCounter).toBe(5);
      expect(
        bobSession.recentlyConsumedKeys?.some(k => k.sequenceNumber === 2),
      ).toBe(true);

      // Simulates the injection: a NEWLY encrypted message whose sendCounter was MANUALLY reset to
      // 2 — it thus carries sequenceNumber===2 to the outside, but was actually encrypted with the
      // CHAIN STATE AFTER message 4 (Alice's send side is by now five HMAC steps further than the
      // historical state of message 2) — a GENUINELY DIFFERENT, real message key than the
      // historically cached one.
      const forgedSourceSession: Session = {...aliceSession, sendCounter: 2};
      const {envelope: injectedEnvelope} = await encryptMessage(
        forgedSourceSession,
        'eingeschleuste nachricht unter alter sequenznummer',
        aliceSigning.privateKey,
      );
      expect(injectedEnvelope.sequenceNumber).toBe(2);

      const beforeState = JSON.stringify(bobSession);
      // The cache check applies (2 < 5): AEAD decryption against the CACHED message key of message
      // 2 — not against the key actually used (the new one) — necessarily fails. The regular "new
      // message" path is NEVER reached, the injected message is NOT wrongly accepted as a new
      // sequence number 2.
      await expect(
        decryptMessage(bobSession, injectedEnvelope, aliceSigning.publicKey),
      ).rejects.toThrow(ReplayOrOutOfOrderError);
      expect(JSON.stringify(bobSession)).toBe(beforeState);
    });

    it('malicious-but-valid peer: 1000 consecutive, protocol-conformant messages do NOT let recentlyConsumedKeys grow unboundedly', async () => {
      // Threat model: an already authenticated but malicious contact can send arbitrarily many
      // FORMALLY valid messages (no protocol violation needed) — is that enough to make an array
      // that has so far only been checked at the window boundary (see the test above, exactly
      // 10/11 messages) grow unboundedly after all, unnoticed? Proven directly instead of merely
      // asserted: process 1000 messages, then check the ACTUAL array length.
      const alice = keypair();
      const bob = keypair();
      const aliceSigning = await signingKeypair();
      let aliceSession = createSession(
        alice.privateKey,
        alice.publicKey,
        bob.publicKey,
      );
      let bobSession = createSession(
        bob.privateKey,
        bob.publicKey,
        alice.publicKey,
      );

      const MESSAGE_COUNT = 1000;
      for (let i = 0; i < MESSAGE_COUNT; i++) {
        const {envelope, nextSession} = await encryptMessage(
          aliceSession,
          `bulk-${i}`,
          aliceSigning.privateKey,
        );
        aliceSession = nextSession;
        const result = await decryptMessage(
          bobSession,
          envelope,
          aliceSigning.publicKey,
        );
        bobSession = result.nextSession;
      }

      expect(bobSession.receiveCounter).toBe(MESSAGE_COUNT);
      // The actual proof: NOT only "smaller than before", but concretely within the documented
      // upper bound — `.slice(-MAX_RECENTLY_CONSUMED_KEYS)` in session.ts must trim the array on
      // EVERY single insertion, not only at the end.
      expect(bobSession.recentlyConsumedKeys).toBeDefined();
      expect(bobSession.recentlyConsumedKeys!.length).toBeLessThanOrEqual(
        MAX_RECENTLY_CONSUMED_KEYS,
      );
      expect(bobSession.recentlyConsumedKeys!.length).toBe(
        MAX_RECENTLY_CONSUMED_KEYS,
      );
      // Contains exclusively the most recently used sequence numbers (sliding window) — the
      // oldest 990 have long since fallen out, not just "somehow bounded".
      const cachedSequenceNumbers = bobSession
        .recentlyConsumedKeys!.map(k => k.sequenceNumber)
        .sort((a, b) => a - b);
      expect(cachedSequenceNumbers).toEqual([
        990, 991, 992, 993, 994, 995, 996, 997, 998, 999,
      ]);
    });
  });
});
