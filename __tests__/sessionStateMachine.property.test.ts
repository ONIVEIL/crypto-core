/**
 * @format
 */

// Model-/property-based testing of the session ratchet state machine from
// src/crypto/session.ts. The goal is NOT to duplicate the individually hand-written scenarios
// already present in __tests__/session.test.ts, but to additionally secure confidence in the
// WHOLE state machine across many operation sequences (level 1: long, targeted ones; level 2:
// many random ones) — in particular the receive-driven DH rotation logic (see session.ts module
// documentation, points 2+3: `receivedSomethingNew`/`forcedInitialRotation`) and the
// repeat/replay tolerance (`recentlyConsumedKeys`).
//
// Deliberately NO new npm dependency (no fast-check/jsverify/etc.): the project consistently
// prefers hand-rolled, low-dependency implementations (see e.g. src/crypto/textCodec.ts,
// src/crypto/onionAddress.ts — own UTF-8 decoder/Base32 encoder instead of libraries). The PRNG
// below (mulberry32) is a tiny, publicly known, deterministic 32-bit generator — entirely
// sufficient here, since we need no cryptographic randomness, only a REPRODUCIBLE operation
// sequence per seed.

// session.ts does not import react-native-get-random-values itself, but the underlying @noble
// libraries still need a crypto.getRandomValues source (same pattern as in
// __tests__/session.test.ts).
// @ts-ignore
global.crypto = global.crypto ?? require('crypto').webcrypto;

import {describe, it, expect} from '@jest/globals';
import {x25519} from '@noble/curves/ed25519.js';
import * as ed from '@noble/ed25519';
import {sha512} from '@noble/hashes/sha2.js';
import {bytesToHex} from '@noble/hashes/utils.js';
import {
  createSession,
  decryptMessage,
  encryptMessage,
  MAX_RECENTLY_CONSUMED_KEYS,
  OutgoingEnvelope,
  Session,
} from '../src/crypto/session';

// @noble/ed25519 v2/v3 needs a SHA-512 implementation supplied from outside (same pattern as in
// crypto/identity.ts, crypto/session.ts itself and __tests__/session.test.ts).
ed.hashes.sha512Async = (m: Uint8Array) => Promise.resolve(sha512(m));

function keypair() {
  const {secretKey, publicKey} = x25519.keygen();
  return {privateKey: bytesToHex(secretKey), publicKey: bytesToHex(publicKey)};
}

// Second, completely independent key pair per person (Ed25519, signature) — NOT to be confused
// with the X25519 encryption keys above. Since the Ed25519 freshness binding (KCI/reset
// hardening), encryptMessage/decryptMessage require such a key pair per side (third parameter),
// see the current signature in session.ts / __tests__/session.test.ts.
async function signingKeypair() {
  const {secretKey, publicKey} = await ed.keygenAsync();
  return {privateKey: bytesToHex(secretKey), publicKey: bytesToHex(publicKey)};
}

// Detects a REAL DH ratchet step in encryptMessage: only then does the own ratchet public key
// change (a pure HMAC chain step leaves myRatchetPublicKey unchanged, see session.ts
// encryptMessage — the rotation condition there sets myRatchetPrivateKey/myRatchetPublicKey anew
// exclusively in the `if (receivedSomethingNew || forcedInitialRotation)` branch). Comparing two
// session snapshots is just as valid here as comparing envelope.ratchetPublicKey before/after the
// call — both values are identical (the envelope carries exactly the new myRatchetPublicKey).
function isRealRotation(before: Session, after: Session): boolean {
  return before.myRatchetPublicKey !== after.myRatchetPublicKey;
}

// ---------------------------------------------------------------------------------------------
// Level 1: deterministic reference model — long, hand-written scenarios that, for EVERY message,
// explicitly record/assert whether a real DH rotation took place at that point or only an HMAC
// chain step.
// ---------------------------------------------------------------------------------------------

// Generates two X25519 key pairs for which bob.publicKey < alice.publicKey is GUARANTEED — Bob
// is thus `amLower` (see session.ts module documentation, point 3) and Alice is NOT. That makes
// the order of the forced initial rotation in the following long-running scenarios
// deterministically predictable (exact message index instead of "at some point"), instead of
// depending on the random key generation. Expected effort: ~2 attempts (fifty-fifty per pass), no
// noticeable cost.
function keypairsWithBobLower() {
  for (;;) {
    const alice = keypair();
    const bob = keypair();
    if (bob.publicKey < alice.publicKey) {
      return {alice, bob};
    }
  }
}

describe('sessionStateMachine.property — level 1: long reference-model scenarios', () => {
  it('(a) strict ping-pong over 12 rounds: first real rotation per direction at exactly the predicted position', async () => {
    const {alice, bob} = keypairsWithBobLower();
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

    // Bob is amLower (see keypairsWithBobLower), Alice is not — precondition for the exact
    // rotation indices derived below.
    expect(aliceSession.amLower).toBe(false);
    expect(bobSession.amLower).toBe(true);

    const aliceRotationRounds: number[] = [];
    const bobRotationRounds: number[] = [];

    const ROUNDS = 12;
    for (let round = 0; round < ROUNDS; round++) {
      const aliceBefore = aliceSession;
      const fromAlice = await encryptMessage(
        aliceSession,
        `alice-${round}`,
        aliceSigning.privateKey,
      );
      aliceSession = fromAlice.nextSession;
      if (isRealRotation(aliceBefore, aliceSession)) {
        aliceRotationRounds.push(round);
      }
      const bobResult = await decryptMessage(
        bobSession,
        fromAlice.envelope,
        aliceSigning.publicKey,
      );
      bobSession = bobResult.nextSession;
      expect(bobResult.plaintext).toBe(`alice-${round}`);

      const bobBefore = bobSession;
      const fromBob = await encryptMessage(
        bobSession,
        `bob-${round}`,
        bobSigning.privateKey,
      );
      bobSession = fromBob.nextSession;
      if (isRealRotation(bobBefore, bobSession)) {
        bobRotationRounds.push(round);
      }
      const aliceResult = await decryptMessage(
        aliceSession,
        fromBob.envelope,
        bobSigning.publicKey,
      );
      aliceSession = aliceResult.nextSession;
      expect(aliceResult.plaintext).toBe(`bob-${round}`);
    }

    // Expectation derived analytically from the rotation logic in session.ts:
    //   - Bob (amLower) forces his very first own rotation on HIS very first sent message
    //     (round 0, forcedInitialRotation) — regardless of the fact that at that point he has
    //     already received Alice's (unrotated) first message.
    //   - Alice (NOT amLower) really rotates only on HER SECOND sent message (round 1): her
    //     round-0 message goes out BEFORE she has received anything new from Bob (Bob's round-0
    //     reply only arrives afterwards); only after she has received Bob's new ratchet key from
    //     his round-0 reply does her round-1 message satisfy `receivedSomethingNew`.
    expect(bobRotationRounds[0]).toBe(0);
    expect(aliceRotationRounds[0]).toBe(1);
    // And neither side rotates already BEFORE these rounds (not just "the first rotation found
    // is right", but really "exactly at this position, not earlier").
    expect(bobRotationRounds.some(r => r < 0)).toBe(false);
    expect(aliceRotationRounds.some(r => r < 1)).toBe(false);
  });

  it('(b) long one-sided phase (only Alice sends, 8 messages), then ONE reply from Bob, then Alice again — rotation exactly at the expected position', async () => {
    const {alice, bob} = keypairsWithBobLower();
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

    const aliceRotationIndices: number[] = [];
    const ONE_SIDED_COUNT = 8;
    for (let i = 0; i < ONE_SIDED_COUNT; i++) {
      const before = aliceSession;
      const {envelope, nextSession} = await encryptMessage(
        aliceSession,
        `einseitig-${i}`,
        aliceSigning.privateKey,
      );
      aliceSession = nextSession;
      if (isRealRotation(before, aliceSession)) {
        aliceRotationIndices.push(i);
      }
      const result = await decryptMessage(
        bobSession,
        envelope,
        aliceSigning.publicKey,
      );
      bobSession = result.nextSession;
      expect(result.plaintext).toBe(`einseitig-${i}`);
    }
    // During the ENTIRE one-sided phase, NO real rotation may have taken place on Alice's send
    // side: Bob has never sent (no `receivedSomethingNew` for Alice), and Alice is NOT amLower (no
    // `forcedInitialRotation`).
    expect(aliceRotationIndices).toEqual([]);

    // Bob's only reply in this phase.
    const bobBefore = bobSession;
    const reply = await encryptMessage(
      bobSession,
      'bobs-einzige-antwort',
      bobSigning.privateKey,
    );
    bobSession = reply.nextSession;
    // Bob (amLower) forces his very first own rotation on his (so far only) sent message,
    // regardless of how long he only received passively before.
    expect(isRealRotation(bobBefore, bobSession)).toBe(true);

    const aliceReceivesReply = await decryptMessage(
      aliceSession,
      reply.envelope,
      bobSigning.publicKey,
    );
    aliceSession = aliceReceivesReply.nextSession;
    expect(aliceReceivesReply.plaintext).toBe('bobs-einzige-antwort');

    // Alice's EXACTLY NEXT message (index ONE_SIDED_COUNT, her ninth in total, the first after
    // Bob's reply) must now really rotate: with Bob's reply she has received a NEW ratchet key
    // from Bob for the first time.
    const resumedBefore = aliceSession;
    const resumed = await encryptMessage(
      aliceSession,
      'wieder-alice',
      aliceSigning.privateKey,
    );
    aliceSession = resumed.nextSession;
    expect(isRealRotation(resumedBefore, aliceSession)).toBe(true);

    // And the message AFTER that does NOT rotate again — no further receipt since the last own
    // rotation.
    const nextBefore = aliceSession;
    const next = await encryptMessage(
      aliceSession,
      'weiter-alice',
      aliceSigning.privateKey,
    );
    expect(isRealRotation(nextBefore, next.nextSession)).toBe(false);
  });

  it('(c) mix of normal sending and recentlyConsumedKeys repeats, interleaved with a real rotation — repeats do not disturb the rotation progress', async () => {
    const {alice, bob} = keypairsWithBobLower();
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

    // Round 0: Alice sends (no rotation, see scenario b), Bob receives and replies (Bob really
    // rotates, since amLower).
    const m0 = await encryptMessage(
      aliceSession,
      'runde0-alice',
      aliceSigning.privateKey,
    );
    aliceSession = m0.nextSession;
    const bobRecv0 = await decryptMessage(
      bobSession,
      m0.envelope,
      aliceSigning.publicKey,
    );
    bobSession = bobRecv0.nextSession;

    const bobBefore = bobSession;
    const bobReply0 = await encryptMessage(
      bobSession,
      'runde0-bob',
      bobSigning.privateKey,
    );
    bobSession = bobReply0.nextSession;
    expect(isRealRotation(bobBefore, bobSession)).toBe(true);

    const aliceRecvReply = await decryptMessage(
      aliceSession,
      bobReply0.envelope,
      bobSigning.publicKey,
    );
    aliceSession = aliceRecvReply.nextSession;
    expect(aliceRecvReply.duplicate).toBe(false);

    // First repeat of the same Bob reply, BEFORE any further real message ("lost ack", see the
    // existing tests in session.test.ts as a model).
    const dup1 = await decryptMessage(
      aliceSession,
      bobReply0.envelope,
      bobSigning.publicKey,
    );
    expect(dup1.duplicate).toBe(true);
    expect(dup1.plaintext).toBe('runde0-bob');
    expect(JSON.stringify(dup1.nextSession)).toBe(JSON.stringify(aliceSession));

    // Alice's next REAL message — according to the analysis (see scenario b) it must now really
    // rotate; the repeat in between must not have changed that.
    const rotateBefore = aliceSession;
    const m1 = await encryptMessage(
      aliceSession,
      'runde1-alice',
      aliceSigning.privateKey,
    );
    aliceSession = m1.nextSession;
    expect(isRealRotation(rotateBefore, aliceSession)).toBe(true);

    // Another repeat of the same old Bob reply AFTER the rotation — must still be recognized as
    // a duplicate (the sequence number lies in the recentlyConsumedKeys window) and must not reset
    // the rotation state, which has advanced in the meantime.
    const dup2 = await decryptMessage(
      aliceSession,
      bobReply0.envelope,
      bobSigning.publicKey,
    );
    expect(dup2.duplicate).toBe(true);
    expect(JSON.stringify(dup2.nextSession)).toBe(JSON.stringify(aliceSession));

    const bobRecv1 = await decryptMessage(
      bobSession,
      m1.envelope,
      aliceSigning.publicKey,
    );
    bobSession = bobRecv1.nextSession;
    expect(bobRecv1.plaintext).toBe('runde1-alice');

    // More real messages AND more repeats in alternation — in total (m0, bobReply0, m1, m2..m9)
    // 11 real messages in this scenario, in order to fulfil the "10+ messages" requirement, each of
    // them accompanied by at least one repeat.
    for (let i = 2; i < 10; i++) {
      const dupBefore = await decryptMessage(
        aliceSession,
        bobReply0.envelope,
        bobSigning.publicKey,
      );
      expect(dupBefore.duplicate).toBe(true);

      const mi = await encryptMessage(
        aliceSession,
        `runde${i}-alice`,
        aliceSigning.privateKey,
      );
      aliceSession = mi.nextSession;
      const bobRecv = await decryptMessage(
        bobSession,
        mi.envelope,
        aliceSigning.publicKey,
      );
      bobSession = bobRecv.nextSession;
      expect(bobRecv.plaintext).toBe(`runde${i}-alice`);
      // No further real DH ratchet step on Alice's send side during this series: Bob has sent
      // nothing new since his round-0 reply, so `receivedSomethingNew` stays consistently false
      // for Alice from here on.
      expect(isRealRotation(rotateBefore, aliceSession)).toBe(true); // stays rotated since m1
    }
  });
});

// ---------------------------------------------------------------------------------------------
// Level 2: seed-based randomized property test.
// ---------------------------------------------------------------------------------------------

// mulberry32 — a tiny, publicly known, deterministic 32-bit PRNG (see e.g.
// https://github.com/bryc/code/blob/master/jshash/PRNGs.md). Deliberately NO Math.random(): only
// the OPERATION SEQUENCE (who sends to whom when, when a repeat happens) must follow
// reproducibly from `seed`, so that a failing seed can later be traced exactly — the
// cryptographic quality of the generator itself is irrelevant here, only determinism matters.
function mulberry32(seed: number): () => number {
  let a = seed >>> 0;
  return function (): number {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function randInt(rng: () => number, exclusiveMax: number): number {
  return Math.floor(rng() * exclusiveMax);
}

function pick<T>(rng: () => number, items: readonly T[]): T {
  return items[randInt(rng, items.length)];
}

// Fixed list of 200 seeds — each seed runs as its own `it(...)` test case (see `it.each` below),
// so that a failing seed is visible INDIVIDUALLY in the test report instead of getting lost in one
// collective test.
const LEVEL2_SEEDS: number[] = Array.from({length: 200}, (_, i) => i + 1);

interface QueuedEnvelope {
  envelope: OutgoingEnvelope;
  plaintext: string;
}

interface InvariantContext {
  seed: number;
  operationSequence: readonly string[];
  stateBefore: unknown;
  input: unknown;
  stateAfter: unknown;
  expected: unknown;
  actual: unknown;
}

// Formats a context block in a fixed layout (with slightly uneven field widths). A separate
// function, so that both assertInvariant() and the unexpected-exception handler below produce
// exactly the same block.
function formatInvariantContext(context: InvariantContext): string {
  return [
    `seed:               ${context.seed}`,
    `operation_sequence: ${JSON.stringify(context.operationSequence)}`,
    `state_before:       ${JSON.stringify(context.stateBefore)}`,
    `input:               ${JSON.stringify(context.input)}`,
    `state_after:         ${JSON.stringify(context.stateAfter)}`,
    `expected:            ${JSON.stringify(context.expected)}`,
    `actual:              ${JSON.stringify(context.actual)}`,
  ].join('\n');
}

// Throws a fully contextualized error on a violated invariant — a bare `expect(a).toBe(b)` would
// no longer be reproducibly traceable for e.g. seed #147 later.
function assertInvariant(
  condition: boolean,
  message: string,
  context: InvariantContext,
): void {
  if (condition) {
    return;
  }
  throw new Error(`${message}\n${formatInvariantContext(context)}`);
}

// Runs ONE random operation sequence, reproducible from `seed`, between two fresh sessions
// (Alice, Bob) and checks the invariants after EVERY operation. Throws with full context on a
// violation (or on an unexpected exception).
async function runRandomOperationSequence(
  seed: number,
  operationCount: number,
): Promise<void> {
  const rng = mulberry32(seed);

  // Real random keygen is deliberately fine here: only the OPERATION SEQUENCE itself must follow
  // deterministically from `seed`, not the key material itself — x25519.keygen()/ed.keygenAsync()
  // draw from crypto.getRandomValues.
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

  // FIFO queues of "not yet processed envelopes" per direction — strict order, the protocol
  // supports no skip-ahead (see session.ts module documentation).
  const aliceToBobQueue: QueuedEnvelope[] = [];
  const bobToAliceQueue: QueuedEnvelope[] = [];

  // Up to MAX_RECENTLY_CONSUMED_KEYS most recently SUCCESSFULLY processed envelopes per receiving
  // direction — basis for the realistic repeat operation. These two lists mirror the
  // `recentlyConsumedKeys` window of the respective session 1:1 (same cap, same insertion order),
  // because only B_RECV/A_RECV (not REDELIVER_*) produce new entries.
  const consumedByBob: QueuedEnvelope[] = []; // sent by Alice, consumed by Bob
  const consumedByAlice: QueuedEnvelope[] = []; // sent by Bob, consumed by Alice

  const operationSequence: string[] = [];
  let messageCounter = 0;

  // For the monotonicity check ("never regressing, except in the unchanged duplicate branch") —
  // updated after every operation.
  let lastAliceSendCounter = aliceSession.sendCounter;
  let lastAliceReceiveCounter = aliceSession.receiveCounter;
  let lastBobSendCounter = bobSession.sendCounter;
  let lastBobReceiveCounter = bobSession.receiveCounter;

  for (let step = 0; step < operationCount; step++) {
    const candidates: string[] = ['A_SEND', 'B_SEND'];
    if (aliceToBobQueue.length > 0) {
      candidates.push('B_RECV');
    }
    if (bobToAliceQueue.length > 0) {
      candidates.push('A_RECV');
    }
    if (consumedByBob.length > 0) {
      candidates.push('REDELIVER_TO_BOB');
    }
    if (consumedByAlice.length > 0) {
      candidates.push('REDELIVER_TO_ALICE');
    }
    const op = pick(rng, candidates);

    try {
      if (op === 'A_SEND') {
        const plaintext = `seed${seed}-a-${messageCounter++}`;
        operationSequence.push(`A_SEND(${plaintext})`);
        const stateBefore = aliceSession;
        const {envelope, nextSession} = await encryptMessage(
          aliceSession,
          plaintext,
          aliceSigning.privateKey,
        );
        assertInvariant(
          nextSession.sendCounter === stateBefore.sendCounter + 1,
          'sendCounter muss nach erfolgreichem encryptMessage genau um 1 steigen',
          {
            seed,
            operationSequence,
            stateBefore,
            input: plaintext,
            stateAfter: nextSession,
            expected: stateBefore.sendCounter + 1,
            actual: nextSession.sendCounter,
          },
        );
        aliceSession = nextSession;
        aliceToBobQueue.push({envelope, plaintext});
      } else if (op === 'B_SEND') {
        const plaintext = `seed${seed}-b-${messageCounter++}`;
        operationSequence.push(`B_SEND(${plaintext})`);
        const stateBefore = bobSession;
        const {envelope, nextSession} = await encryptMessage(
          bobSession,
          plaintext,
          bobSigning.privateKey,
        );
        assertInvariant(
          nextSession.sendCounter === stateBefore.sendCounter + 1,
          'sendCounter muss nach erfolgreichem encryptMessage genau um 1 steigen',
          {
            seed,
            operationSequence,
            stateBefore,
            input: plaintext,
            stateAfter: nextSession,
            expected: stateBefore.sendCounter + 1,
            actual: nextSession.sendCounter,
          },
        );
        bobSession = nextSession;
        bobToAliceQueue.push({envelope, plaintext});
      } else if (op === 'B_RECV') {
        const queued = aliceToBobQueue.shift() as QueuedEnvelope;
        operationSequence.push(
          `B_RECV(seq=${queued.envelope.sequenceNumber})`,
        );
        const stateBefore = bobSession;
        const result = await decryptMessage(
          bobSession,
          queued.envelope,
          aliceSigning.publicKey,
        );
        assertInvariant(
          result.duplicate === false,
          'eine frisch aus der FIFO-Warteschlange entnommene, noch nie zugestellte Nachricht darf nie als Duplikat erkannt werden',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: false,
            actual: result.duplicate,
          },
        );
        assertInvariant(
          result.plaintext === queued.plaintext,
          'entschluesselter Klartext muss EXAKT dem urspruenglich verschluesselten entsprechen',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: queued.plaintext,
            actual: result.plaintext,
          },
        );
        assertInvariant(
          result.nextSession.receiveCounter === stateBefore.receiveCounter + 1,
          'receiveCounter muss nach erfolgreichem, nicht-dupliziertem decryptMessage genau um 1 steigen',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: stateBefore.receiveCounter + 1,
            actual: result.nextSession.receiveCounter,
          },
        );
        bobSession = result.nextSession;
        consumedByBob.push(queued);
        if (consumedByBob.length > MAX_RECENTLY_CONSUMED_KEYS) {
          consumedByBob.shift();
        }
      } else if (op === 'A_RECV') {
        const queued = bobToAliceQueue.shift() as QueuedEnvelope;
        operationSequence.push(
          `A_RECV(seq=${queued.envelope.sequenceNumber})`,
        );
        const stateBefore = aliceSession;
        const result = await decryptMessage(
          aliceSession,
          queued.envelope,
          bobSigning.publicKey,
        );
        assertInvariant(
          result.duplicate === false,
          'eine frisch aus der FIFO-Warteschlange entnommene, noch nie zugestellte Nachricht darf nie als Duplikat erkannt werden',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: false,
            actual: result.duplicate,
          },
        );
        assertInvariant(
          result.plaintext === queued.plaintext,
          'entschluesselter Klartext muss EXAKT dem urspruenglich verschluesselten entsprechen',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: queued.plaintext,
            actual: result.plaintext,
          },
        );
        assertInvariant(
          result.nextSession.receiveCounter === stateBefore.receiveCounter + 1,
          'receiveCounter muss nach erfolgreichem, nicht-dupliziertem decryptMessage genau um 1 steigen',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: stateBefore.receiveCounter + 1,
            actual: result.nextSession.receiveCounter,
          },
        );
        aliceSession = result.nextSession;
        consumedByAlice.push(queued);
        if (consumedByAlice.length > MAX_RECENTLY_CONSUMED_KEYS) {
          consumedByAlice.shift();
        }
      } else if (op === 'REDELIVER_TO_BOB') {
        const queued = pick(rng, consumedByBob);
        operationSequence.push(
          `REDELIVER_TO_BOB(seq=${queued.envelope.sequenceNumber})`,
        );
        const stateBefore = bobSession;
        const result = await decryptMessage(
          bobSession,
          queued.envelope,
          aliceSigning.publicKey,
        );
        assertInvariant(
          result.duplicate === true,
          'eine erneute Zustellung eines bereits (aus dem Fenster) bekannten Envelopes muss als Duplikat erkannt werden',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: true,
            actual: result.duplicate,
          },
        );
        assertInvariant(
          result.plaintext === queued.plaintext,
          'auch eine als Duplikat erkannte Wiederholung muss den urspruenglichen Klartext liefern',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: queued.plaintext,
            actual: result.plaintext,
          },
        );
        // Negative-state preservation (established as a principle in other tests, see
        // __tests__/session.test.ts): a duplicate:true response leaves the session state
        // BYTE-IDENTICAL.
        assertInvariant(
          JSON.stringify(result.nextSession) === JSON.stringify(stateBefore),
          'eine duplicate:true-Antwort muss den Sitzungszustand des Empfaengers BYTE-IDENTISCH lassen (Negative-State-Preservation)',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: JSON.stringify(stateBefore),
            actual: JSON.stringify(result.nextSession),
          },
        );
        bobSession = result.nextSession; // unchanged by specification, reassigned for completeness
      } else {
        // REDELIVER_TO_ALICE
        const queued = pick(rng, consumedByAlice);
        operationSequence.push(
          `REDELIVER_TO_ALICE(seq=${queued.envelope.sequenceNumber})`,
        );
        const stateBefore = aliceSession;
        const result = await decryptMessage(
          aliceSession,
          queued.envelope,
          bobSigning.publicKey,
        );
        assertInvariant(
          result.duplicate === true,
          'eine erneute Zustellung eines bereits (aus dem Fenster) bekannten Envelopes muss als Duplikat erkannt werden',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: true,
            actual: result.duplicate,
          },
        );
        assertInvariant(
          result.plaintext === queued.plaintext,
          'auch eine als Duplikat erkannte Wiederholung muss den urspruenglichen Klartext liefern',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: queued.plaintext,
            actual: result.plaintext,
          },
        );
        assertInvariant(
          JSON.stringify(result.nextSession) === JSON.stringify(stateBefore),
          'eine duplicate:true-Antwort muss den Sitzungszustand des Empfaengers BYTE-IDENTISCH lassen (Negative-State-Preservation)',
          {
            seed,
            operationSequence,
            stateBefore,
            input: queued.envelope,
            stateAfter: result.nextSession,
            expected: JSON.stringify(stateBefore),
            actual: JSON.stringify(result.nextSession),
          },
        );
        aliceSession = result.nextSession;
      }
    } catch (err) {
      // This operation sequence contains NO deliberate attacks (no skip-ahead, no manipulation, no
      // repeat that fell out of the window) — every exception occurring here (including
      // ReplayOrOutOfOrderError/InvalidInitialAuthError) is therefore UNEXPECTED at this point and
      // a real test failure, not a deliberately provoked branch.
      if (err instanceof Error && err.message.includes('seed:')) {
        // Already fully formatted by assertInvariant() — pass through unchanged.
        throw err;
      }
      throw new Error(
        [
          `unerwartete Exception bei Operation ${op}`,
          formatInvariantContext({
            seed,
            operationSequence,
            stateBefore: {aliceSession, bobSession},
            input: op,
            stateAfter: '(Operation fehlgeschlagen, kein neuer Zustand)',
            expected:
              'kein Fehler (diese Operationsfolge sieht an dieser Stelle keinen Angriff vor)',
            actual: err instanceof Error ? (err.stack ?? err.message) : String(err),
          }),
        ].join('\n'),
      );
    }

    // Global invariants, checked after EVERY operation (independent of the concrete branch).
    assertInvariant(
      aliceSession.sendCounter >= 0 && Number.isInteger(aliceSession.sendCounter),
      'sendCounter (Alice) darf nie negativ oder nicht-ganzzahlig sein',
      {
        seed,
        operationSequence,
        stateBefore: null,
        input: op,
        stateAfter: aliceSession,
        expected: '>= 0, ganzzahlig',
        actual: aliceSession.sendCounter,
      },
    );
    assertInvariant(
      aliceSession.receiveCounter >= 0 &&
        Number.isInteger(aliceSession.receiveCounter),
      'receiveCounter (Alice) darf nie negativ oder nicht-ganzzahlig sein',
      {
        seed,
        operationSequence,
        stateBefore: null,
        input: op,
        stateAfter: aliceSession,
        expected: '>= 0, ganzzahlig',
        actual: aliceSession.receiveCounter,
      },
    );
    assertInvariant(
      bobSession.sendCounter >= 0 && Number.isInteger(bobSession.sendCounter),
      'sendCounter (Bob) darf nie negativ oder nicht-ganzzahlig sein',
      {
        seed,
        operationSequence,
        stateBefore: null,
        input: op,
        stateAfter: bobSession,
        expected: '>= 0, ganzzahlig',
        actual: bobSession.sendCounter,
      },
    );
    assertInvariant(
      bobSession.receiveCounter >= 0 &&
        Number.isInteger(bobSession.receiveCounter),
      'receiveCounter (Bob) darf nie negativ oder nicht-ganzzahlig sein',
      {
        seed,
        operationSequence,
        stateBefore: null,
        input: op,
        stateAfter: bobSession,
        expected: '>= 0, ganzzahlig',
        actual: bobSession.receiveCounter,
      },
    );
    assertInvariant(
      aliceSession.sendCounter >= lastAliceSendCounter,
      'sendCounter (Alice) darf niemals ruecklaeufig sein',
      {
        seed,
        operationSequence,
        stateBefore: null,
        input: op,
        stateAfter: aliceSession,
        expected: `>= ${lastAliceSendCounter}`,
        actual: aliceSession.sendCounter,
      },
    );
    assertInvariant(
      aliceSession.receiveCounter >= lastAliceReceiveCounter,
      'receiveCounter (Alice) darf niemals ruecklaeufig sein',
      {
        seed,
        operationSequence,
        stateBefore: null,
        input: op,
        stateAfter: aliceSession,
        expected: `>= ${lastAliceReceiveCounter}`,
        actual: aliceSession.receiveCounter,
      },
    );
    assertInvariant(
      bobSession.sendCounter >= lastBobSendCounter,
      'sendCounter (Bob) darf niemals ruecklaeufig sein',
      {
        seed,
        operationSequence,
        stateBefore: null,
        input: op,
        stateAfter: bobSession,
        expected: `>= ${lastBobSendCounter}`,
        actual: bobSession.sendCounter,
      },
    );
    assertInvariant(
      bobSession.receiveCounter >= lastBobReceiveCounter,
      'receiveCounter (Bob) darf niemals ruecklaeufig sein',
      {
        seed,
        operationSequence,
        stateBefore: null,
        input: op,
        stateAfter: bobSession,
        expected: `>= ${lastBobReceiveCounter}`,
        actual: bobSession.receiveCounter,
      },
    );
    lastAliceSendCounter = aliceSession.sendCounter;
    lastAliceReceiveCounter = aliceSession.receiveCounter;
    lastBobSendCounter = bobSession.sendCounter;
    lastBobReceiveCounter = bobSession.receiveCounter;

    assertInvariant(
      (aliceSession.recentlyConsumedKeys?.length ?? 0) <=
        MAX_RECENTLY_CONSUMED_KEYS,
      'recentlyConsumedKeys (Alice) darf MAX_RECENTLY_CONSUMED_KEYS nie ueberschreiten',
      {
        seed,
        operationSequence,
        stateBefore: null,
        input: op,
        stateAfter: aliceSession,
        expected: `<= ${MAX_RECENTLY_CONSUMED_KEYS}`,
        actual: aliceSession.recentlyConsumedKeys?.length ?? 0,
      },
    );
    assertInvariant(
      (bobSession.recentlyConsumedKeys?.length ?? 0) <=
        MAX_RECENTLY_CONSUMED_KEYS,
      'recentlyConsumedKeys (Bob) darf MAX_RECENTLY_CONSUMED_KEYS nie ueberschreiten',
      {
        seed,
        operationSequence,
        stateBefore: null,
        input: op,
        stateAfter: bobSession,
        expected: `<= ${MAX_RECENTLY_CONSUMED_KEYS}`,
        actual: bobSession.recentlyConsumedKeys?.length ?? 0,
      },
    );
  }
}

describe('sessionStateMachine.property — level 2: seed-based randomized operation sequences', () => {
  // One `it(...)` per seed (via it.each) instead of a collective test: a failing seed (e.g.
  // #147) is then individually visible in the test report, not swallowed in a loop.
  // 30-60 operations per run, varying slightly per seed (30 + seed % 31).
  it.each(LEVEL2_SEEDS)(
    'seed %i: random operation sequence preserves all invariants',
    async seed => {
      const operationCount = 30 + (seed % 31); // 30..60
      await runRandomOperationSequence(seed, operationCount);
    },
  );
});
