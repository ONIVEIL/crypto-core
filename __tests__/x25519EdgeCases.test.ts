/**
 * @format
 */
// x25519EdgeCases.test.ts — X25519 edge cases on two separate levels:
//
//   - PRIMITIVE level: pure `@noble/curves` x25519 function calls, without any session.ts
//     context. Checks WHAT the actually installed library itself does for known edge cases
//     (RFC 7748 vectors, low-order points, all-zero keys, wrong key length) — not assumed, but
//     traced in the real code (see node_modules/@noble/curves/src/abstract/montgomery.ts: the
//     `lowOrderU` set and the `abytes(...)` length check).
//   - PROTOCOL level: the same edge cases in the context of `createSession` — in particular the
//     question whether a malicious contact code with a crafted (low-order) X25519 public key as
//     `encryptionPublicKey` (which parseContactCode/addContact check ONLY for format, NOT for
//     curve validity, see crypto/contactCode.ts) could weaken session security for the OTHER,
//     honest participant — not the trivial/uninteresting "attacker knows their own session with
//     themselves".
//
// Source of the RFC 7748 test vectors (important for the reliability of these tests themselves):
// the values below were NOT taken from memory, but retrieved twice independently from
// https://www.rfc-editor.org/rfc/rfc7748.txt (RFC Editor, the official IETF source) and checked
// byte for byte (both retrievals agreed, 32 bytes/64 hex characters per value). A wrong test
// vector in the test itself would be worse than none at all — hence this explicit provenance
// instead of a bare literal value without evidence.
global.crypto = global.crypto ?? require('crypto').webcrypto;

import {describe, it, expect} from '@jest/globals';
import {x25519} from '@noble/curves/ed25519.js';
import {bytesToHex, hexToBytes} from '@noble/hashes/utils.js';
import {createSession} from '../src/crypto/session';
import {parseContactCode} from '../src/crypto/contactCode';
import {HEX_32_BYTES_PATTERN} from '../src/crypto/validation';

function keypair() {
  const {secretKey, publicKey} = x25519.keygen();
  return {privateKey: bytesToHex(secretKey), publicKey: bytesToHex(publicKey)};
}

// Encodes a u-coordinate value exactly like noble internally (`encodeU`/`numberToBytesLE` in
// montgomery.ts): little-endian, 32 bytes. Deliberately re-built locally instead of imported from
// the library (not part of its public API) — for the two known order-8 points below that is
// enough, because we ONLY want to produce the bytes to be tested, not re-verify the library's
// own encoding.
function leBytesFromBigInt(n: bigint, length = 32): Uint8Array {
  const bytes = new Uint8Array(length);
  let v = n;
  for (let i = 0; i < length; i++) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

describe('X25519 — RFC 7748 test vectors (primitive level)', () => {
  // RFC 7748 §6.1, "Diffie-Hellman" — Alice/Bob example. Verified against rfc-editor.org (see
  // the module documentation above), 64 hex characters (32 bytes) each.
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

  it('the test vectors themselves are well-formed (64 hex characters = 32 bytes) — protection against a typo when copying the RFC values', () => {
    for (const value of [
      ALICE_PRIVATE,
      ALICE_PUBLIC,
      BOB_PRIVATE,
      BOB_PUBLIC,
      EXPECTED_SHARED_SECRET,
    ]) {
      expect(value).toMatch(HEX_32_BYTES_PATTERN);
    }
  });

  it('X25519(Alice_priv, Bob_pub) yields exactly the expected shared secret from RFC 7748', () => {
    const result = x25519.getSharedSecret(
      hexToBytes(ALICE_PRIVATE),
      hexToBytes(BOB_PUBLIC),
    );
    expect(bytesToHex(result)).toBe(EXPECTED_SHARED_SECRET);
  });

  it('X25519(Bob_priv, Alice_pub) yields the same shared secret (symmetry, opposite direction)', () => {
    const result = x25519.getSharedSecret(
      hexToBytes(BOB_PRIVATE),
      hexToBytes(ALICE_PUBLIC),
    );
    expect(bytesToHex(result)).toBe(EXPECTED_SHARED_SECRET);
  });

  it('X25519(Alice_priv, 9) / X25519(Bob_priv, 9) derive exactly the public keys given in the RFC', () => {
    expect(bytesToHex(x25519.getPublicKey(hexToBytes(ALICE_PRIVATE)))).toBe(
      ALICE_PUBLIC,
    );
    expect(bytesToHex(x25519.getPublicKey(hexToBytes(BOB_PRIVATE)))).toBe(
      BOB_PUBLIC,
    );
  });
});

describe('X25519 — low-order points / small subgroup (primitive level)', () => {
  // All five u-coordinates whose order divides the cofactor (curve AND its quadratic twist) —
  // the same blocklist approach as libsodium/Libgcrypt since CVE-2017-0379. The last two decimal
  // values are taken LITERALLY from node_modules/@noble/curves/src/abstract/montgomery.ts
  // (`lowOrderU` set) — the actually installed library, as used by session.ts, is the
  // authoritative source here, not a separately memorized hex value.
  const P = 2n ** 255n - 19n;
  const LOW_ORDER_U_VALUES: Array<{label: string; value: bigint}> = [
    {label: 'u=0', value: 0n},
    {label: 'u=1', value: 1n},
    {label: 'u=p-1 (Twist-Punkt der Ordnung 2)', value: P - 1n},
    {
      label: 'Ordnung-8-Punkt A (aus @noble/curves lowOrderU)',
      value: 325606250916557431795983626356110631294008115727848805560023387167927233504n,
    },
    {
      label: 'Ordnung-8-Punkt B (aus @noble/curves lowOrderU)',
      value: 39382357235489614581723060781553021112529911719440698176882885853963445705823n,
    },
  ];

  it.each(LOW_ORDER_U_VALUES)(
    'x25519.getSharedSecret rejects $label as a foreign public key, instead of readily returning a (predictable) shared secret',
    ({value}) => {
      const maliciousPublicKeyHex = bytesToHex(leBytesFromBigInt(value));
      const honest = keypair();
      // @noble/curves v2 validates the u-coordinate value BEFORE the ladder computation (see
      // montgomery.ts scalarMult: `if (lowOrderU.has(pointU)) throw ...`) — not a conclusion from
      // documentation, but observed here directly in the actually installed code.
      expect(() =>
        x25519.getSharedSecret(
          hexToBytes(honest.privateKey),
          hexToBytes(maliciousPublicKeyHex),
        ),
      ).toThrow(/invalid private or public key received/i);
    },
  );

  it('leBytesFromBigInt(1n) encodes exactly the literal all-zero-with-leading-1-byte value (protects the test helper itself against a little-/big-endian mix-up)', () => {
    // Pure self-test of the helper defined above: u=1 must be encoded as 0x01 followed by 31 zero
    // bytes (little-endian, like encodeU() in montgomery.ts) — a big-endian error in the helper
    // would produce a VALID, non-degenerate point and wrongly make the low-order tests above
    // meaningless (but still green).
    expect(bytesToHex(leBytesFromBigInt(1n))).toBe('01' + '00'.repeat(31));
  });
});

describe('X25519 — all-zero key (primitive and protocol level)', () => {
  const ALL_ZERO_HEX = '00'.repeat(32);

  it('primitive level: an all-zero public key is rejected (u=0 is part of the low-order set above)', () => {
    const honest = keypair();
    expect(() =>
      x25519.getSharedSecret(
        hexToBytes(honest.privateKey),
        hexToBytes(ALL_ZERO_HEX),
      ),
    ).toThrow(/invalid private or public key received/i);
  });

  it('protocol level: createSession() rejects a malicious contact with an all-zero encryptionPublicKey already at session setup — a session NEVER comes into existence, hence NEVER one that is weak/predictable for the honest participant', () => {
    const honest = keypair();
    expect(() =>
      createSession(honest.privateKey, honest.publicKey, ALL_ZERO_HEX),
    ).toThrow(/invalid private or public key received/i);
  });

  it('primitive level: an all-zero OWN private key does NOT throw (scalar clamping turns it into a well-defined, non-trivial scalar 2^254) — actual behavior documented instead of assumed', () => {
    const contact = keypair();
    const derivedOwnPublicKey = bytesToHex(
      x25519.getPublicKey(hexToBytes(ALL_ZERO_HEX)),
    );
    const shared = x25519.getSharedSecret(
      hexToBytes(ALL_ZERO_HEX),
      hexToBytes(contact.publicKey),
    );
    // Not a security-relevant finding: an all-zero byte sequence as a RAW scalar is mapped by
    // adjustScalarBytes (RFC 7748 clamping: bit 254 set, lowest 3 bits cleared) to a fixed but
    // entirely ordinary scalar value (2^254) — no special case that the library could or should
    // detect. It would only matter if the OWN private key were attacker-influenced — but it always
    // comes from the own random generation in crypto/identity.ts, never from contact data.
    expect(shared).not.toEqual(new Uint8Array(32));
    expect(derivedOwnPublicKey).toMatch(HEX_32_BYTES_PATTERN);

    // createSession with this (degenerate, but technically valid) own key pair keeps working
    // unremarkably — no crash, no special handling needed.
    const session = createSession(
      ALL_ZERO_HEX,
      derivedOwnPublicKey,
      contact.publicKey,
    );
    expect(session.rootKey).toMatch(HEX_32_BYTES_PATTERN);
  });
});

describe('X25519 — invalid public-key length (primitive and protocol level)', () => {
  const TOO_SHORT_HEX = '00'.repeat(16); // 16 instead of 32 bytes
  const TOO_LONG_HEX = '00'.repeat(48); // 48 instead of 32 bytes

  it('primitive level: x25519.getSharedSecret throws for a too-short public-key hex', () => {
    const honest = keypair();
    expect(() =>
      x25519.getSharedSecret(
        hexToBytes(honest.privateKey),
        hexToBytes(TOO_SHORT_HEX),
      ),
    ).toThrow();
  });

  it('primitive level: x25519.getSharedSecret throws for a too-long public-key hex', () => {
    const honest = keypair();
    expect(() =>
      x25519.getSharedSecret(
        hexToBytes(honest.privateKey),
        hexToBytes(TOO_LONG_HEX),
      ),
    ).toThrow();
  });

  it('protocol level: createSession() called DIRECTLY (not via the contact-code parser) with a wrongly long hex also throws — the format check in validation.ts/contactCode.ts is an ADDITIONAL, not the ONLY line of defense against this case', () => {
    const honest = keypair();
    expect(() =>
      createSession(honest.privateKey, honest.publicKey, TOO_SHORT_HEX),
    ).toThrow();
    expect(() =>
      createSession(honest.privateKey, honest.publicKey, TOO_LONG_HEX),
    ).toThrow();
  });

  it('confirms the FIRST line of defense: parseContactCode() rejects a contact code with a wrongly long key field before any session.ts call (returns null)', () => {
    const honest = keypair();
    const codeWithTooShortEncryptionKey = `oniveil-kontakt:${'a'.repeat(
      56,
    )}.onion:${honest.publicKey}:${TOO_SHORT_HEX}`;
    expect(parseContactCode(codeWithTooShortEncryptionKey)).toBeNull();
  });
});

describe('protocol level — malicious-but-valid contact code with a low-order point as encryptionPublicKey', () => {
  // Threat model (explicitly NOT the trivial "attacker knows their own session with themselves"):
  // parseContactCode/addContact check ONLY the format/length of the encryptionPublicKey field
  // (see crypto/contactCode.ts, HEX_32_BYTES_PATTERN) — NOT whether the value is actually a valid,
  // non-degenerate X25519 curve point. An attacker could therefore try to craft their own
  // contact-code field with a low-order value and slip it to the victim (e.g. by copy-pasting a
  // manipulated text). Question: does that give the VICTIM (the honest participant who adds this
  // contact) a session that is predictable/weakened for the attacker?
  //
  // Result: NO — createSession() throws synchronously and IMMEDIATELY at the first session setup,
  // because x25519.getSharedSecret() itself rejects the low-order value before any root
  // key/chain key is derived at all. So NO session ever comes into existence — neither a weak one
  // nor any at all. The practical effect is a malfunction (the contact cannot be used), not a
  // compromise of confidentiality.
  //
  // NOTE: because createSession() throws, every CALLER must handle that exception. In an
  // application that tries several contacts in turn when guessing the sender of an incoming
  // message, an unhandled throw for one malicious contact could block the receipt of unrelated,
  // legitimate messages of OTHER contacts — an availability/robustness matter of the calling
  // layer, not a weakening of the session security of session.ts itself, and hence deliberately
  // not modelled here as a session.ts test case. The messaging layer is not part of this
  // repository.
  const P = 2n ** 255n - 19n;
  const LOW_ORDER_VALUES: bigint[] = [
    0n,
    1n,
    P - 1n,
    325606250916557431795983626356110631294008115727848805560023387167927233504n,
    39382357235489614581723060781553021112529911719440698176882885853963445705823n,
  ];

  it('createSession() throws for EVERY known low-order value as theirEncryptionPublicKey — a session that is predictable or otherwise weakened for the honest participant never comes into existence', () => {
    const honest = keypair();
    for (const value of LOW_ORDER_VALUES) {
      const maliciousHex = bytesToHex(leBytesFromBigInt(value));
      expect(() =>
        createSession(honest.privateKey, honest.publicKey, maliciousHex),
      ).toThrow(/invalid private or public key received/i);
    }
  });

  it('the same contact code is NOT already rejected at the format level by parseContactCode() — the low-order check happens in fact exclusively in @noble/curves itself, not in this code base (documentation of the actual defensive situation)', () => {
    const honest = keypair();
    const lowOrderPubKeyHex = bytesToHex(leBytesFromBigInt(1n));
    // Onion address and signingPublicKey are fundamentally INDEPENDENT of each other in a real
    // contact code (Orbot assigns its own, random key pair for the onion service, see the note in
    // crypto/contactCode.ts) — hence deliberately an arbitrary, non-derived address.
    const onionAddress = `${'a'.repeat(56)}.onion`;
    const code = `oniveil-kontakt:${onionAddress}:${honest.publicKey}:${lowOrderPubKeyHex}`;
    // parseContactCode has no notion of a "valid curve point" — a purely FORMAT-valid
    // encryptionPublicKey field like lowOrderPubKeyHex passes this check without complaint. Only
    // createSession() (see the tests above) rejects the actual value.
    expect(lowOrderPubKeyHex).toMatch(HEX_32_BYTES_PATTERN);
    expect(parseContactCode(code)).toEqual({
      onionAddress,
      signingPublicKey: honest.publicKey,
      encryptionPublicKey: lowOrderPubKeyHex,
    });
  });
});
