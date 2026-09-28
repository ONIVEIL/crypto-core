/**
 * @format
 */
import {describe, it, expect} from '@jest/globals';
import {computeSafetyNumber} from '../src/crypto/fingerprint';

const ALICE = {
  signingPublicKey: '11'.repeat(32),
  encryptionPublicKey: '22'.repeat(32),
};
const BOB = {
  signingPublicKey: '33'.repeat(32),
  encryptionPublicKey: '44'.repeat(32),
};

describe('computeSafetyNumber', () => {
  it('independently arrives at the same number on both sides', () => {
    const fromAlice = computeSafetyNumber(ALICE, BOB);
    const fromBob = computeSafetyNumber(BOB, ALICE);

    expect(fromAlice).toBe(fromBob);
  });

  it('is deterministic for the same keys', () => {
    expect(computeSafetyNumber(ALICE, BOB)).toBe(
      computeSafetyNumber(ALICE, BOB),
    );
  });

  it('changes when a key of a contact changes', () => {
    const original = computeSafetyNumber(ALICE, BOB);
    const withDifferentKey = computeSafetyNumber(ALICE, {
      ...BOB,
      signingPublicKey: '99'.repeat(32),
    });

    expect(withDifferentKey).not.toBe(original);
  });

  it('is formatted in groups of 4', () => {
    const result = computeSafetyNumber(ALICE, BOB);
    expect(result).toMatch(/^[0-9a-f]{4}( [0-9a-f]{4})*$/);
  });
});
