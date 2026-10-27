/**
 * @format
 */

import {describe, it, expect} from '@jest/globals';
import {buildContactCode, parseContactCode} from '../src/crypto/contactCode';

// Onion address deliberately NOT derived from signingPublicKey — in a real contact code the two
// values are fundamentally independent (when set up manually, Orbot assigns its own random key
// pair for the onion service; see the note in crypto/contactCode.ts).
const FIELDS = {
  onionAddress: `${'a'.repeat(56)}.onion`,
  signingPublicKey: '11'.repeat(32),
  encryptionPublicKey: '22'.repeat(32),
};

describe('contactCode', () => {
  it('builds a code that can be split back into the same fields', () => {
    const code = buildContactCode(FIELDS);
    expect(parseContactCode(code)).toEqual(FIELDS);
  });

  it('also recognizes the code with surrounding whitespace (e.g. from a pasted message)', () => {
    const code = `  ${buildContactCode(FIELDS)}\n`;
    expect(parseContactCode(code)).toEqual(FIELDS);
  });

  it('normalizes the letter case of the keys as when filling in manually', () => {
    const code = buildContactCode(FIELDS).replace(
      FIELDS.signingPublicKey,
      FIELDS.signingPublicKey.toUpperCase(),
    );
    expect(parseContactCode(code)).toEqual(FIELDS);
  });

  it('adds a missing ".onion" suffix like normalizeOnionAddress()', () => {
    const bare = FIELDS.onionAddress.replace('.onion', '');
    const code = buildContactCode({...FIELDS, onionAddress: bare});
    expect(parseContactCode(code)).toEqual(FIELDS);
  });

  it('returns null for text without the expected prefix (e.g. an ordinary message)', () => {
    expect(parseContactCode('hallo, wie geht es dir?')).toBeNull();
  });

  it('returns null if there are not exactly three parts after the prefix', () => {
    expect(parseContactCode(`oniveil-kontakt:${FIELDS.onionAddress}`)).toBeNull();
    expect(
      parseContactCode(
        `oniveil-kontakt:${FIELDS.onionAddress}:${FIELDS.signingPublicKey}:${FIELDS.encryptionPublicKey}:extra`,
      ),
    ).toBeNull();
  });

  it('returns null for an invalid onion address in the code', () => {
    expect(
      parseContactCode(
        `oniveil-kontakt:nicht-valide:${FIELDS.signingPublicKey}:${FIELDS.encryptionPublicKey}`,
      ),
    ).toBeNull();
  });

  it('returns null for a too-short key in the code', () => {
    expect(
      parseContactCode(
        `oniveil-kontakt:${FIELDS.onionAddress}:zukurz:${FIELDS.encryptionPublicKey}`,
      ),
    ).toBeNull();
  });

  it('rejects empty text instead of throwing', () => {
    expect(parseContactCode('')).toBeNull();
  });

  it('accepts an onion address that is NOT derivable from signingPublicKey (regression test: that is the normal case, not an attack)', () => {
    // Exactly the real scenario: Orbot's own, independently generated onion key pair combined
    // with the app's own signingPublicKey — a perfectly valid, real contact code.
    const code = buildContactCode({
      ...FIELDS,
      onionAddress: `${'z'.repeat(56)}.onion`,
    });
    expect(parseContactCode(code)).toEqual({
      ...FIELDS,
      onionAddress: `${'z'.repeat(56)}.onion`,
    });
  });

  describe('prefix after the rename to ONIVEIL', () => {
    it('builds codes with the new prefix', () => {
      expect(buildContactCode(FIELDS).startsWith('oniveil-kontakt:')).toBe(true);
    });

    it('still accepts codes with the legacy prefix so existing contacts need not exchange codes again', () => {
      const legacy = `onyvia-kontakt:${FIELDS.onionAddress}:${FIELDS.signingPublicKey}:${FIELDS.encryptionPublicKey}`;
      expect(parseContactCode(legacy)).toEqual(FIELDS);
      expect(parseContactCode(legacy.toUpperCase().replace('ONYVIA-KONTAKT', 'Onyvia-Kontakt'))).not.toBeNull();
    });

    it('still rejects foreign prefixes', () => {
      expect(
        parseContactCode(`fremd-kontakt:${FIELDS.onionAddress}:${FIELDS.signingPublicKey}:${FIELDS.encryptionPublicKey}`),
      ).toBeNull();
    });
  });
});
