/**
 * @format
 */

import {describe, it, expect} from '@jest/globals';
import {normalizeOnionAddress, sanitizeUserText} from '../src/crypto/validation';

describe('sanitizeUserText', () => {
  it('leaves normal text unchanged', () => {
    expect(sanitizeUserText('hallo welt', 100)).toBe('hallo welt');
  });

  it('truncates to the given maximum length', () => {
    expect(sanitizeUserText('a'.repeat(50), 10)).toBe('a'.repeat(10));
  });

  it('removes bidi override characters (visual spoofing)', () => {
    // U+202E RIGHT-TO-LEFT OVERRIDE could e.g. visually hide an extension like ".exe".
    const spoofed = 'gpj.exe‮cod.avi';
    expect(sanitizeUserText(spoofed, 100)).toBe('gpj.execod.avi');
  });

  it('removes bidi isolate characters', () => {
    const withIsolate = 'a⁦b⁩c';
    expect(sanitizeUserText(withIsolate, 100)).toBe('abc');
  });

  it('removes zero-width space and BOM', () => {
    const withZeroWidth = 'a​b﻿c';
    expect(sanitizeUserText(withZeroWidth, 100)).toBe('abc');
  });

  it('leaves zero-width joiners untouched (needed for composite emoji)', () => {
    const familyEmoji = '\u{1F468}‍\u{1F469}‍\u{1F467}'; // 👨‍👩‍👧
    expect(sanitizeUserText(familyEmoji, 100)).toBe(familyEmoji);
  });

  it('leaves LRM/RLM untouched (legitimate RTL formatting hints)', () => {
    const withMarks = 'a‎b‏c';
    expect(sanitizeUserText(withMarks, 100)).toBe(withMarks);
  });
});

describe('normalizeOnionAddress', () => {
  const BARE = 'a'.repeat(56);

  it('leaves an already complete address unchanged', () => {
    expect(normalizeOnionAddress(`${BARE}.onion`)).toBe(`${BARE}.onion`);
  });

  it('adds the missing ".onion" suffix to an otherwise well-formed address (Orbot quirk)', () => {
    // Some Orbot versions show/copy only the bare Base32 string without ".onion" in their own
    // interface — copied text AND manually typed text, both without ".onion", would otherwise fail
    // validation.
    expect(normalizeOnionAddress(BARE)).toBe(`${BARE}.onion`);
  });

  it('trims and lowercases as before', () => {
    expect(normalizeOnionAddress(`  ${BARE.toUpperCase()}.ONION  `)).toBe(
      `${BARE}.onion`,
    );
    expect(normalizeOnionAddress(`  ${BARE.toUpperCase()}  `)).toBe(
      `${BARE}.onion`,
    );
  });

  it('leaves a string of the wrong length or otherwise invalid unchanged (does not guess a suffix)', () => {
    expect(normalizeOnionAddress('zu-kurz')).toBe('zu-kurz');
    expect(normalizeOnionAddress('a'.repeat(55))).toBe('a'.repeat(55));
    expect(normalizeOnionAddress('a'.repeat(57))).toBe('a'.repeat(57));
  });

  it('computes the real .onion address from a raw 32-byte Ed25519 public key in hex (Orbot quirk #2)', () => {
    // Some Orbot versions copy the raw public key (64 hex characters) instead of the finished
    // .onion address on "copy onion service". The synthetic key 00 01 02 ... 1f is used here; the
    // expected value was computed independently of this code base, with a separate implementation
    // of the Tor rend-spec-v3 procedure (SHA3-256 checksum, Base32, version byte 0x03).
    const rawPublicKeyHex =
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    expect(normalizeOnionAddress(rawPublicKeyHex)).toBe(
      'aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp3kead.onion',
    );
  });

  it('recognizes the raw public key regardless of letter case and surrounding spaces', () => {
    const rawPublicKeyHex =
      '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';
    expect(normalizeOnionAddress(`  ${rawPublicKeyHex}  `)).toBe(
      'aaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dyp3kead.onion',
    );
  });
});
