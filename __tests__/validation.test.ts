/**
 * @format
 */

import {describe, it, expect} from '@jest/globals';
import {
  normalizeOnionAddress,
  sanitizeSingleLineText,
  sanitizeUserText,
} from '../src/crypto/validation';

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

describe('sanitizeUserText / sanitizeSingleLineText (invisible and control characters)', () => {
  const cp = (code: number) => String.fromCodePoint(code);
  const NEWLINE = String.fromCharCode(10);
  const TAB = String.fromCharCode(9);

  it('removes control characters but keeps line feed and tab', () => {
    const text = `a${cp(1)}b${cp(0x7f)}c${cp(0x85)}d${NEWLINE}e${TAB}f`;
    expect(sanitizeUserText(text, 100)).toBe(`abcd${NEWLINE}e${TAB}f`);
  });

  it('removes bidi overrides, isolates, zero-width space, word joiner and line separators', () => {
    const bad = [0x202a, 0x202e, 0x2066, 0x2069, 0x200b, 0x2060, 0x2064, 0x2028, 0x2029, 0x061c, 0xfeff, 0x206a].map(cp);
    expect(sanitizeUserText(`x${bad.join('y')}z`, 100)).toBe(
      `x${'y'.repeat(bad.length - 1)}z`,
    );
  });

  it('removes invisible Unicode tag characters and surplus variation selectors', () => {
    const tagged = `a${cp(0xe0041)}${cp(0xe0042)}b${cp(0xfe00)}c${cp(0xe0100)}d`;
    expect(sanitizeUserText(tagged, 100)).toBe('abcd');
  });

  it('keeps emoji presentation and composite emoji (VS16, zero-width joiner)', () => {
    const heart = `${cp(0x2764)}${cp(0xfe0f)}`;
    const family = `${cp(0x1f468)}${cp(0x200d)}${cp(0x1f469)}${cp(0x200d)}${cp(0x1f467)}`;
    expect(sanitizeUserText(heart + family, 100)).toBe(heart + family);
  });

  it('keeps LRM/RLM and real RTL text', () => {
    const text = `${cp(0x05d0)}${cp(0x05d1)}${cp(0x200f)}1`;
    expect(sanitizeUserText(text, 100)).toBe(text);
  });

  it('never splits a surrogate pair in the middle when truncating', () => {
    const smiley = cp(0x1f600);
    expect(sanitizeUserText(`a${smiley}${smiley}`, 2)).toBe('a');
    expect(sanitizeUserText(`a${smiley}${smiley}`, 3)).toBe(`a${smiley}`);
    expect(sanitizeUserText(`${smiley}${smiley}`, 3)).toBe(smiley);
  });

  it('the single-line variant turns line breaks and tabs into spaces and trims the edges', () => {
    expect(
      sanitizeSingleLineText(`  Ana${NEWLINE}${NEWLINE}Maria${TAB}K  `, 100),
    ).toBe('Ana Maria K');
  });

  it('the single-line variant truncates only after cleaning', () => {
    expect(sanitizeSingleLineText(`${cp(0x202e)}abcdef`, 3)).toBe('abc');
  });
});
