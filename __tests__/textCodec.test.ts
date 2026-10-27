/**
 * @format
 */

import {describe, it, expect} from '@jest/globals';
import {bytesToUtf8} from '../src/crypto/textCodec';

// Node provides TextEncoder/TextDecoder globally, Hermes demonstrably does NOT on at least one
// real test device (see textCodec.ts) — so this test deliberately does NOT compare against
// TextDecoder, but against known, hand-verified byte sequences, so that the test still says
// something when `TextDecoder` is missing in the respective runtime environment.
describe('bytesToUtf8', () => {
  it('decodes plain ASCII', () => {
    expect(bytesToUtf8(new TextEncoder().encode('hello world'))).toBe(
      'hello world',
    );
  });

  it('decodes 2-byte sequences (German umlauts)', () => {
    const text = 'äöüß Grüße';
    expect(bytesToUtf8(new TextEncoder().encode(text))).toBe(text);
  });

  it('decodes 3-byte sequences', () => {
    const text = '日本語';
    expect(bytesToUtf8(new TextEncoder().encode(text))).toBe(text);
  });

  it('decodes 4-byte sequences (emoji, outside the BMP)', () => {
    const text = '🔒🎉👍';
    expect(bytesToUtf8(new TextEncoder().encode(text))).toBe(text);
  });

  it('decodes mixed content like a typical contact JSON structure', () => {
    const text = JSON.stringify([
      {displayName: 'Müller 🔒', onionAddress: 'abc.onion'},
    ]);
    expect(bytesToUtf8(new TextEncoder().encode(text))).toBe(text);
  });

  it('decodes an empty byte sequence as an empty string', () => {
    expect(bytesToUtf8(new Uint8Array(0))).toBe('');
  });

  it('matches known, hand-computed byte values (independent of TextEncoder)', () => {
    // "aä€" — 'a' (1 byte), 'ä' (U+00E4, 2 bytes: 0xC3 0xA4), '€' (U+20AC, 3 bytes: 0xE2 0x82 0xAC)
    const bytes = new Uint8Array([0x61, 0xc3, 0xa4, 0xe2, 0x82, 0xac]);
    expect(bytesToUtf8(bytes)).toBe('aä€');
  });

  // These cases concern exclusively faulty/foreign byte sequences, as could occur e.g. after a
  // damaged (but authenticated-and-decrypted) storage blob (readEncrypted in encryptedStore.ts) —
  // the decoder must NEVER throw there (see the module comment), but behave like `TextDecoder` in
  // its default mode (U+FFFD instead of a crash).
  it('never throws, not even for a code point above U+10FFFF (formerly a RangeError)', () => {
    const bytes = new Uint8Array([0xf4, 0xbf, 0xbf, 0xbf]);
    expect(() => bytesToUtf8(bytes)).not.toThrow();
    expect(bytesToUtf8(bytes)).toBe('�');
  });

  it('replaces a truncated multi-byte sequence at the end with U+FFFD instead of producing garbage', () => {
    // Only the first 2 of 3 bytes of a '€' (0xE2 0x82 0xAC)
    const bytes = new Uint8Array([0x61, 0xe2, 0x82]);
    expect(bytesToUtf8(bytes)).toBe('a�');
  });

  it('replaces an invalid lead byte (stray continuation byte) with U+FFFD', () => {
    const bytes = new Uint8Array([0x61, 0x80, 0x62]);
    expect(bytesToUtf8(bytes)).toBe('a�b');
  });

  it('replaces a sequence with an invalid continuation byte with U+FFFD and resynchronizes afterwards', () => {
    // 0xE2 announces 2 more bytes, but the second (0x41 = 'A') is not a continuation byte
    const bytes = new Uint8Array([0xe2, 0x82, 0x41]);
    expect(bytesToUtf8(bytes)).toBe('�A');
  });

  it('decodes boundary code points correctly (U+FFFF and U+10000)', () => {
    expect(bytesToUtf8(new TextEncoder().encode('￿'))).toBe('￿');
    expect(bytesToUtf8(new TextEncoder().encode('\u{10000}'))).toBe(
      '\u{10000}',
    );
  });

  describe('strict decoding', () => {
    const REPLACEMENT = String.fromCodePoint(0xfffd);

    it('rejects overlong encodings (two bytes for an ASCII character)', () => {
      // 0xC0 0x80 would be an overlong encoding of U+0000, 0xC1 0xBF one of U+007F
      expect(bytesToUtf8(new Uint8Array([0xc0, 0x80]))).toBe(REPLACEMENT);
      expect(bytesToUtf8(new Uint8Array([0xc1, 0xbf]))).toBe(REPLACEMENT);
    });

    it('rejects overlong three- and four-byte encodings', () => {
      expect(bytesToUtf8(new Uint8Array([0xe0, 0x80, 0xaf]))).toBe(REPLACEMENT);
      expect(bytesToUtf8(new Uint8Array([0xf0, 0x80, 0x80, 0xaf]))).toBe(
        REPLACEMENT,
      );
    });

    it('rejects surrogate halves (U+D800-DFFF)', () => {
      expect(bytesToUtf8(new Uint8Array([0xed, 0xa0, 0x80]))).toBe(REPLACEMENT);
      expect(bytesToUtf8(new Uint8Array([0xed, 0xbf, 0xbf]))).toBe(REPLACEMENT);
    });

    it('rejects values above U+10FFFF', () => {
      expect(bytesToUtf8(new Uint8Array([0xf4, 0x90, 0x80, 0x80]))).toBe(
        REPLACEMENT,
      );
    });

    it('still decodes the shortest valid form of each length', () => {
      expect(bytesToUtf8(new Uint8Array([0xc2, 0x80]))).toBe(
        String.fromCodePoint(0x80),
      );
      expect(bytesToUtf8(new Uint8Array([0xe0, 0xa0, 0x80]))).toBe(
        String.fromCodePoint(0x800),
      );
      expect(bytesToUtf8(new Uint8Array([0xf0, 0x90, 0x80, 0x80]))).toBe(
        String.fromCodePoint(0x10000),
      );
      expect(bytesToUtf8(new Uint8Array([0xf4, 0x8f, 0xbf, 0xbf]))).toBe(
        String.fromCodePoint(0x10ffff),
      );
    });
  });
});
