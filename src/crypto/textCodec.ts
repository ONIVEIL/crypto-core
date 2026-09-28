// textCodec.ts — UTF-8 bytes to string, without depending on the web API `TextDecoder`.
//
// Root cause of a bug reproduced on a real test device: Hermes provides `TextEncoder`, but
// depending on the RN/Hermes version NOT `TextDecoder` — confirmed by
// `ReferenceError: Property 'TextDecoder' doesn't exist` in a real logcat capture. It affected
// EVERY read from storage/encryptedStore.ts (among others the reachable onion address) AND every
// incoming message decryption in crypto/session.ts — both called `new TextDecoder().decode(...)`,
// which threw immediately on this device, before the actual content was processed at all.
// `TextEncoder` (only the opposite direction, string to bytes) stays in use unchanged, since it
// demonstrably works on the same device (see encryptedStore.ts writeEncrypted, whose writes
// succeeded in the same log).
//
// A small implementation of our own instead of a new polyfill dependency (in line with this
// project's principle of keeping crypto-adjacent building blocks small and auditable, see
// encryptedStore.ts).
//
// Behaves like `TextDecoder` in its default ("non-fatal") mode: NEVER throws, but replaces
// invalid byte sequences with U+FFFD. Important, because this code runs on the read path for data
// that is already decrypted (but possibly damaged, e.g. by an interrupted write) — an earlier
// version that assumed well-formed UTF-8 threw a `RangeError` from `String.fromCodePoint` for
// certain broken byte sequences (e.g. a code point > U+10FFFF), which defeated exactly the
// fail-safe path meant to catch it (the JSON-parse error handling of readEncrypted in
// encryptedStore.ts).
const REPLACEMENT_CHAR = '�';

function isContinuationByte(byte: number | undefined): byte is number {
  return byte !== undefined && (byte & 0xc0) === 0x80;
}

export function bytesToUtf8(bytes: Uint8Array): string {
  let result = '';
  let i = 0;
  while (i < bytes.length) {
    const byte0 = bytes[i];
    if (byte0 < 0x80) {
      result += String.fromCharCode(byte0);
      i += 1;
      continue;
    }

    let length: number;
    let codepoint: number;
    if ((byte0 & 0xe0) === 0xc0) {
      length = 2;
      codepoint = byte0 & 0x1f;
    } else if ((byte0 & 0xf0) === 0xe0) {
      length = 3;
      codepoint = byte0 & 0x0f;
    } else if ((byte0 & 0xf8) === 0xf0) {
      length = 4;
      codepoint = byte0 & 0x07;
    } else {
      // Invalid lead byte (e.g. a stray continuation byte 0x80-0xBF, or 0xF8-0xFF, which never
      // occur as lead bytes in valid UTF-8).
      result += REPLACEMENT_CHAR;
      i += 1;
      continue;
    }

    // `consumed` counts only bytes actually recognized as valid continuation bytes (lead byte
    // included) — decisive for the resynchronization below: if the sequence breaks off midway
    // (e.g. because the next byte is not a continuation byte at all), ONLY the part already
    // consumed may be skipped. The interrupting byte itself is left for the next loop iteration
    // instead of being wrongly consumed — otherwise e.g. [0xE2, 0x82, 0x41] ('€' without a valid
    // 3rd byte, followed by 'A') would yield two replacement characters instead of one, because
    // 'A' would be swallowed instead of decoded normally.
    let consumed = 1;
    let valid = true;
    for (let j = 1; j < length; j += 1) {
      const continuation = bytes[i + j];
      if (!isContinuationByte(continuation)) {
        valid = false;
        break;
      }
      codepoint = (codepoint << 6) | (continuation & 0x3f);
      consumed += 1;
    }

    if (!valid) {
      result += REPLACEMENT_CHAR;
      i += consumed;
      continue;
    }
    if (codepoint > 0x10ffff) {
      // All announced bytes were structurally valid continuation bytes, but together yield an
      // impossible code point (e.g. from a damaged 4-byte sequence) — consume the complete
      // sequence here, since (unlike above) it was fully present.
      result += REPLACEMENT_CHAR;
      i += length;
      continue;
    }

    // fromCharCode suffices for everything up to U+FFFF (1-3 bytes); only from 4 bytes on (outside
    // the Basic Multilingual Plane, e.g. emoji) is fromCodePoint needed for a correct UTF-16
    // surrogate pair.
    result +=
      length <= 3 ? String.fromCharCode(codepoint) : String.fromCodePoint(codepoint);
    i += length;
  }
  return result;
}
