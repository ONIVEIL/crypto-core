/**
 * @format
 */
// Parser fuzzing — this entire test file treats `decodeMessageContent`
// (crypto/messageContent.ts) as the boundary to an UNAUTHENTICATED or formally invalid attacker:
// everything "entered" here simulates bytes that were already successfully decrypted via the
// session ratchet (i.e. that come from a real contact — session.ts checks authenticity BEFORE
// this module), but that can be arbitrarily manipulated/broken/pathological within that trusted
// frame (a modified client, a bug at the peer, or the like). Goal: no case may throw, crash or
// take unreasonably long — every rejection must cleanly be `null` (see the decodeMessageContent
// comment: "Returns `null` for any kind of invalid, unknown or oversized content instead of
// throwing").
//
// Deliberately supplements ONLY gaps that messageContent.test.ts does not cover yet (see there
// for the basic encoding/decoding correctness of each content type) — this file focuses on
// pathological/adversarial raw strings instead of correct structure.
import {describe, it, expect} from '@jest/globals';
import {
  decodeMessageContent,
  MAX_CONTENT_BYTES,
} from '../src/crypto/messageContent';

const ID_1 = '11'.repeat(16);
const ID_2 = '22'.repeat(16);
const TRANSFER_ID = '33'.repeat(16);
const GROUP_ID = '44'.repeat(16);
const VALID_KEY = 'ab'.repeat(32);

describe('messageContent parser fuzzing', () => {
  describe('pathological/broken raw inputs', () => {
    it('rejects an empty string instead of throwing', () => {
      expect(() => decodeMessageContent('')).not.toThrow();
      expect(decodeMessageContent('')).toBeNull();
    });

    it('rejects plain whitespace in various forms instead of throwing', () => {
      for (const raw of [' ', '\n', '\t', '   \n\t  ', '\r\n']) {
        expect(() => decodeMessageContent(raw)).not.toThrow();
        expect(decodeMessageContent(raw)).toBeNull();
      }
    });

    it('rejects truncated/half, otherwise valid JSON instead of throwing', () => {
      const full = JSON.stringify({
        v: 1,
        type: 'text',
        id: ID_1,
        body: 'eine ganz normale, an sich gültige Nachricht',
      });
      const half = full.slice(0, Math.floor(full.length / 2));
      expect(() => decodeMessageContent(half)).not.toThrow();
      expect(decodeMessageContent(half)).toBeNull();
      // Even a cut that ends in the middle of a string literal or right before the closing
      // bracket must not throw (different JSON.parse failure positions).
      expect(decodeMessageContent(full.slice(0, full.length - 1))).toBeNull();
      expect(decodeMessageContent(full.slice(0, 5))).toBeNull();
    });

    it('returns null for a JSON value that is a number instead of an object', () => {
      for (const raw of ['0', '-1', '3.14159', String(Number.MAX_SAFE_INTEGER)]) {
        expect(() => decodeMessageContent(raw)).not.toThrow();
        expect(decodeMessageContent(raw)).toBeNull();
      }
    });

    it('returns null for a JSON array instead of an object (also with realistic-looking content)', () => {
      expect(decodeMessageContent('[]')).toBeNull();
      expect(decodeMessageContent('[1,2,3]')).toBeNull();
      expect(
        decodeMessageContent(
          JSON.stringify([{v: 1, type: 'text', id: ID_1, body: 'x'}]),
        ),
      ).toBeNull();
    });

    it('returns null if a field actually expected as a string carries a nested object instead', () => {
      // 'body' of 'text' expects a string — a nested object must not slip through by accident as
      // "truthy enough" or throw while sanitizing.
      expect(
        decodeMessageContent(
          JSON.stringify({
            v: 1,
            type: 'text',
            id: ID_1,
            body: {nested: {tief: ['verschachtelt', 1, null]}},
          }),
        ),
      ).toBeNull();
      // The same for 'media'.transferId (string expected, here an object).
      expect(
        decodeMessageContent(
          JSON.stringify({
            v: 1,
            type: 'media',
            id: ID_1,
            transferId: {evil: true},
            filename: 'a.jpg',
            mimeType: 'image/jpeg',
            size: 10,
            key: VALID_KEY,
          }),
        ),
      ).toBeNull();
    });

    it('tolerates additional, unknown fields in an otherwise valid object (forward compatibility)', () => {
      // A newer app version might send additional fields that this version does not know yet —
      // decodeMessageContent must NOT reject that as "broken", see the
      // detectUnrecognizedMessageType comment (only an entirely unknown `type` triggers the
      // "unsupported" feedback, a known type with additional fields does not).
      const decoded = decodeMessageContent(
        JSON.stringify({
          v: 1,
          type: 'text',
          id: ID_1,
          body: 'hallo',
          replyToId: ID_2,
          einZukuenftigesFeld: 'irgendwas',
          nocheins: {tief: [1, 2, 3]},
        }),
      );
      expect(decoded).toEqual({
        v: 1,
        type: 'text',
        id: ID_1,
        body: 'hallo',
        replyToId: ID_2,
      });
    });

    // Deliberately builds the nested structure via string concatenation instead of recursively
    // nested JS objects — otherwise the TEST SETUP itself (not the code under test) would risk a
    // stack overflow.
    it('does not throw and rejects cleanly for JSON nested 1000 levels deep (no stack overflow)', () => {
      const depth = 1000;
      const raw = '{"a":'.repeat(depth) + '0' + '}'.repeat(depth);
      // Deliberately stays below MAX_CONTENT_BYTES, so that the size check does not kick in
      // before JSON.parse — this test is meant to target the parsing/the object structure itself.
      expect(raw.length).toBeLessThan(MAX_CONTENT_BYTES);
      expect(() => decodeMessageContent(raw)).not.toThrow();
      // No `v`/`type` at the top level — must cleanly be recognized as invalid.
      expect(decodeMessageContent(raw)).toBeNull();
    });

    it('does not throw for JSON nested 1000 levels deep, even if `v`/`type` are present at the top level', () => {
      const depth = 1000;
      const nested = '{"a":'.repeat(depth) + '0' + '}'.repeat(depth);
      const raw = JSON.stringify({v: 1, type: 'text', id: ID_1}).replace(
        '}',
        `,"body":${JSON.stringify(nested)}}`,
      );
      // body is a string here (containing the nested structure as text, not as actually nested
      // JSON) — a pure check that this constellation does not throw either. (body is recognized
      // as a string and sanitized/truncated normally.)
      expect(() => decodeMessageContent(raw)).not.toThrow();
    });
  });

  describe('MAX_CONTENT_BYTES boundary', () => {
    // Constructs a 'text' message whose encoded JSON length corresponds exactly to the desired
    // total byte count (plain ASCII in body — 1 character corresponds to exactly 1 byte, no
    // escaping surprises).
    function encodedTextOfExactLength(totalLength: number): string {
      const baseLength = JSON.stringify({
        v: 1,
        type: 'text',
        id: ID_1,
        body: '',
      }).length;
      const bodyLength = totalLength - baseLength;
      expect(bodyLength).toBeGreaterThanOrEqual(0);
      return JSON.stringify({
        v: 1,
        type: 'text',
        id: ID_1,
        body: 'x'.repeat(bodyLength),
      });
    }

    it('accepts an encoded object exactly at MAX_CONTENT_BYTES', () => {
      const raw = encodedTextOfExactLength(MAX_CONTENT_BYTES);
      expect(raw.length).toBe(MAX_CONTENT_BYTES);
      expect(decodeMessageContent(raw)).not.toBeNull();
    });

    it('rejects an encoded object exactly ONE byte above MAX_CONTENT_BYTES', () => {
      const raw = encodedTextOfExactLength(MAX_CONTENT_BYTES + 1);
      expect(raw.length).toBe(MAX_CONTENT_BYTES + 1);
      expect(decodeMessageContent(raw)).toBeNull();
    });

    // Verifies the specification comment in messageContent.ts literally: the size check comes
    // BEFORE JSON.parse. A particularly "expensive" (deeply nested) JSON just above the limit must
    // therefore be rejected JUST AS FAST as a trivial one — the rejection must not happen only
    // after the (potentially expensive) parsing.
    it('immediately rejects a pathological, deeply nested JSON just above the limit (before JSON.parse)', () => {
      // Nested deeply enough to cause noticeable work on actual parsing, but kept just above
      // MAX_CONTENT_BYTES.
      let depth = 1;
      let raw = '{"a":0}';
      while (raw.length <= MAX_CONTENT_BYTES) {
        depth += 1;
        raw = '{"a":'.repeat(depth) + '0' + '}'.repeat(depth);
      }
      expect(raw.length).toBeGreaterThan(MAX_CONTENT_BYTES);

      const start = Date.now();
      const result = decodeMessageContent(raw);
      const elapsedMs = Date.now() - start;

      expect(result).toBeNull();
      // Generous upper bound (a pure length check should take a fraction of a millisecond) — this
      // test is meant to detect gross regressions (e.g. someone swaps the order of the length
      // check and JSON.parse), not to be a strict performance measurement.
      expect(elapsedMs).toBeLessThan(200);
    });
  });

  describe('ID fields: path-traversal/injection payloads as transferId/id/groupId', () => {
    // `id` (text/media/group-*), `transferId` (media/group-media) and `groupId` (group-*) are,
    // according to the messageContent.ts comment, used among other things as a file name for local
    // attachment/message storage — HEX_16_BYTES_PATTERN (32 hex characters, ^...$ fully anchored)
    // MUST reject each of these payloads, regardless of encoding/content.
    const PATH_TRAVERSAL_PAYLOADS = [
      '../../etc/passwd',
      '..%2F..%2F..%2Fetc%2Fpasswd',
      'id\0.txt', // null-byte injection
      '....//....//etc/passwd',
      'a'.repeat(10000), // very long
      // The empty string is already covered in messageContent.test.ts ('returns null if a text
      // message lacks the ID') — deliberately NOT included again here.
      // Otherwise valid (right length, real hex alphabet), but upper case — the pattern is
      // deliberately [0-9a-f], not case-insensitive (unlike e.g. contact codes, which are
      // explicitly normalized before the check, see contactCode.ts). Important:
      // '1'.toUpperCase() would be a no-op (digits have no upper/lower case) — hence a hex value
      // WITH letters ('ab') here, not just digits.
      'ab'.repeat(16).toUpperCase(),
      '11'.repeat(15) + 'gg', // right length, but invalid hex alphabet at the end
    ];

    it.each(PATH_TRAVERSAL_PAYLOADS)(
      'rejects "%s" as text.id',
      payload => {
        expect(
          decodeMessageContent(
            JSON.stringify({v: 1, type: 'text', id: payload, body: 'x'}),
          ),
        ).toBeNull();
      },
    );

    it.each(PATH_TRAVERSAL_PAYLOADS)(
      'rejects "%s" as media.transferId (otherwise a completely valid envelope)',
      payload => {
        expect(
          decodeMessageContent(
            JSON.stringify({
              v: 1,
              type: 'media',
              id: ID_1,
              transferId: payload,
              filename: 'a.jpg',
              mimeType: 'image/jpeg',
              size: 10,
              key: VALID_KEY,
            }),
          ),
        ).toBeNull();
      },
    );

    it.each(PATH_TRAVERSAL_PAYLOADS)(
      'rejects "%s" as media.id (used as a file name for attachment storage)',
      payload => {
        expect(
          decodeMessageContent(
            JSON.stringify({
              v: 1,
              type: 'media',
              id: payload,
              transferId: TRANSFER_ID,
              filename: 'a.jpg',
              mimeType: 'image/jpeg',
              size: 10,
              key: VALID_KEY,
            }),
          ),
        ).toBeNull();
      },
    );

    it.each(PATH_TRAVERSAL_PAYLOADS)(
      'rejects "%s" as group-text.groupId',
      payload => {
        expect(
          decodeMessageContent(
            JSON.stringify({
              v: 1,
              type: 'group-text',
              groupId: payload,
              id: ID_1,
              body: 'x',
            }),
          ),
        ).toBeNull();
      },
    );

    it('never throws for a null byte in the middle of an otherwise correctly long id field, instead of crashing', () => {
      // A null byte at any position must not let the pattern "terminate early" (the classic
      // C-string mix-up) — JS strings/regexes are length-based, not NUL-terminated, so the pattern
      // must still reject correctly.
      const withNullByte = '1'.repeat(31) + '\x00'; // 32 characters long, the last one is a null byte.
      expect(() =>
        decodeMessageContent(
          JSON.stringify({v: 1, type: 'text', id: withNullByte, body: 'x'}),
        ),
      ).not.toThrow();
      expect(
        decodeMessageContent(
          JSON.stringify({v: 1, type: 'text', id: withNullByte, body: 'x'}),
        ),
      ).toBeNull();
    });
  });
});
