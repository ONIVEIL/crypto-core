/**
 * @format
 */

import {describe, it, expect, jest} from '@jest/globals';
import {Buffer} from 'buffer';

// wireProtocol.ts imports diagnostics.ts (only for the diagnostic log in the JSON.parse failure
// case), which transitively pulls in AsyncStorage (hence the same mock as elsewhere).
jest.mock('@react-native-async-storage/async-storage', () =>
  require('@react-native-async-storage/async-storage/jest/async-storage-mock'),
);

import {
  encodeFrame,
  FrameDecoder,
  MAX_FRAME_SIZE,
  MAX_MEDIA_CHUNK_BYTES,
  ProtocolError,
} from '../src/transport/wireProtocol';

const ENVELOPE = {
  sequenceNumber: 0,
  nonce: 'ab'.repeat(24),
  ciphertext: 'cd'.repeat(24),
  ratchetPublicKey: '33'.repeat(32),
};

describe('wireProtocol', () => {
  it('encodes and decodes a message frame without loss', () => {
    const encoded = encodeFrame({type: 'message', envelope: ENVELOPE});
    const decoder = new FrameDecoder();
    const frames = decoder.push(encoded);

    expect(frames).toEqual([{type: 'message', envelope: ENVELOPE}]);
  });

  it('encodes and decodes an ack frame without loss', () => {
    const encoded = encodeFrame({type: 'ack', sequenceNumber: 7});
    const decoder = new FrameDecoder();
    const frames = decoder.push(encoded);

    expect(frames).toEqual([{type: 'ack', sequenceNumber: 7}]);
  });

  it('processes a frame that arrives spread over several chunks', () => {
    const encoded = encodeFrame({type: 'ack', sequenceNumber: 3});
    const decoder = new FrameDecoder();

    const first = decoder.push(encoded.subarray(0, 2));
    expect(first).toEqual([]);
    const second = decoder.push(encoded.subarray(2));
    expect(second).toEqual([{type: 'ack', sequenceNumber: 3}]);
  });

  it('extracts several frames from a single chunk', () => {
    const combined = Buffer.concat([
      encodeFrame({type: 'ack', sequenceNumber: 1}),
      encodeFrame({type: 'ack', sequenceNumber: 2}),
    ]);
    const decoder = new FrameDecoder();

    const frames = decoder.push(combined);
    expect(frames).toEqual([
      {type: 'ack', sequenceNumber: 1},
      {type: 'ack', sequenceNumber: 2},
    ]);
  });

  it('rejects an announced frame length above MAX_FRAME_SIZE', () => {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(MAX_FRAME_SIZE + 1, 0);
    const decoder = new FrameDecoder();

    expect(() => decoder.push(header)).toThrow(ProtocolError);
  });

  it('rejects an outgoing frame that is too large when encoding', () => {
    const huge = {
      sequenceNumber: 0,
      nonce: 'ab',
      ciphertext: 'x'.repeat(MAX_FRAME_SIZE),
      ratchetPublicKey: '33'.repeat(32),
    };
    expect(() => encodeFrame({type: 'message', envelope: huge})).toThrow(
      ProtocolError,
    );
  });

  it('rejects an unknown frame type', () => {
    const payload = Buffer.from(JSON.stringify({type: 'evil'}), 'utf8');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length, 0);
    const decoder = new FrameDecoder();

    expect(() => decoder.push(Buffer.concat([header, payload]))).toThrow(
      ProtocolError,
    );
  });

  it('rejects a frame with invalid JSON as ProtocolError (not as a raw SyntaxError)', () => {
    const payload = Buffer.from('{kaputt', 'utf8');
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length, 0);
    const decoder = new FrameDecoder();

    expect(() => decoder.push(Buffer.concat([header, payload]))).toThrow(
      ProtocolError,
    );
  });

  it('rejects a message frame with a faulty envelope', () => {
    const payload = Buffer.from(
      JSON.stringify({type: 'message', envelope: {sequenceNumber: 'x'}}),
      'utf8',
    );
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length, 0);
    const decoder = new FrameDecoder();

    expect(() => decoder.push(Buffer.concat([header, payload]))).toThrow(
      ProtocolError,
    );
  });

  it('rejects a message frame with a missing/invalid ratchetPublicKey', () => {
    const payload = Buffer.from(
      JSON.stringify({
        type: 'message',
        envelope: {sequenceNumber: 0, nonce: 'ab', ciphertext: 'cd'},
      }),
      'utf8',
    );
    const header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length, 0);
    const decoder = new FrameDecoder();

    expect(() => decoder.push(Buffer.concat([header, payload]))).toThrow(
      ProtocolError,
    );
  });

  describe('media-chunk / media-ack', () => {
    it('encodes and decodes a media-chunk frame without loss', () => {
      const frame = {
        type: 'media-chunk' as const,
        transferId: 'abc123',
        index: 2,
        totalChunks: 5,
        data: 'ab34',
      };
      const encoded = encodeFrame(frame);
      const decoder = new FrameDecoder();
      expect(decoder.push(encoded)).toEqual([frame]);
    });

    it('encodes and decodes a media-ack frame without loss', () => {
      const frame = {type: 'media-ack' as const, transferId: 'xyz789'};
      const encoded = encodeFrame(frame);
      const decoder = new FrameDecoder();
      expect(decoder.push(encoded)).toEqual([frame]);
    });

    function pushRawFrame(decoder: FrameDecoder, obj: unknown): unknown {
      const payload = Buffer.from(JSON.stringify(obj), 'utf8');
      const header = Buffer.alloc(4);
      header.writeUInt32BE(payload.length, 0);
      return decoder.push(Buffer.concat([header, payload]));
    }

    it('rejects a media-chunk frame with index >= totalChunks', () => {
      const decoder = new FrameDecoder();
      expect(() =>
        pushRawFrame(decoder, {
          type: 'media-chunk',
          transferId: 't1',
          index: 5,
          totalChunks: 5,
          data: 'ab',
        }),
      ).toThrow(ProtocolError);
    });

    it('rejects a media-chunk frame with non-base64 data', () => {
      const decoder = new FrameDecoder();
      expect(() =>
        pushRawFrame(decoder, {
          type: 'media-chunk',
          transferId: 't1',
          index: 0,
          totalChunks: 1,
          // Length 4 (would pass the multiple-of-4 check), but '!' is outside the Base64
          // alphabet — deliberately isolates the character-set check.
          data: '!!!!',
        }),
      ).toThrow(ProtocolError);
    });

    it('rejects a media-chunk frame whose data length exceeds the Base64 upper bound', () => {
      const decoder = new FrameDecoder();
      // Base64 output length for MAX_MEDIA_CHUNK_BYTES raw bytes (see wireProtocol.ts
      // MAX_MEDIA_CHUNK_BASE64_LENGTH) plus one more full group of 4 — thus stays both valid Base64
      // (multiple of 4, valid alphabet) and unambiguously fails ONLY at the size check, not at the
      // character set/length-modulo-4.
      const overLimitLength = Math.ceil(MAX_MEDIA_CHUNK_BYTES / 3) * 4 + 4;
      expect(() =>
        pushRawFrame(decoder, {
          type: 'media-chunk',
          transferId: 't1',
          index: 0,
          totalChunks: 1,
          data: 'A'.repeat(overLimitLength),
        }),
      ).toThrow(ProtocolError);
    });

    it('rejects a media-chunk frame with an empty/missing transferId', () => {
      const decoder = new FrameDecoder();
      expect(() =>
        pushRawFrame(decoder, {
          type: 'media-chunk',
          transferId: '',
          index: 0,
          totalChunks: 1,
          data: 'ab',
        }),
      ).toThrow(ProtocolError);
    });

    it('rejects a media-ack frame with a missing transferId', () => {
      const decoder = new FrameDecoder();
      expect(() => pushRawFrame(decoder, {type: 'media-ack'})).toThrow(
        ProtocolError,
      );
    });
  });

  describe('strict format check', () => {
    function decodeEnvelope(envelope: Record<string, unknown>) {
      const frame = encodeFrame({type: 'message', envelope: envelope as never});
      return () => new FrameDecoder().push(frame);
    }

    it.each([
      ['a nonce of the wrong length', {nonce: 'ab'.repeat(12)}],
      ['a nonce with non-hex characters', {nonce: 'zz'.repeat(24)}],
      ['a ciphertext that is too short (no room for the authentication tag)', {ciphertext: 'ab'.repeat(8)}],
      ['a ciphertext of odd length', {ciphertext: 'a'.repeat(33)}],
      ['a ciphertext with non-hex characters', {ciphertext: 'xy'.repeat(24)}],
      ['a negative sequence number', {sequenceNumber: -1}],
      ['an unreasonably large sequence number', {sequenceNumber: 2 ** 40}],
      ['a freshness value of the wrong length', {initialFreshness: 'ab'}],
      ['a signature of the wrong length', {initialAuth: 'ab'.repeat(10)}],
    ])('rejects an envelope with %s', (_name, override) => {
      expect(decodeEnvelope({...ENVELOPE, ...override})).toThrow(ProtocolError);
    });

    it('accepts a complete first envelope with freshness and signature', () => {
      const envelope = {
        ...ENVELOPE,
        initialFreshness: 'ab'.repeat(16),
        initialAuth: 'cd'.repeat(64),
      };
      expect(decodeEnvelope(envelope)()).toEqual([{type: 'message', envelope}]);
    });
  });

  describe('authenticated acknowledgements', () => {
    it('transports the MAC of a message acknowledgement', () => {
      const frame = encodeFrame({type: 'ack', sequenceNumber: 4, mac: 'ab'.repeat(32)});
      expect(new FrameDecoder().push(frame)).toEqual([
        {type: 'ack', sequenceNumber: 4, mac: 'ab'.repeat(32)},
      ]);
    });

    it('transports the MAC of an attachment acknowledgement', () => {
      const frame = encodeFrame({type: 'media-ack', transferId: 't1', mac: 'cd'.repeat(32)});
      expect(new FrameDecoder().push(frame)).toEqual([
        {type: 'media-ack', transferId: 't1', mac: 'cd'.repeat(32)},
      ]);
    });

    it('still accepts acknowledgements without a MAC (older peer)', () => {
      const frame = encodeFrame({type: 'ack', sequenceNumber: 4});
      expect(new FrameDecoder().push(frame)).toEqual([{type: 'ack', sequenceNumber: 4}]);
    });

    it('rejects a MAC in the wrong format', () => {
      const frame = encodeFrame({type: 'ack', sequenceNumber: 4, mac: 'not-hex'});
      expect(() => new FrameDecoder().push(frame)).toThrow(ProtocolError);
    });
  });
});
