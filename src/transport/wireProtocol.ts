// wireProtocol.ts — Framing for the TCP connection to a contact over Orbot's SOCKS5 tunnel. Pure
// transport framing, no cryptography of its own: the envelope fields actually transferred (nonce,
// ciphertext) are already encrypted/authenticated by src/crypto/session.ts — this module only
// packs them, length-prefixed, for transfer over TCP as a byte stream.
import {Buffer} from 'buffer';
import type {OutgoingEnvelope} from '../crypto/session';
import {HEX_32_BYTES_PATTERN} from '../crypto/validation';
import {diagLog} from '../diagnostics';

// 4-byte big-endian length prefix before every JSON frame.
const LENGTH_PREFIX_BYTES = 4;

// Upper bound for the frame length itself — MUST be checked BEFORE waiting for the announced
// number of bytes/allocating a buffer. Without this bound, a malicious peer (or a
// manipulated/stray TCP stream) could send a huge length value and get the receiver to allocate
// unbounded memory or wait indefinitely for further data (memory/resource DoS). 64 KiB is
// generous enough for an envelope (message text is limited to MAX_MESSAGE_LENGTH, see
// src/crypto/validation.ts) and still small enough not to offer a noticeable attack surface.
export const MAX_FRAME_SIZE = 64 * 1024;

// Fixed application port under which every ONIVEIL onion service is reachable — used both when
// creating the own onion service and when connecting to a contact.
export const ONIVEIL_PROTOCOL_PORT = 8080;

// Maximum raw byte size per attachment chunk, BEFORE Base64 encoding — so a media-chunk frame,
// including JSON structure overhead, safely stays below MAX_FRAME_SIZE. 24 KiB is divisible by 3,
// so Base64 needs no padding characters for it (see MAX_MEDIA_CHUNK_BASE64_LENGTH below).
export const MAX_MEDIA_CHUNK_BYTES = 24 * 1024;

// Base64 instead of hex encoding (hex doubles the raw size, +100% overhead, vs. +33% for Base64) —
// with an already heavily bandwidth-limited Tor, that is a direct factor on the actual transfer
// duration (a screenshot took 4-5 minutes over real Tor with hex), not merely cosmetic.
// `Math.ceil(MAX_MEDIA_CHUNK_BYTES / 3) * 4` is the standard formula for the Base64 output length;
// since MAX_MEDIA_CHUNK_BYTES is divisible by 3, no padding arises, so the bound is exact (no
// additional buffer for '=' characters needed).
const MAX_MEDIA_CHUNK_BASE64_LENGTH = Math.ceil(MAX_MEDIA_CHUNK_BYTES / 3) * 4;

// Structure check for Base64: only the standard alphabet, at most 2 trailing '=' padding
// characters, total length a multiple of 4 (checked separately) — sufficient as defense in depth
// before any attempt is made to decode the string.
const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;

// Upper bound for the number of chunks of a transfer — generously above what an attachment at the
// upper limit (MAX_ATTACHMENT_BYTES, see crypto/messageContent.ts: 50 MiB) plus nonce/AEAD-tag
// overhead actually needs (~2134 at MAX_MEDIA_CHUNK_BYTES), but still finite — prevents a
// maliciously inflated `totalChunks` value from announcing unbounded numbers of chunk slots on its
// own (before the actual size check against the 'media' message).
// IMPORTANT: must grow along with MAX_ATTACHMENT_BYTES — this value was deliberately adjusted when
// MAX_ATTACHMENT_BYTES was raised (15 MiB -> 50 MiB), otherwise every attachment above ~24 MiB
// (1024 * MAX_MEDIA_CHUNK_BYTES) would silently have broken the chunk-count check at the receiver,
// although the actual size check would have allowed it.
const MAX_MEDIA_CHUNKS = 4096;

// Upper bound for the length of a transferId — a pure structure check (no fixed hex-length
// requirement like other IDs, since transferId only serves as a correlation key and does not flow
// directly into cryptographic operations), but it prevents an arbitrarily long string being used
// as a registry/map key.
const MAX_TRANSFER_ID_LENGTH = 128;

// `mac` proves that the responder actually decrypted the message (see crypto/session.ts
// deriveAckKey/computeAckMac). Optional as long as older peers do not send an authenticated
// acknowledgement — the sender requires it once it has seen one from this contact.
export type Frame =
  | {type: 'message'; envelope: OutgoingEnvelope}
  | {type: 'ack'; sequenceNumber: number; mac?: string}
  // One chunk of an attachment transfer — `data` is Base64-encoded (see
  // MAX_MEDIA_CHUNK_BASE64_LENGTH above for the rationale), `transferId` correlates all chunks of
  // a transfer AND must be known to the receiver in advance from a successfully decrypted 'media'
  // message — otherwise arbitrary, unauthenticated connections could cause a memory DoS.
  | {
      type: 'media-chunk';
      transferId: string;
      index: number;
      totalChunks: number;
      data: string;
    }
  | {type: 'media-ack'; transferId: string; mac?: string};

// Strict format check of the envelope fields BEFORE any expensive operation (keychain, X25519,
// Ed25519) is applied to them. Frames are unauthenticated; the earlier an invalid frame is
// discarded, the less computation time a stranger can force.
const NONCE_HEX_PATTERN = /^[0-9a-f]{48}$/; // XChaCha20 nonce, 24 bytes
const CIPHERTEXT_HEX_PATTERN = /^(?:[0-9a-f]{2})+$/;
const INITIAL_FRESHNESS_HEX_PATTERN = /^[0-9a-f]{32}$/; // 16 bytes
const INITIAL_AUTH_HEX_PATTERN = /^[0-9a-f]{128}$/; // Ed25519 signature, 64 bytes
// The Poly1305 tag (16 bytes) is mandatory; an envelope fits into MAX_FRAME_SIZE at the top anyway.
const MIN_CIPHERTEXT_HEX_LENGTH = 32;
const MAX_CIPHERTEXT_HEX_LENGTH = 50_000;
const MAX_SEQUENCE_NUMBER = 2 ** 32;

export class ProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProtocolError';
  }
}

function isOutgoingEnvelope(value: unknown): value is OutgoingEnvelope {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const v = value as Record<string, unknown>;
  if (
    typeof v.sequenceNumber !== 'number' ||
    !Number.isInteger(v.sequenceNumber) ||
    v.sequenceNumber < 0 ||
    v.sequenceNumber > MAX_SEQUENCE_NUMBER ||
    typeof v.nonce !== 'string' ||
    !NONCE_HEX_PATTERN.test(v.nonce) ||
    typeof v.ciphertext !== 'string' ||
    v.ciphertext.length < MIN_CIPHERTEXT_HEX_LENGTH ||
    v.ciphertext.length > MAX_CIPHERTEXT_HEX_LENGTH ||
    !CIPHERTEXT_HEX_PATTERN.test(v.ciphertext) ||
    typeof v.ratchetPublicKey !== 'string' ||
    !HEX_32_BYTES_PATTERN.test(v.ratchetPublicKey)
  ) {
    return false;
  }
  // Optional fields of the first message: if present, exactly in the expected format.
  if (
    v.initialFreshness !== undefined &&
    (typeof v.initialFreshness !== 'string' ||
      !INITIAL_FRESHNESS_HEX_PATTERN.test(v.initialFreshness))
  ) {
    return false;
  }
  if (
    v.initialAuth !== undefined &&
    (typeof v.initialAuth !== 'string' ||
      !INITIAL_AUTH_HEX_PATTERN.test(v.initialAuth))
  ) {
    return false;
  }
  return true;
}

function parseOptionalMac(value: unknown, frameName: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string' || !HEX_32_BYTES_PATTERN.test(value)) {
    throw new ProtocolError(`${frameName}-Frame hat keine gültige mac.`);
  }
  return value;
}

function parseFramePayload(json: unknown): Frame {
  if (typeof json !== 'object' || json === null) {
    throw new ProtocolError('Frame ist kein Objekt.');
  }
  const obj = json as Record<string, unknown>;
  if (obj.type === 'message') {
    if (!isOutgoingEnvelope(obj.envelope)) {
      throw new ProtocolError('message-Frame hat kein gültiges Envelope.');
    }
    return {type: 'message', envelope: obj.envelope};
  }
  if (obj.type === 'ack') {
    if (
      typeof obj.sequenceNumber !== 'number' ||
      !Number.isInteger(obj.sequenceNumber) ||
      obj.sequenceNumber < 0
    ) {
      throw new ProtocolError('ack-Frame hat keine gültige sequenceNumber.');
    }
    return {
      type: 'ack',
      sequenceNumber: obj.sequenceNumber,
      mac: parseOptionalMac(obj.mac, 'ack'),
    };
  }
  if (obj.type === 'media-chunk') {
    if (
      typeof obj.transferId !== 'string' ||
      obj.transferId.length === 0 ||
      obj.transferId.length > MAX_TRANSFER_ID_LENGTH
    ) {
      throw new ProtocolError(
        'media-chunk-Frame hat keine gültige transferId.',
      );
    }
    if (
      typeof obj.totalChunks !== 'number' ||
      !Number.isInteger(obj.totalChunks) ||
      obj.totalChunks < 1 ||
      obj.totalChunks > MAX_MEDIA_CHUNKS
    ) {
      throw new ProtocolError(
        'media-chunk-Frame hat keine gültige totalChunks.',
      );
    }
    if (
      typeof obj.index !== 'number' ||
      !Number.isInteger(obj.index) ||
      obj.index < 0 ||
      obj.index >= obj.totalChunks
    ) {
      throw new ProtocolError('media-chunk-Frame hat keinen gültigen index.');
    }
    if (
      typeof obj.data !== 'string' ||
      obj.data.length === 0 ||
      obj.data.length > MAX_MEDIA_CHUNK_BASE64_LENGTH ||
      obj.data.length % 4 !== 0 ||
      !BASE64_PATTERN.test(obj.data)
    ) {
      throw new ProtocolError('media-chunk-Frame hat keine gültigen Daten.');
    }
    return {
      type: 'media-chunk',
      transferId: obj.transferId,
      index: obj.index,
      totalChunks: obj.totalChunks,
      data: obj.data,
    };
  }
  if (obj.type === 'media-ack') {
    if (
      typeof obj.transferId !== 'string' ||
      obj.transferId.length === 0 ||
      obj.transferId.length > MAX_TRANSFER_ID_LENGTH
    ) {
      throw new ProtocolError('media-ack-Frame hat keine gültige transferId.');
    }
    return {
      type: 'media-ack',
      transferId: obj.transferId,
      mac: parseOptionalMac(obj.mac, 'media-ack'),
    };
  }
  throw new ProtocolError(`Unbekannter Frame-Typ: ${String(obj.type)}`);
}

export function encodeFrame(frame: Frame): Buffer {
  const payload = Buffer.from(JSON.stringify(frame), 'utf8');
  if (payload.length > MAX_FRAME_SIZE) {
    // Own outgoing frame too large — a programming error, or an envelope that bypassed the
    // validation limits of the messaging layer. Better to fail loudly here than to send a frame
    // that the other side would treat as a protocol violation.
    throw new ProtocolError('Ausgehendes Frame überschreitet MAX_FRAME_SIZE.');
  }
  const header = Buffer.alloc(LENGTH_PREFIX_BYTES);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

// Stateful decoder for the TCP byte stream: `data` events deliver arbitrary chunk boundaries (a
// frame can be spread over several chunks, or one chunk can contain several frames) — this buffer
// turns them into complete, parsed frames.
export class FrameDecoder {
  private buffer: Buffer = Buffer.alloc(0);

  // Throws ProtocolError as soon as an announced frame exceeds MAX_FRAME_SIZE — the caller should
  // close the connection immediately in that case instead of continuing to trust it.
  push(chunk: Buffer): Frame[] {
    // For diagnostics only (see the catch below): how many bytes were already buffered BEFORE this
    // call? A value > 0 proves that this chunk does not begin at byte offset 0 of a new frame —
    // exactly what a pure chunk-by-chunk view on the caller side cannot show (there one only ever
    // sees the CURRENT chunk).
    const bufferedBeforeThisChunk = this.buffer.length;
    this.buffer = Buffer.concat([this.buffer, chunk]);
    const frames: Frame[] = [];

    for (;;) {
      if (this.buffer.length < LENGTH_PREFIX_BYTES) {
        break;
      }
      const length = this.buffer.readUInt32BE(0);
      if (length > MAX_FRAME_SIZE) {
        throw new ProtocolError(
          `Angekündigte Frame-Länge (${length}) überschreitet MAX_FRAME_SIZE (${MAX_FRAME_SIZE}).`,
        );
      }
      const totalLength = LENGTH_PREFIX_BYTES + length;
      if (this.buffer.length < totalLength) {
        break; // Frame not completely arrived yet — wait for more data.
      }

      // BUGFIX (found live on a real device): the 'buffer' polyfill package turns a Uint8Array into
      // a "Buffer" via Object.setPrototypeOf() — but it does NOT override .subarray() itself, which
      // stays the native TypedArray method. The construction of its return value
      // (SpeciesConstructor) is engine-dependent: under Node/V8 (Jest) the result remains a real
      // Buffer, under Hermes (real device) it reproducibly degrades to a PLAIN Uint8Array, whose
      // own .toString() method silently ignores the 'utf8' argument (TypedArray.prototype.toString
      // does an Array.prototype.join(',')) — JSON.parse then receives a comma-separated list of
      // decimal numbers instead of real text and is GUARANTEED to fail, although the raw bytes
      // themselves contain perfectly valid JSON (proven by reproducing it manually on a real
      // device with additional diagnostic logging). Buffer.from(...) always builds a real,
      // correctly prototyped instance, independent of engine behavior.
      const payload = Buffer.from(
        this.buffer.subarray(LENGTH_PREFIX_BYTES, totalLength),
      );
      this.buffer = Buffer.from(this.buffer.subarray(totalLength));

      let json: unknown;
      try {
        json = JSON.parse(payload.toString('utf8'));
      } catch {
        // A dedicated error type instead of the raw SyntaxError — callers handle all protocol
        // violations uniformly via ProtocolError, not via arbitrary error types.
        diagLog(
          `oniveil[diag]: FrameDecoder: JSON.parse fehlgeschlagen. Bereits gepuffert vor diesem chunk=${bufferedBeforeThisChunk} Bytes, dieser chunk=${chunk.length} Bytes, angekündigte Länge=${length}, tatsächlicher payload=${JSON.stringify(payload.toString('utf8'))}`,
        );
        throw new ProtocolError('Frame enthält kein gültiges JSON.');
      }
      frames.push(parseFramePayload(json));
    }

    return frames;
  }
}
