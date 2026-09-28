// attachmentCrypto.ts — Encryption of the actual attachment bytes (image/file), separate from the
// session ratchet (session.ts). Reason: the ratchet is designed for individual, short, strictly
// numbered messages (one sequence number per call) — an attachment several MB in size would not
// fit into it cleanly and would have to keep the ratchet state for a single "message" open over a
// long, multi-part transfer. Instead, EVERY attachment gets its own single-use, purely random key
// (no relation to identity or session); this key itself then travels — small, like any other
// message content — encrypted/authenticated as usual by the session ratchet to the contact (see
// the 'media' content in messageContent.ts). The actual (often large) attachment bytes run
// separately over the attachment transfer, split into several frames but encrypted as ONE AEAD
// operation (XChaCha20-Poly1305 has no block-size problem with several MB).
import {xchacha20poly1305} from '@noble/ciphers/chacha.js';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
} from '@noble/hashes/utils.js';

const KEY_LENGTH = 32;
const NONCE_LENGTH = 24; // XChaCha20 — safe for random nonces
const AEAD_TAG_LENGTH = 16; // Poly1305

// Fixed size overhead that encryptAttachment ALWAYS adds to the plaintext (nonce + AEAD tag) —
// exported so that callers that must check the encrypted blob size against an upper bound derived
// from the plaintext (`declaredSize` comes from the 'media' announcement and denotes the
// plaintext size) know the right comparison value — without this overhead, EVERY transfer would
// wrongly be rejected as "over the limit", because the bytes actually transferred are always
// slightly larger than the announced plaintext.
export const ATTACHMENT_ENCRYPTION_OVERHEAD_BYTES =
  NONCE_LENGTH + AEAD_TAG_LENGTH;

export function generateAttachmentKey(): string {
  return bytesToHex(randomBytes(KEY_LENGTH));
}

// The nonce is prepended to the ciphertext instead of being transported separately — that way the
// attachment stays ONE single byte blob on the transport path, which is simply split into
// chunks/reassembled without having to carry another field through the protocol.
// `associatedData` binds the encryption to the (not secret, but integrity-relevant) transferId —
// an attacker thus cannot silently reuse/redirect the ciphertext of ONE transfer under the
// transferId of ANOTHER, even if they observed both ciphertexts (without knowing the key).
export function encryptAttachment(
  key: string,
  plaintext: Uint8Array,
  associatedData: string,
): Uint8Array {
  const nonce = randomBytes(NONCE_LENGTH);
  const ciphertext = xchacha20poly1305(
    hexToBytes(key),
    nonce,
    new TextEncoder().encode(associatedData),
  ).encrypt(plaintext);
  return concatBytes(nonce, ciphertext);
}

// Throws (AEAD authentication fails, or the blob is too short to even contain a nonce) if the
// reassembled blob, key or associatedData do not match exactly — e.g. a manipulated or
// incompletely reassembled ciphertext (the receiving side first collects all chunks of a transfer
// completely before decrypting at all).
export function decryptAttachment(
  key: string,
  nonceAndCiphertext: Uint8Array,
  associatedData: string,
): Uint8Array {
  if (nonceAndCiphertext.length < NONCE_LENGTH) {
    throw new Error('Anhang-Blob ist kürzer als eine Nonce.');
  }
  const nonce = nonceAndCiphertext.subarray(0, NONCE_LENGTH);
  const ciphertext = nonceAndCiphertext.subarray(NONCE_LENGTH);
  return xchacha20poly1305(
    hexToBytes(key),
    nonce,
    new TextEncoder().encode(associatedData),
  ).decrypt(ciphertext);
}
