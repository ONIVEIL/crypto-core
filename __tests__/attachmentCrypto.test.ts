/**
 * @format
 */
// @ts-ignore
global.crypto = global.crypto ?? require('crypto').webcrypto;

import {describe, it, expect} from '@jest/globals';
import {
  computeMediaAckMac,
  decryptAttachment,
  deriveMediaAckKey,
  encryptAttachment,
  generateAttachmentKey,
  verifyMediaAckMac,
} from '../src/crypto/attachmentCrypto';

describe('attachment acknowledgement', () => {
  it('accepts the MAC for the right transfer and rejects it for another one', () => {
    const ackKey = deriveMediaAckKey(generateAttachmentKey());
    const mac = computeMediaAckMac(ackKey, 'transfer-1');
    expect(verifyMediaAckMac(ackKey, 'transfer-1', mac)).toBe(true);
    expect(verifyMediaAckMac(ackKey, 'transfer-2', mac)).toBe(false);
  });

  it('rejects a MAC derived from a different attachment key and malformed values', () => {
    const ackKey = deriveMediaAckKey(generateAttachmentKey());
    const otherKey = deriveMediaAckKey(generateAttachmentKey());
    const mac = computeMediaAckMac(otherKey, 'transfer-1');
    expect(verifyMediaAckMac(ackKey, 'transfer-1', mac)).toBe(false);
    expect(verifyMediaAckMac(ackKey, 'transfer-1', 'zz')).toBe(false);
  });
});

describe('attachmentCrypto', () => {
  it('encrypts and decrypts without loss', () => {
    const key = generateAttachmentKey();
    const plaintext = new TextEncoder().encode('hallo anhang');
    const blob = encryptAttachment(key, plaintext, 'transfer-1');

    expect(decryptAttachment(key, blob, 'transfer-1')).toEqual(plaintext);
  });

  it('produces different ciphertexts for the same plaintext (random nonce)', () => {
    const key = generateAttachmentKey();
    const plaintext = new TextEncoder().encode('immer gleich');
    const first = encryptAttachment(key, plaintext, 't');
    const second = encryptAttachment(key, plaintext, 't');

    expect(Buffer.from(first)).not.toEqual(Buffer.from(second));
  });

  it('rejects decryption with the wrong key', () => {
    const key = generateAttachmentKey();
    const otherKey = generateAttachmentKey();
    const blob = encryptAttachment(
      key,
      new TextEncoder().encode('geheim'),
      't',
    );

    expect(() => decryptAttachment(otherKey, blob, 't')).toThrow();
  });

  it('rejects decryption with the wrong associatedData (transferId)', () => {
    const key = generateAttachmentKey();
    const blob = encryptAttachment(
      key,
      new TextEncoder().encode('geheim'),
      't1',
    );

    expect(() => decryptAttachment(key, blob, 't2')).toThrow();
  });

  it('rejects a tampered ciphertext', () => {
    const key = generateAttachmentKey();
    const blob = encryptAttachment(
      key,
      new TextEncoder().encode('geheim'),
      't',
    );
    const tampered = new Uint8Array(blob);
    tampered[tampered.length - 1] ^= 0xff;

    expect(() => decryptAttachment(key, tampered, 't')).toThrow();
  });

  // The nonce is part of the assembled blob (see the comment at encryptAttachment) and enters the
  // AEAD computation as such — a manipulated nonce byte MUST therefore be detected just as
  // reliably as a manipulated ciphertext byte, not merely by chance because it also "shifts" the
  // ciphertext. Tests must cover a byte in the first 24 bytes (the nonce itself), not only one in
  // the ciphertext part.
  it('rejects a blob with a manipulated nonce byte', () => {
    const key = generateAttachmentKey();
    const blob = encryptAttachment(
      key,
      new TextEncoder().encode('geheim'),
      't',
    );
    const tampered = new Uint8Array(blob);
    tampered[0] ^= 0xff; // the first byte is guaranteed to lie within the 24-byte nonce.

    expect(() => decryptAttachment(key, tampered, 't')).toThrow();
  });

  // Key isolation between two different attachments of the same conversation — every attachment
  // gets its own, purely random key with no relation to identity/session (see the
  // generateAttachmentKey comment in attachmentCrypto.ts). It is not enough to show that the two
  // generated key STRINGS differ (that follows trivially from randomBytes) — the decisive part is
  // the NEGATIVE cryptographic proof: attachment A's key must under NO circumstances decrypt
  // attachment B's ciphertext, not even with its own, correct associatedData (transferId).
  it('isolates the keys of two different attachments of the same conversation from each other', () => {
    const keyA = generateAttachmentKey();
    const keyB = generateAttachmentKey();
    expect(keyA).not.toBe(keyB);

    const plaintextA = new TextEncoder().encode('anhang A: urlaubsfoto');
    const plaintextB = new TextEncoder().encode('anhang B: rechnung.pdf');
    const blobA = encryptAttachment(keyA, plaintextA, 'transfer-a');
    const blobB = encryptAttachment(keyB, plaintextB, 'transfer-b');

    // Positive control: each key still correctly decrypts its OWN attachment.
    expect(decryptAttachment(keyA, blobA, 'transfer-a')).toEqual(plaintextA);
    expect(decryptAttachment(keyB, blobB, 'transfer-b')).toEqual(plaintextB);

    // Negative control: attachment A's key cannot decrypt attachment B's ciphertext — even with
    // B's own, correct transferId as associatedData.
    expect(() => decryptAttachment(keyA, blobB, 'transfer-b')).toThrow();
    // ... and vice versa.
    expect(() => decryptAttachment(keyB, blobA, 'transfer-a')).toThrow();
  });

  it('rejects a too-short blob (shorter than a nonce) instead of crashing', () => {
    const key = generateAttachmentKey();
    expect(() => decryptAttachment(key, new Uint8Array(4), 't')).toThrow();
  });

  it('handles a plaintext of several hundred KB correctly (several chunk sizes)', () => {
    const key = generateAttachmentKey();
    const plaintext = new Uint8Array(500 * 1024);
    for (let i = 0; i < plaintext.length; i++) {
      plaintext[i] = i % 256;
    }
    const blob = encryptAttachment(key, plaintext, 'big-transfer');
    expect(decryptAttachment(key, blob, 'big-transfer')).toEqual(plaintext);
  });
});
