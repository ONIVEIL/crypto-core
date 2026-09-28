// fingerprint.ts — Condenses the public keys of two contacts into a short, human-comparable
// "safety number" (like Signal/WhatsApp). Verifies nothing automatically — the user has to
// compare the displayed number with the contact over a channel independent of the device (in
// person, phone call). If it matches, no man-in-the-middle can have occurred during contact setup
// without being noticed — both sides would otherwise hold different public keys of the respective
// other and arrive at different numbers.
import {sha256} from '@noble/hashes/sha2.js';
import {bytesToHex, utf8ToBytes} from '@noble/hashes/utils.js';

export interface FingerprintKeys {
  signingPublicKey: string;
  encryptionPublicKey: string;
}

// Sorted concatenation (not by "who am I"/"who is the contact"), so both devices independently
// arrive at the same number — same principle as the existing `amLower` ordering at session setup
// (see crypto/session.ts).
export function computeSafetyNumber(
  myKeys: FingerprintKeys,
  theirKeys: FingerprintKeys,
): string {
  const mine = myKeys.signingPublicKey + myKeys.encryptionPublicKey;
  const theirs = theirKeys.signingPublicKey + theirKeys.encryptionPublicKey;
  const combined = mine < theirs ? mine + theirs : theirs + mine;
  const digest = sha256(utf8ToBytes(combined));
  const hex = bytesToHex(digest);
  // Formatted in groups of 4 — easier to read/read aloud/compare than a continuous hex string,
  // same convention as e.g. GPG fingerprints.
  return (hex.match(/.{1,4}/g) ?? [hex]).join(' ');
}
