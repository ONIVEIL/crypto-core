// onionAddress.ts — Derive a Tor v3 onion address from a raw Ed25519 public key (official Tor
// specification rend-spec-v3). A standalone module instead of part of identity.ts, so that code
// that does NOT load/create an identity and should not pull in any keychain/random-number
// machinery (e.g. the pure input normalization in validation.ts) can use this purely
// mathematical derivation.
import {sha3_256} from '@noble/hashes/sha3.js';

const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

// Unpadded Base32 (RFC 4648) — the format Tor uses for onion addresses.
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }
  return output;
}

function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    result.set(a, offset);
    offset += a.length;
  }
  return result;
}

// Derive a Tor v3 onion address from a public key (specification: Tor rend-spec-v3).
export function deriveOnionAddressFromPublicKey(
  signingPublicKey: Uint8Array,
): string {
  const version = new Uint8Array([0x03]);
  const prefix = new TextEncoder().encode('.onion checksum');
  const checksum = sha3_256(
    concatBytes(prefix, signingPublicKey, version),
  ).slice(0, 2);
  const addressBytes = concatBytes(signingPublicKey, checksum, version);
  return `${base32Encode(addressBytes)}.onion`;
}
