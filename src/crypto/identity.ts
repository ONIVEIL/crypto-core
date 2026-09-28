// identity.ts — Creates and stores the app identity:
//   - Ed25519 signing key (derives the Tor v3 onion address)
//   - X25519 encryption key (for ECDH-based message encryption)
// Both key pairs are deliberately generated independently of each other — one key for signatures
// and identity, another for encryption, instead of reusing one key type for both purposes
// (classic crypto best practice: no key reuse across different cryptographic operations).
import 'react-native-get-random-values';
import * as ed from '@noble/ed25519';
import {x25519} from '@noble/curves/ed25519.js';
import {sha512} from '@noble/hashes/sha2.js';
import * as Keychain from 'react-native-keychain';
import {hardenedGetOptions, hardenedSetOptions} from './keychainOptions';
import {deriveOnionAddressFromPublicKey} from './onionAddress';

// @noble/ed25519 v2 needs a SHA-512 implementation supplied from outside (library design, not a bug)
ed.hashes.sha512Async = (m: Uint8Array) => Promise.resolve(sha512(m));

const KEYCHAIN_SERVICE = 'oniveil-identity';
const {bytesToHex, hexToBytes} = ed.etc;

const KEYCHAIN_SET_OPTIONS = hardenedSetOptions(KEYCHAIN_SERVICE);
const KEYCHAIN_GET_OPTIONS = hardenedGetOptions(KEYCHAIN_SERVICE);

export interface Identity {
  onionAddress: string;
  signingPublicKey: string; // Ed25519, hex — onionAddress is derived from it
  signingPrivateKey: string; // Ed25519, hex
  encryptionPublicKey: string; // X25519, hex — for ECDH message encryption
  encryptionPrivateKey: string; // X25519, hex
}

// What actually lies in the keychain entry: only the private keys. The public keys are re-derived
// deterministically on every load instead of being stored redundantly.
interface StoredSecrets {
  signingPrivateKey: string;
  encryptionPrivateKey: string;
}

function buildIdentity(
  signingSecretKey: Uint8Array,
  signingPublicKey: Uint8Array,
  encryptionSecretKey: Uint8Array,
  encryptionPublicKey: Uint8Array,
): Identity {
  return {
    onionAddress: deriveOnionAddressFromPublicKey(signingPublicKey),
    signingPublicKey: bytesToHex(signingPublicKey),
    signingPrivateKey: bytesToHex(signingSecretKey),
    encryptionPublicKey: bytesToHex(encryptionPublicKey),
    encryptionPrivateKey: bytesToHex(encryptionSecretKey),
  };
}

// Creates a new identity (signing + encryption key) and stores the private keys securely
// (Android Keystore via Keychain)
export async function createAndStoreIdentity(): Promise<Identity> {
  const {secretKey: signingSecretKey, publicKey: signingPublicKey} =
    await ed.keygenAsync();
  const {secretKey: encryptionSecretKey, publicKey: encryptionPublicKey} =
    x25519.keygen();

  const stored: StoredSecrets = {
    signingPrivateKey: bytesToHex(signingSecretKey),
    encryptionPrivateKey: bytesToHex(encryptionSecretKey),
  };
  await Keychain.setGenericPassword(
    'identity',
    JSON.stringify(stored),
    KEYCHAIN_SET_OPTIONS,
  );

  return buildIdentity(
    signingSecretKey,
    signingPublicKey,
    encryptionSecretKey,
    encryptionPublicKey,
  );
}

// Loads an already stored identity, if present (e.g. on app restart)
export async function loadIdentity(): Promise<Identity | null> {
  const result = await Keychain.getGenericPassword(KEYCHAIN_GET_OPTIONS);
  if (!result) {
    return null;
  }

  const stored: StoredSecrets = JSON.parse(result.password);
  const signingSecretKey = hexToBytes(stored.signingPrivateKey);
  const encryptionSecretKey = hexToBytes(stored.encryptionPrivateKey);

  const signingPublicKey = await ed.getPublicKeyAsync(signingSecretKey);
  const encryptionPublicKey = x25519.getPublicKey(encryptionSecretKey);

  return buildIdentity(
    signingSecretKey,
    signingPublicKey,
    encryptionSecretKey,
    encryptionPublicKey,
  );
}
