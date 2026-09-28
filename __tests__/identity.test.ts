/**
 * @format
 */

// react-native-get-random-values accesses a native module that does not exist under Jest.
// For the test, Node's own crypto implementation suffices as a replacement.
jest.mock('react-native-get-random-values', () => {
  const nodeCrypto = require('crypto');
  // @ts-ignore
  global.crypto = nodeCrypto.webcrypto;
});

// react-native-keychain accesses native Android Keystore behavior — replaced for the test by a
// simple in-memory store (see testUtils/keychainMock.ts).
jest.mock('react-native-keychain', () =>
  require('./testUtils/keychainMock').createInMemoryKeychainMock(),
);

import {describe, it, expect} from '@jest/globals';
import {x25519} from '@noble/curves/ed25519.js';
import {createAndStoreIdentity, loadIdentity} from '../src/crypto/identity';

const ONION_V3_PATTERN = /^[a-z2-7]{56}\.onion$/;
const HEX_32_BYTES = /^[0-9a-f]{64}$/;

describe('identity', () => {
  it('creates a specification-conformant Tor v3 onion address from the signing key', async () => {
    const identity = await createAndStoreIdentity();

    expect(identity.signingPublicKey).toMatch(HEX_32_BYTES);
    expect(identity.signingPrivateKey).toMatch(HEX_32_BYTES);
    // 56 Base32 characters encode 32 (public key) + 2 (checksum) + 1 (version) = 35 bytes.
    expect(identity.onionAddress).toMatch(ONION_V3_PATTERN);
  });

  it('creates an independent X25519 key pair for encryption', async () => {
    const identity = await createAndStoreIdentity();

    expect(identity.encryptionPublicKey).toMatch(HEX_32_BYTES);
    expect(identity.encryptionPrivateKey).toMatch(HEX_32_BYTES);
    // Signing and encryption keys must not be identical (independent pairs).
    expect(identity.encryptionPrivateKey).not.toBe(identity.signingPrivateKey);
  });

  it('the X25519 key pair works for a real ECDH key exchange', async () => {
    const alice = await createAndStoreIdentity();
    const bobSecret = x25519.keygen();

    const sharedByAlice = x25519.getSharedSecret(
      Buffer.from(alice.encryptionPrivateKey, 'hex'),
      bobSecret.publicKey,
    );
    const sharedByBob = x25519.getSharedSecret(
      bobSecret.secretKey,
      Buffer.from(alice.encryptionPublicKey, 'hex'),
    );

    expect(Buffer.from(sharedByAlice).toString('hex')).toBe(
      Buffer.from(sharedByBob).toString('hex'),
    );
  });

  it('creates a new, different identity on every call', async () => {
    const first = await createAndStoreIdentity();
    const second = await createAndStoreIdentity();

    expect(first.signingPrivateKey).not.toBe(second.signingPrivateKey);
    expect(first.encryptionPrivateKey).not.toBe(second.encryptionPrivateKey);
    expect(first.onionAddress).not.toBe(second.onionAddress);
  });

  it('loads a stored identity again with identical keys', async () => {
    const created = await createAndStoreIdentity();
    const loaded = await loadIdentity();

    expect(loaded).not.toBeNull();
    expect(loaded?.signingPublicKey).toBe(created.signingPublicKey);
    expect(loaded?.signingPrivateKey).toBe(created.signingPrivateKey);
    expect(loaded?.encryptionPublicKey).toBe(created.encryptionPublicKey);
    expect(loaded?.encryptionPrivateKey).toBe(created.encryptionPrivateKey);
    expect(loaded?.onionAddress).toBe(created.onionAddress);
  });

  it('returns null when no identity has been stored yet', async () => {
    jest.resetModules();
    jest.doMock('react-native-keychain', () =>
      require('./testUtils/keychainMock').createInMemoryKeychainMock(),
    );
    jest.doMock('react-native-get-random-values', () => {});

    const freshModule = require('../src/crypto/identity');
    await expect(freshModule.loadIdentity()).resolves.toBeNull();
  });
});
