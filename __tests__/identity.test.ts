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

jest.mock('@react-native-async-storage/async-storage', () =>
  require('@react-native-async-storage/async-storage/jest/async-storage-mock'),
);

import {describe, it, expect, beforeEach} from '@jest/globals';
import AsyncStorage from '@react-native-async-storage/async-storage';
import {x25519} from '@noble/curves/ed25519.js';
import * as Keychain from 'react-native-keychain';
import {
  createAndStoreIdentity,
  IdentityMissingError,
  loadIdentity,
} from '../src/crypto/identity';

const ONION_V3_PATTERN = /^[a-z2-7]{56}\.onion$/;
const HEX_32_BYTES = /^[0-9a-f]{64}$/;

beforeEach(async () => {
  await AsyncStorage.clear();
  await Keychain.resetGenericPassword({service: 'oniveil-identity'});
});

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

  it('creates a new, different identity on every explicitly allowed call', async () => {
    const first = await createAndStoreIdentity();
    const second = await createAndStoreIdentity({allowReplace: true});

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

  describe('protection against silent replacement', () => {
    it('creates an identity without history and sets the marker', async () => {
      const identity = await createAndStoreIdentity();

      expect(identity.onionAddress).toMatch(ONION_V3_PATTERN);
      expect(await AsyncStorage.getItem('oniveil:identity-ever-created')).toBe('1');
    });

    it('refuses a new identity when the keystore does not return one although one existed here', async () => {
      await createAndStoreIdentity();
      // The keystore temporarily reports the entry as "not present".
      await Keychain.resetGenericPassword({service: 'oniveil-identity'});

      await expect(loadIdentity()).resolves.toBeNull();
      await expect(createAndStoreIdentity()).rejects.toBeInstanceOf(
        IdentityMissingError,
      );
    });

    it('also protects an older installation without the marker if it already had a vault key', async () => {
      await AsyncStorage.setItem('oniveil:vault-key-ever-created', '1');

      await expect(createAndStoreIdentity()).rejects.toBeInstanceOf(
        IdentityMissingError,
      );
    });

    it('replaces the identity only with explicit permission', async () => {
      const first = await createAndStoreIdentity();
      await Keychain.resetGenericPassword({service: 'oniveil-identity'});

      const second = await createAndStoreIdentity({allowReplace: true});

      expect(second.signingPublicKey).not.toBe(first.signingPublicKey);
      await expect(loadIdentity()).resolves.toMatchObject({
        signingPublicKey: second.signingPublicKey,
      });
    });

    it('backfills the marker when loading an existing identity', async () => {
      await createAndStoreIdentity();
      await AsyncStorage.removeItem('oniveil:identity-ever-created');

      await loadIdentity();
      await new Promise(resolve => setImmediate(resolve));

      expect(await AsyncStorage.getItem('oniveil:identity-ever-created')).toBe('1');
    });
  });
});
