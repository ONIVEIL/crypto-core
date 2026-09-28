/**
 * @format
 */

jest.mock('react-native-get-random-values', () => {
  const nodeCrypto = require('crypto');
  // @ts-ignore
  global.crypto = nodeCrypto.webcrypto;
});

jest.mock('react-native-keychain', () =>
  require('./testUtils/keychainMock').createInMemoryKeychainMock(),
);

jest.mock('@react-native-async-storage/async-storage', () =>
  require('@react-native-async-storage/async-storage/jest/async-storage-mock'),
);

import {describe, it, expect} from '@jest/globals';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Keychain from 'react-native-keychain';
import {getOrCreateVaultKey, VAULT_KEYCHAIN_SERVICE} from '../src/storage/vaultKey';

const mockGetGenericPassword = Keychain.getGenericPassword as jest.MockedFunction<
  typeof Keychain.getGenericPassword
>;

describe('vaultKey', () => {
  it('creates a 256-bit key', async () => {
    const key = await getOrCreateVaultKey();
    expect(key).toHaveLength(32);
  });

  it('returns the same key on repeated calls (persistence)', async () => {
    const first = await getOrCreateVaultKey();
    const second = await getOrCreateVaultKey();
    expect(Buffer.from(second)).toEqual(Buffer.from(first));
  });

  it('returns the same key for SIMULTANEOUS first calls (empty keychain state) instead of creating one each (race fix)', async () => {
    // Reset so that this case really tests the "no key yet" starting situation — the previous
    // tests in the same module already created a key, which would otherwise hide the actual race
    // condition (creation path). The "already created once" marker must be reset as well (see the
    // test below), otherwise this truly empty starting situation would wrongly be interpreted as
    // a "vanished key" and an error thrown instead of creating a new key.
    await Keychain.resetGenericPassword({service: VAULT_KEYCHAIN_SERVICE});
    await AsyncStorage.removeItem('oniveil:vault-key-ever-created');

    // Without serialization, two parallel first calls (e.g. several screens loading at the same
    // time on the very first app start) could both see "no key yet" and each create their OWN
    // random key — the second write would overwrite the first, making everything already
    // encrypted with the first (now lost) key permanently undecryptable.
    const [first, second, third] = await Promise.all([
      getOrCreateVaultKey(),
      getOrCreateVaultKey(),
      getOrCreateVaultKey(),
    ]);
    expect(Buffer.from(second)).toEqual(Buffer.from(first));
    expect(Buffer.from(third)).toEqual(Buffer.from(first));
  });

  it('creates NO new key (and throws instead) when the vault key is suddenly reported "not found" after having already been created', async () => {
    // A real symptom complex observed on a real device: stored values (e.g. the reachable onion
    // address) "vanish" for no apparent reason, although nothing in the code ever deletes them. A
    // possible cause: an Android Keystore entry can transiently come back as "not found" because
    // of OS/hardware quirks although it does exist — the old (naive) logic would have interpreted
    // that as "never created" and SILENTLY created a new key, making everything encrypted with the
    // old key permanently undecryptable without an error ever being visible.
    const original = await getOrCreateVaultKey();

    mockGetGenericPassword.mockResolvedValueOnce(false);
    await expect(getOrCreateVaultKey()).rejects.toThrow();

    // The actual, already existing key must not have been overwritten by this.
    const stillOriginal = await getOrCreateVaultKey();
    expect(Buffer.from(stillOriginal)).toEqual(Buffer.from(original));
  });
});
