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

import {describe, it, expect, beforeEach} from '@jest/globals';
import AsyncStorage from '@react-native-async-storage/async-storage';
import {checkAndRecordInitialFreshness} from '../src/storage/consumedInitialFreshness';

beforeEach(async () => {
  await AsyncStorage.clear();
});

describe('consumedInitialFreshness store (KCI/reset hardening)', () => {
  it('accepts a freshness that was never used for a peer', async () => {
    await expect(
      checkAndRecordInitialFreshness('peer-a'.padEnd(64, '0'), 'fresh-1'),
    ).resolves.toBe(true);
  });

  it('rejects, on the second attempt, a freshness already consumed for the same peer', async () => {
    const peer = 'peer-a'.padEnd(64, '0');
    await expect(
      checkAndRecordInitialFreshness(peer, 'fresh-1'),
    ).resolves.toBe(true);
    // Replay of the same freshness — exactly the scenario an attacker would try after a
    // deleteContact() + re-adding the contact: presenting the same, once genuine
    // (freshness, signature) pair again.
    await expect(
      checkAndRecordInitialFreshness(peer, 'fresh-1'),
    ).resolves.toBe(false);
  });

  it('treats different freshness values of the same peer independently of each other', async () => {
    const peer = 'peer-a'.padEnd(64, '0');
    await expect(
      checkAndRecordInitialFreshness(peer, 'fresh-1'),
    ).resolves.toBe(true);
    await expect(
      checkAndRecordInitialFreshness(peer, 'fresh-2'),
    ).resolves.toBe(true);
    // fresh-1 still stays consumed.
    await expect(
      checkAndRecordInitialFreshness(peer, 'fresh-1'),
    ).resolves.toBe(false);
  });

  it('treats different peers completely independently of each other (the same freshness does not collide across peers)', async () => {
    const peerA = 'peer-a'.padEnd(64, '0');
    const peerB = 'peer-b'.padEnd(64, '0');
    await expect(
      checkAndRecordInitialFreshness(peerA, 'fresh-1'),
    ).resolves.toBe(true);
    // The same freshness at a DIFFERENT peer is an independent event, not a reuse — every peer has
    // its own freshness universe.
    await expect(
      checkAndRecordInitialFreshness(peerB, 'fresh-1'),
    ).resolves.toBe(true);
  });

  it('stays consistent across several successive calls (no read-then-write window)', async () => {
    const peer = 'peer-a'.padEnd(64, '0');
    const results = await Promise.all([
      checkAndRecordInitialFreshness(peer, 'race'),
      checkAndRecordInitialFreshness(peer, 'race'),
      checkAndRecordInitialFreshness(peer, 'race'),
    ]);
    // EXACTLY ONE of the three concurrent attempts with identical freshness may pass as "new" —
    // withCollectionLock serializes the operation, see storage/consumedInitialFreshness.ts.
    expect(results.filter(r => r === true)).toHaveLength(1);
    expect(results.filter(r => r === false)).toHaveLength(2);
  });
});
