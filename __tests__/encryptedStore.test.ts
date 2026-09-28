/**
 * @format
 */

// react-native-get-random-values accesses a native module that does not exist under Jest.
jest.mock('react-native-get-random-values', () => {
  const nodeCrypto = require('crypto');
  // @ts-ignore
  global.crypto = nodeCrypto.webcrypto;
});

jest.mock('@react-native-async-storage/async-storage', () =>
  require('@react-native-async-storage/async-storage/jest/async-storage-mock'),
);

import {describe, it, expect, beforeEach} from '@jest/globals';
import AsyncStorage from '@react-native-async-storage/async-storage';
import {randomBytes} from '@noble/hashes/utils.js';
import {
  decodeEncrypted,
  encryptBlob,
  readEncrypted,
  writeEncrypted,
} from '../src/storage/encryptedStore';

const STORAGE_KEY = 'test:collection';

interface Item {
  id: string;
  value: string;
}

beforeEach(async () => {
  await AsyncStorage.clear();
});

describe('encryptedStore', () => {
  it('returns an empty list when nothing has been stored yet', async () => {
    const key = randomBytes(32);
    await expect(readEncrypted<Item[]>(STORAGE_KEY, key, [])).resolves.toEqual(
      [],
    );
  });

  it('writes and reads back a collection unchanged (round trip)', async () => {
    const key = randomBytes(32);
    const items: Item[] = [
      {id: '1', value: 'hallo'},
      {id: '2', value: 'welt'},
    ];

    await writeEncrypted(STORAGE_KEY, key, items);
    await expect(readEncrypted<Item[]>(STORAGE_KEY, key, [])).resolves.toEqual(
      items,
    );
  });

  it('stores only ciphertext, not the plaintext data', async () => {
    const key = randomBytes(32);
    await writeEncrypted(STORAGE_KEY, key, [{id: '1', value: 'geheim'}]);

    const raw = await AsyncStorage.getItem(STORAGE_KEY);
    expect(raw).not.toContain('geheim');
  });

  it('rejects reading with a wrong key', async () => {
    const key = randomBytes(32);
    const wrongKey = randomBytes(32);
    await writeEncrypted(STORAGE_KEY, key, [{id: '1', value: 'geheim'}]);

    await expect(
      readEncrypted<Item[]>(STORAGE_KEY, wrongKey, []),
    ).rejects.toThrow();
  });

  it('detects tampered stored data (authentication fails)', async () => {
    const key = randomBytes(32);
    await writeEncrypted(STORAGE_KEY, key, [{id: '1', value: 'geheim'}]);

    const raw = await AsyncStorage.getItem(STORAGE_KEY);
    expect(raw).not.toBeNull();
    // Flip one hex character in the stored blob to simulate tampering.
    const tampered = raw!.slice(0, -1) + (raw!.slice(-1) === '0' ? '1' : '0');
    await AsyncStorage.setItem(STORAGE_KEY, tampered);

    await expect(readEncrypted<Item[]>(STORAGE_KEY, key, [])).rejects.toThrow();
  });

  it('leaves a write that did not actually arrive unnoticed by default (no verify requested)', async () => {
    // Default behavior (no `options.verify`): no read-back, as for all ~30 existing callers of
    // this function (contacts, messages, sessions, ...) — deliberately so, see the comment in
    // writeEncrypted() for the trade-off (a failure in the middle of a multi-step,
    // session-dependent flow such as message receipt could otherwise do worse than the original,
    // silent loss that the read-back is meant to fix).
    const key = randomBytes(32);
    const setItemSpy = jest
      .spyOn(AsyncStorage, 'setItem')
      .mockResolvedValueOnce(undefined);

    await expect(
      writeEncrypted(STORAGE_KEY, key, [{id: '1', value: 'unbemerkt'}]),
    ).resolves.toBeUndefined();

    setItemSpy.mockRestore();
  });

  it('throws with `verify: true` when the write does not actually arrive, instead of silently reporting success', async () => {
    // A real bug observed on a real device (first fixed only for the reachable onion address): a
    // stored value appeared to be saved successfully but was gone again on the next read, without
    // any error ever being seen. With `verify: true`, writeEncrypted() now reads itself back
    // right after writing and checks the raw ciphertext — AsyncStorage.setItem is mocked here so
    // that its promise resolves "successfully" but actually writes nothing.
    const key = randomBytes(32);
    const setItemSpy = jest
      .spyOn(AsyncStorage, 'setItem')
      .mockResolvedValueOnce(undefined);

    await expect(
      writeEncrypted(STORAGE_KEY, key, [{id: '1', value: 'geht verloren'}], {
        verify: true,
      }),
    ).rejects.toThrow('konnte nicht verifiziert werden');

    setItemSpy.mockRestore();
  });

  describe('encryptBlob/decodeEncrypted with AAD (context binding for encryptedCollection.ts)', () => {
    it('round-trips correctly with matching AAD', () => {
      const key = randomBytes(32);
      const aad = new TextEncoder().encode('oniveil-collection-v1|item|oniveil:messages:c1|m1');
      const blob = encryptBlob(key, new TextEncoder().encode('{"id":"m1"}'), aad);
      expect(decodeEncrypted('m1', key, blob, null, aad)).toEqual({id: 'm1'});
    });

    it('rejects when a DIFFERENT AAD is used on reading than on writing (core of the context binding)', () => {
      const key = randomBytes(32);
      const aadForA = new TextEncoder().encode('oniveil-collection-v1|item|oniveil:messages:c1|m1');
      const aadForB = new TextEncoder().encode('oniveil-collection-v1|item|oniveil:messages:c2|m1');
      const blob = encryptBlob(key, new TextEncoder().encode('{"id":"m1"}'), aadForA);
      expect(() => decodeEncrypted('m1', key, blob, null, aadForB)).toThrow();
    });

    it('stays unchanged for existing callers without AAD (no third argument == explicit undefined)', () => {
      const key = randomBytes(32);
      const blob = encryptBlob(key, new TextEncoder().encode('{"ok":true}'));
      expect(decodeEncrypted('x', key, blob, null)).toEqual({ok: true});
      expect(decodeEncrypted('x', key, blob, null, undefined)).toEqual({ok: true});
    });
  });
});
