/**
 * @format
 */

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
import {encryptBlob} from '../src/storage/encryptedStore';
import {
  clearCollection,
  collectionIndexKey,
  collectionItemKey,
  readCollectionIndex,
  readCollectionItem,
  readCollectionItems,
  removeCollectionItem,
  writeCollectionIndex,
  writeCollectionItem,
  writeCollectionItemsAndIndex,
  type CollectionIndexRecord,
} from '../src/storage/encryptedCollection';

interface Item {
  id: string;
  value: string;
}
interface Summary {
  lastId: string | null;
}
const EMPTY_SUMMARY: Summary = {lastId: null};
const BASE_KEY = 'oniveil:messages:contact-1';

beforeEach(async () => {
  await AsyncStorage.clear();
});

describe('encryptedCollection', () => {
  it('returns an empty index as long as nothing has been written', async () => {
    const key = randomBytes(32);
    await expect(
      readCollectionIndex(BASE_KEY, key, EMPTY_SUMMARY),
    ).resolves.toEqual({ids: [], summary: EMPTY_SUMMARY});
  });

  it('index round trip: writes and reads back unchanged', async () => {
    const key = randomBytes(32);
    const index: CollectionIndexRecord<Summary> = {
      ids: ['a', 'b'],
      summary: {lastId: 'b'},
    };
    await writeCollectionIndex(BASE_KEY, key, index);
    await expect(
      readCollectionIndex(BASE_KEY, key, EMPTY_SUMMARY),
    ).resolves.toEqual(index);
  });

  it('element round trip: writes and reads back a single element unchanged', async () => {
    const key = randomBytes(32);
    const item: Item = {id: 'm1', value: 'hallo'};
    await writeCollectionItem(BASE_KEY, key, 'm1', item);
    await expect(
      readCollectionItem<Item>(BASE_KEY, key, 'm1'),
    ).resolves.toEqual(item);
  });

  it('returns null for a non-existent element (no error)', async () => {
    const key = randomBytes(32);
    await expect(
      readCollectionItem<Item>(BASE_KEY, key, 'fehlt'),
    ).resolves.toBeNull();
  });

  it('reads several elements in ONE multiGet call, in the order of the IDs passed', async () => {
    const key = randomBytes(32);
    const multiGetSpy = jest.spyOn(AsyncStorage, 'multiGet');
    multiGetSpy.mockClear();
    await writeCollectionItem(BASE_KEY, key, 'm1', {id: 'm1', value: 'eins'});
    await writeCollectionItem(BASE_KEY, key, 'm2', {id: 'm2', value: 'zwei'});
    await writeCollectionItem(BASE_KEY, key, 'm3', {id: 'm3', value: 'drei'});
    multiGetSpy.mockClear();

    const items = await readCollectionItems<Item>(BASE_KEY, key, [
      'm2',
      'm1',
      'm3',
    ]);
    expect(items.map(i => i.id)).toEqual(['m2', 'm1', 'm3']);
    expect(multiGetSpy).toHaveBeenCalledTimes(1);
    // Deliberately NO mockRestore() here: AsyncStorage.multiGet is already a jest.fn() itself in
    // the mock (see async-storage-mock.js) — mockRestore() on a function observed via
    // jest.spyOn() that was a jest.fn() beforehand replaces its implementation with NOTHING
    // (broken for the rest of the file, since the mock module is the same instance across all
    // tests). mockClear() (already done above) suffices to reset only the call history without
    // destroying the implementation.
  });

  it('skips an element listed in the index but actually missing, instead of discarding the whole list', async () => {
    const key = randomBytes(32);
    await writeCollectionItem(BASE_KEY, key, 'm1', {id: 'm1', value: 'eins'});
    // 'm2' deliberately NEVER written — simulates an index/element inconsistency.
    const items = await readCollectionItems<Item>(BASE_KEY, key, ['m1', 'm2']);
    expect(items.map(i => i.id)).toEqual(['m1']);
  });

  it('rejects an EXISTING but tampered element (auth failure still throws)', async () => {
    const key = randomBytes(32);
    await writeCollectionItem(BASE_KEY, key, 'm1', {id: 'm1', value: 'eins'});
    const itemKey = collectionItemKey(BASE_KEY, 'm1');
    const raw = await AsyncStorage.getItem(itemKey);
    const tampered = raw!.slice(0, -1) + (raw!.slice(-1) === '0' ? '1' : '0');
    await AsyncStorage.setItem(itemKey, tampered);

    await expect(readCollectionItem<Item>(BASE_KEY, key, 'm1')).rejects.toThrow();
  });

  it('rejects a tampered index (auth failure still throws)', async () => {
    const key = randomBytes(32);
    await writeCollectionIndex(BASE_KEY, key, {ids: ['m1'], summary: {lastId: 'm1'}});
    const indexKey = collectionIndexKey(BASE_KEY);
    const raw = await AsyncStorage.getItem(indexKey);
    const tampered = raw!.slice(0, -1) + (raw!.slice(-1) === '0' ? '1' : '0');
    await AsyncStorage.setItem(indexKey, tampered);

    await expect(
      readCollectionIndex(BASE_KEY, key, EMPTY_SUMMARY),
    ).rejects.toThrow();
  });

  describe('context binding (AAD): a ciphertext stored in the wrong place but otherwise valid must be detected', () => {
    it('rejects an element whose ciphertext actually belongs to a DIFFERENT collection (baseKey), although the same vaultKey fits', async () => {
      const key = randomBytes(32);
      const otherBaseKey = 'oniveil:messages:contact-2';
      await writeCollectionItem(otherBaseKey, key, 'm1', {
        id: 'm1',
        value: 'gehört zu contact-2',
      });
      // Copy the same ciphertext (valid under otherBaseKey) to the element key OF BASE_KEY —
      // simulates a swap/a bug in cleanup/copy code, or external manipulation of the AsyncStorage
      // database.
      const stolenBlob = await AsyncStorage.getItem(
        collectionItemKey(otherBaseKey, 'm1'),
      );
      await AsyncStorage.setItem(collectionItemKey(BASE_KEY, 'm1'), stolenBlob!);

      await expect(
        readCollectionItem<Item>(BASE_KEY, key, 'm1'),
      ).rejects.toThrow();
    });

    it('rejects an element whose ciphertext belongs to a DIFFERENT ID of the same collection (AAD also binds the itemId)', async () => {
      const key = randomBytes(32);
      await writeCollectionItem(BASE_KEY, key, 'm1', {id: 'm1', value: 'eins'});
      const blobForM1 = await AsyncStorage.getItem(
        collectionItemKey(BASE_KEY, 'm1'),
      );
      // Store the same ciphertext under the element key for 'm2'.
      await AsyncStorage.setItem(collectionItemKey(BASE_KEY, 'm2'), blobForM1!);

      await expect(
        readCollectionItem<Item>(BASE_KEY, key, 'm2'),
      ).rejects.toThrow();
    });

    it('second defense layer: is noticed even if (hypothetically) a ciphertext with correct AAD but a wrong `id` field in the plaintext existed', async () => {
      // Builds the ciphertext directly via encryptBlob with the CORRECT AAD for "m2", but a
      // plaintext object whose `id` field is wrongly "m1" — tests the second, AAD-independent
      // defense layer (assertMatchingId) in isolation from the AAD check itself.
      const key = randomBytes(32);
      const aad = new TextEncoder().encode(
        'oniveil-collection-v1|item|oniveil:messages:contact-1|m2',
      );
      const blob = encryptBlob(
        key,
        new TextEncoder().encode(JSON.stringify({id: 'm1', value: 'falsch'})),
        aad,
      );
      await AsyncStorage.setItem(collectionItemKey(BASE_KEY, 'm2'), blob);

      await expect(
        readCollectionItem<Item>(BASE_KEY, key, 'm2'),
      ).rejects.toThrow('ID-Mismatch');
    });
  });

  it('writeCollectionItemsAndIndex: writes several elements + index in ONE multiSet call', async () => {
    const key = randomBytes(32);
    const multiSetSpy = jest.spyOn(AsyncStorage, 'multiSet');
    multiSetSpy.mockClear();

    await writeCollectionItemsAndIndex<Item, Summary>(
      BASE_KEY,
      key,
      [
        {id: 'm1', value: {id: 'm1', value: 'eins'}},
        {id: 'm2', value: {id: 'm2', value: 'zwei'}},
      ],
      {ids: ['m1', 'm2'], summary: {lastId: 'm2'}},
    );

    expect(multiSetSpy).toHaveBeenCalledTimes(1);
    await expect(
      readCollectionItems<Item>(BASE_KEY, key, ['m1', 'm2']),
    ).resolves.toEqual([
      {id: 'm1', value: 'eins'},
      {id: 'm2', value: 'zwei'},
    ]);
    await expect(
      readCollectionIndex(BASE_KEY, key, EMPTY_SUMMARY),
    ).resolves.toEqual({ids: ['m1', 'm2'], summary: {lastId: 'm2'}});
    // Deliberately no mockRestore() — see the comment at multiGetSpy above, same reason.
  });

  it('removeCollectionItem removes exactly the one element, no others', async () => {
    const key = randomBytes(32);
    await writeCollectionItem(BASE_KEY, key, 'm1', {id: 'm1', value: 'eins'});
    await writeCollectionItem(BASE_KEY, key, 'm2', {id: 'm2', value: 'zwei'});

    await removeCollectionItem(BASE_KEY, 'm1');

    await expect(readCollectionItem<Item>(BASE_KEY, key, 'm1')).resolves.toBeNull();
    await expect(readCollectionItem<Item>(BASE_KEY, key, 'm2')).resolves.toEqual({
      id: 'm2',
      value: 'zwei',
    });
  });

  it('clearCollection removes the index + exactly the elements listed in the index, no foreign keys', async () => {
    const key = randomBytes(32);
    await writeCollectionItem(BASE_KEY, key, 'm1', {id: 'm1', value: 'eins'});
    await writeCollectionItem(BASE_KEY, key, 'm2', {id: 'm2', value: 'zwei'});
    await writeCollectionIndex(BASE_KEY, key, {
      ids: ['m1', 'm2'],
      summary: {lastId: 'm2'},
    });
    // Foreign, independent key — must NOT be touched by clearCollection.
    await AsyncStorage.setItem('oniveil:contacts', 'unberührt');

    const removedIds = await clearCollection(BASE_KEY, key, EMPTY_SUMMARY);
    expect(removedIds.sort()).toEqual(['m1', 'm2']);

    const remainingKeys = await AsyncStorage.getAllKeys();
    expect(remainingKeys).not.toContain(collectionIndexKey(BASE_KEY));
    expect(remainingKeys).not.toContain(collectionItemKey(BASE_KEY, 'm1'));
    expect(remainingKeys).not.toContain(collectionItemKey(BASE_KEY, 'm2'));
    expect(remainingKeys).toContain('oniveil:contacts');
  });

  it('consistency property: after a random sequence of append/remove-style operations, index.ids matches exactly the set of element keys actually present', async () => {
    const key = randomBytes(32);
    let index: CollectionIndexRecord<Summary> = {ids: [], summary: EMPTY_SUMMARY};
    let seed = 42;
    const rand = () => {
      // Simple, reproducible PRNG (mulberry32 style) — no new dependency import needed, same
      // principle as sessionStateMachine.property.test.ts in the same project.
      seed |= 0;
      seed = (seed + 0x6d2b79f5) | 0;
      let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };

    for (let round = 0; round < 100; round++) {
      if (index.ids.length === 0 || rand() < 0.7) {
        const id = `item-${round}`;
        await writeCollectionItem(BASE_KEY, key, id, {id, value: `v${round}`});
        index = {ids: [...index.ids, id], summary: {lastId: id}};
        await writeCollectionIndex(BASE_KEY, key, index);
      } else {
        const removeIdx = Math.floor(rand() * index.ids.length);
        const removedId = index.ids[removeIdx];
        await removeCollectionItem(BASE_KEY, removedId);
        const remainingIds = index.ids.filter((_, i) => i !== removeIdx);
        index = {
          ids: remainingIds,
          summary: {lastId: remainingIds[remainingIds.length - 1] ?? null},
        };
        await writeCollectionIndex(BASE_KEY, key, index);
      }
    }

    const allKeys = await AsyncStorage.getAllKeys();
    const actualItemIds = allKeys
      .filter(k => k.startsWith(`${BASE_KEY}:item:`))
      .map(k => k.slice(`${BASE_KEY}:item:`.length))
      .sort();
    expect(index.ids.slice().sort()).toEqual(actualItemIds);
    expect(new Set(index.ids).size).toBe(index.ids.length); // no duplicate IDs
  });
});
