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
import {deleteSession, getSession, saveSession} from '../src/storage/sessions';
import type {Session} from '../src/crypto/session';

const SAMPLE_SESSION: Session = {
  rootKey: '00'.repeat(32),
  sendingChainKey: '11'.repeat(32),
  receivingChainKey: '22'.repeat(32),
  myStaticPublicKey: '77'.repeat(32),
  theirStaticPublicKey: '88'.repeat(32),
  sendCounter: 3,
  receiveCounter: 5,
  myRatchetPrivateKey: '44'.repeat(32),
  myRatchetPublicKey: '55'.repeat(32),
  theirRatchetPublicKey: '66'.repeat(32),
  sendingChainRatchetedForTheirKey: '66'.repeat(32),
  receivingChainRatchetedForTheirKey: '66'.repeat(32),
  amLower: true,
};

beforeEach(async () => {
  await AsyncStorage.clear();
});

describe('sessions store', () => {
  it('returns null for a contact without a session', async () => {
    await expect(getSession('contact-1')).resolves.toBeNull();
  });

  it('saves and loads a session unchanged', async () => {
    await saveSession('contact-1', SAMPLE_SESSION);
    await expect(getSession('contact-1')).resolves.toEqual(SAMPLE_SESSION);
  });

  it('manages the sessions of several contacts independently of each other', async () => {
    const otherSession: Session = {...SAMPLE_SESSION, sendCounter: 99};
    await saveSession('contact-1', SAMPLE_SESSION);
    await saveSession('contact-2', otherSession);

    await expect(getSession('contact-1')).resolves.toEqual(SAMPLE_SESSION);
    await expect(getSession('contact-2')).resolves.toEqual(otherSession);
  });

  it('treats a session in the old (pre-Double-Ratchet) format as non-existent', async () => {
    // Regression test: before the Double-Ratchet changeover, a stored session had only
    // sendingChainKey/receivingChainKey/sendCounter/receiveCounter — without the isValidSession
    // check in getSession(), the first hexToBytes(undefined) on one of the new fields would crash
    // instead of (as here) simply building a fresh session.
    const oldShapeSession = {
      sendingChainKey: '11'.repeat(32),
      receivingChainKey: '22'.repeat(32),
      sendCounter: 3,
      receiveCounter: 5,
    };
    await saveSession('contact-1', oldShapeSession as unknown as Session);

    await expect(getSession('contact-1')).resolves.toBeNull();
  });

  it('deletes the session of a contact without touching others', async () => {
    const otherSession: Session = {...SAMPLE_SESSION, sendCounter: 99};
    await saveSession('contact-1', SAMPLE_SESSION);
    await saveSession('contact-2', otherSession);

    await deleteSession('contact-1');

    await expect(getSession('contact-1')).resolves.toBeNull();
    await expect(getSession('contact-2')).resolves.toEqual(otherSession);
  });

  it('stores each contact under its own key (no global blob any more) and does not touch any other when saving one contact', async () => {
    await saveSession('contact-1', SAMPLE_SESSION);
    await saveSession('contact-2', {...SAMPLE_SESSION, sendCounter: 99});

    const keys = await AsyncStorage.getAllKeys();
    expect(keys).toContain('oniveil:sessions:contact-1');
    expect(keys).toContain('oniveil:sessions:contact-2');
    expect(keys).not.toContain('oniveil:sessions');

    // AsyncStorage.setItem is already a jest.fn() itself in the Jest mock — jest.spyOn() returns
    // the same instance with its already existing call history, hence reset explicitly here to
    // really count only the ONE call under examination below.
    const setItemSpy = jest.spyOn(AsyncStorage, 'setItem');
    setItemSpy.mockClear();
    await saveSession('contact-1', {...SAMPLE_SESSION, sendCounter: 100});
    expect(setItemSpy).toHaveBeenCalledTimes(1);
    expect(setItemSpy).toHaveBeenCalledWith(
      'oniveil:sessions:contact-1',
      expect.anything(),
    );
    // Deliberately NO mockRestore() — it would damage the underlying, already pre-existing
    // jest.fn() implementation of AsyncStorage.setItem for the rest of this test file (see the
    // comment above on jest.spyOn on an already existing mock).
  });

  it('rejects a session whose ciphertext actually belongs to a DIFFERENT contact although the same key fits (context binding after the split into per-contact keys)', async () => {
    // Before the storage split, all sessions lay under ONE key — a swap was meaningless. After
    // the split into per-contact keys (the same vaultKey for all), a ciphertext stored in the
    // wrong place but otherwise valid would decrypt without complaint without a context binding —
    // only to the wrong session. Simulated here directly at the AsyncStorage level (no API needed
    // for that, which is the point: the context binding applies independently of HOW the
    // ciphertext got to the wrong place).
    await saveSession('contact-1', SAMPLE_SESSION);
    const stolenBlob = await AsyncStorage.getItem('oniveil:sessions:contact-1');
    await AsyncStorage.setItem('oniveil:sessions:contact-2', stolenBlob!);

    await expect(getSession('contact-2')).rejects.toThrow();
  });
});
