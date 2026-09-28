/**
 * @format
 */

jest.mock('@react-native-async-storage/async-storage', () =>
  require('@react-native-async-storage/async-storage/jest/async-storage-mock'),
);

import {describe, it, expect, beforeEach} from '@jest/globals';
import AsyncStorage from '@react-native-async-storage/async-storage';
import {
  CURRENT_SCHEMA_VERSION,
  getSchemaVersion,
  markSchemaVersion,
} from '../src/storage/schemaVersion';

beforeEach(async () => {
  await AsyncStorage.clear();
});

describe('schemaVersion', () => {
  it('returns 1 (implicit legacy state) as long as nothing was ever written', async () => {
    await expect(getSchemaVersion()).resolves.toBe(1);
  });

  it('returns the most recently set value', async () => {
    await markSchemaVersion(CURRENT_SCHEMA_VERSION);
    await expect(getSchemaVersion()).resolves.toBe(CURRENT_SCHEMA_VERSION);
  });

  it('stores the marker as plaintext (no sensitive data, no vault key needed)', async () => {
    await markSchemaVersion(2);
    await expect(AsyncStorage.getItem('oniveil:schemaVersion')).resolves.toBe(
      '2',
    );
  });
});
