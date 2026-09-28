/**
 * @format
 */
import {describe, it, expect, jest, beforeEach} from '@jest/globals';

jest.mock('react-native-keychain', () =>
  require('./testUtils/keychainMock').createInMemoryKeychainMock(),
);

import * as Keychain from 'react-native-keychain';
import {
  disableAppLock,
  enableAppLock,
  getBiometryTypeLabel,
  isAppLockEnabled,
  verifyAppLock,
} from '../src/security/appLock';

const mockSetGenericPassword =
  Keychain.setGenericPassword as jest.MockedFunction<
    typeof Keychain.setGenericPassword
  >;
const mockGetGenericPassword =
  Keychain.getGenericPassword as jest.MockedFunction<
    typeof Keychain.getGenericPassword
  >;
const mockGetSupportedBiometryType =
  Keychain.getSupportedBiometryType as jest.MockedFunction<
    typeof Keychain.getSupportedBiometryType
  >;

beforeEach(() => {
  mockSetGenericPassword.mockClear();
  mockGetGenericPassword.mockClear();
  mockGetSupportedBiometryType.mockClear();
});

describe('appLock', () => {
  it('is not enabled initially', async () => {
    expect(await isAppLockEnabled()).toBe(false);
  });

  it('enables and disables the lock', async () => {
    await enableAppLock();
    expect(await isAppLockEnabled()).toBe(true);

    await disableAppLock();
    expect(await isAppLockEnabled()).toBe(false);
  });

  it('throws an understandable message when the operating system refuses to create the entry', async () => {
    mockSetGenericPassword.mockRejectedValueOnce(new Error('native failure'));
    await expect(enableAppLock()).rejects.toThrow(/Bildschirmsperre/);
  });

  it('throws when the operating system returns false instead of a result', async () => {
    mockSetGenericPassword.mockResolvedValueOnce(false);
    await expect(enableAppLock()).rejects.toThrow(
      'App-Sperre konnte nicht aktiviert werden.',
    );
  });

  it('verifyAppLock returns true after a successful check', async () => {
    await enableAppLock();
    expect(await verifyAppLock()).toBe(true);
  });

  it('verifyAppLock returns false (fail-closed) when the check fails', async () => {
    await enableAppLock();
    mockGetGenericPassword.mockResolvedValueOnce(false);
    expect(await verifyAppLock()).toBe(false);
  });

  it('verifyAppLock returns false (fail-closed) even if the operating system throws (e.g. cancelled by the user)', async () => {
    await enableAppLock();
    mockGetGenericPassword.mockRejectedValueOnce(new Error('user cancelled'));
    expect(await verifyAppLock()).toBe(false);
  });

  it('returns no label when no biometry is supported', async () => {
    mockGetSupportedBiometryType.mockResolvedValueOnce(null);
    expect(await getBiometryTypeLabel()).toBeNull();
  });

  it('translates a supported biometry type into a readable label', async () => {
    mockGetSupportedBiometryType.mockResolvedValueOnce(
      Keychain.BIOMETRY_TYPE.FINGERPRINT,
    );
    expect(await getBiometryTypeLabel()).toBe('Fingerabdruck');
  });
});
