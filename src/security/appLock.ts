// appLock.ts — Optional app lock: demands a successful biometric or device-credential check on
// opening/returning from the background (see src/crypto/keychainOptions.ts). Protects against
// the most realistic threat — brief physical access to an already unlocked device —, not against
// a determined attacker with full device access: the vault key and identity keys are stored with
// the hardened options (hardware-backed Keystore, but WITHOUT `accessControl`), i.e. they are not
// cryptographically bound to this lock. The lock is a gate in the app flow, not a key-derivation
// factor.
//
// The stored value is deliberately not a real secret, just a random marker — the actual check is
// done by the operating system via `accessControl` when this entry is read.
import * as Keychain from 'react-native-keychain';
import {bytesToHex, randomBytes} from '@noble/hashes/utils.js';
import {appLockGetOptions, appLockSetOptions} from '../crypto/keychainOptions';

const APP_LOCK_SERVICE = 'oniveil-app-lock';

export async function isAppLockEnabled(): Promise<boolean> {
  return Keychain.hasGenericPassword({service: APP_LOCK_SERVICE});
}

// Throws with a message understandable for the settings UI if the device has neither biometrics
// nor a device credential set up (the operating system itself then refuses to create the
// access-protected entry).
export async function enableAppLock(): Promise<void> {
  const marker = bytesToHex(randomBytes(16));
  let result: false | Keychain.Result;
  try {
    result = await Keychain.setGenericPassword(
      'app-lock',
      marker,
      appLockSetOptions(APP_LOCK_SERVICE),
    );
  } catch {
    throw new Error(
      'App-Sperre konnte nicht aktiviert werden — hat dieses Gerät Bildschirmsperre (Code, Muster, Fingerabdruck o.ä.) eingerichtet?',
    );
  }
  if (!result) {
    throw new Error('App-Sperre konnte nicht aktiviert werden.');
  }
}

export async function disableAppLock(): Promise<void> {
  await Keychain.resetGenericPassword({service: APP_LOCK_SERVICE});
}

// true only after a check that actually succeeded at the operating-system level. Every failure —
// cancelled by the user, wrong biometric, any other error — deliberately leads to `false`
// (fail-closed) instead of passing the error on: the calling UI need not distinguish between the
// many possible failure causes, only between "unlocked" and "still locked".
export async function verifyAppLock(): Promise<boolean> {
  try {
    const result = await Keychain.getGenericPassword(
      appLockGetOptions(APP_LOCK_SERVICE, 'ONIVEIL entsperren'),
    );
    return result !== false;
  } catch {
    return false;
  }
}

// Purely informational for the settings UI (e.g. "fingerprint available") — does not affect
// whether the lock can be enabled, since BIOMETRY_ANY_OR_DEVICE_PASSCODE falls back to the device
// credential anyway.
export async function getBiometryTypeLabel(): Promise<string | null> {
  const type = await Keychain.getSupportedBiometryType();
  switch (type) {
    case Keychain.BIOMETRY_TYPE.FINGERPRINT:
      return 'Fingerabdruck';
    case Keychain.BIOMETRY_TYPE.FACE:
    case Keychain.BIOMETRY_TYPE.FACE_ID:
      return 'Gesichtserkennung';
    case Keychain.BIOMETRY_TYPE.IRIS:
      return 'Iris-Scan';
    case Keychain.BIOMETRY_TYPE.TOUCH_ID:
      return 'Touch ID';
    case Keychain.BIOMETRY_TYPE.OPTIC_ID:
      return 'Optic ID';
    default:
      return null;
  }
}
