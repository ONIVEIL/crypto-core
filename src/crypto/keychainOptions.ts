// keychainOptions.ts — Central security policy for all keychain entries of this app:
// hardware-backed Android Keystore for the actual keys (vault/identity), plus, separately, the
// biometric/device-credential-backed access check for the app lock (src/security/appLock.ts) —
// two different purposes, hence separate options functions instead of a shared one.
import * as Keychain from 'react-native-keychain';
import {
  ACCESS_CONTROL,
  SECURITY_LEVEL,
  STORAGE_TYPE,
} from 'react-native-keychain';

export function hardenedSetOptions(service: string): Keychain.SetOptions {
  return {
    service,
    securityLevel: SECURITY_LEVEL.SECURE_HARDWARE,
    storage: STORAGE_TYPE.AES_GCM_NO_AUTH,
  };
}

export function hardenedGetOptions(service: string): Keychain.GetOptions {
  return {service};
}

// The stored value itself is only a meaningless random token (see appLock.ts) — the actual
// security comes from `accessControl`: the operating system demands a successful biometric or
// device-credential check on read before the entry is returned at all. Deliberately uses the
// OS-managed check instead of building a PIN entry ourselves — that is the established, vetted
// way.
export function appLockSetOptions(service: string): Keychain.SetOptions {
  return {
    service,
    accessControl: ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE,
  };
}

export function appLockGetOptions(
  service: string,
  promptTitle: string,
): Keychain.GetOptions {
  return {
    service,
    accessControl: ACCESS_CONTROL.BIOMETRY_ANY_OR_DEVICE_PASSCODE,
    authenticationPrompt: {title: promptTitle},
  };
}
