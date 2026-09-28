// diagnostics.ts — Switchable diagnostic logging for targeted troubleshooting on a real device
// (readable via `adb logcat`), without having to build a separate APK variant each time. Can be
// enabled via a switch in the settings.
//
// Deliberately plain, unencrypted AsyncStorage (no secret, just a UI setting) — default OFF, so
// that in normal operation no internal storage/key metadata (lengths, checksums) is written to
// the system log.
import AsyncStorage from '@react-native-async-storage/async-storage';

const STORAGE_KEY = 'oniveil:diagnostic-logging-enabled';

// Module-global cache: the callers of diagLog() (encryptedStore.ts, vaultKey.ts, ...) are on the
// hot path of EVERY storage access and therefore must not read asynchronously from AsyncStorage
// on every call — instead it is loaded once at app start (see loadDiagnosticLoggingEnabled(),
// called from the app entry point) and queried synchronously.
let enabled = false;

export async function loadDiagnosticLoggingEnabled(): Promise<boolean> {
  const stored = await AsyncStorage.getItem(STORAGE_KEY);
  enabled = stored === 'true';
  return enabled;
}

export function isDiagnosticLoggingEnabled(): boolean {
  return enabled;
}

export async function setDiagnosticLoggingEnabled(value: boolean): Promise<void> {
  enabled = value;
  await AsyncStorage.setItem(STORAGE_KEY, value ? 'true' : 'false');
}

// Central place for all diagnostic logs, instead of scattered individual console.warn calls — a
// single switch covers them all.
export function diagLog(message: string): void {
  if (enabled) {
    console.warn(message);
  }
}
