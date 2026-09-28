// schemaVersion.ts — Plaintext marker (no sensitive data, hence deliberately NOT encrypted via
// encryptedStore.ts) recording which storage-format version the data currently on the device was
// written with.
//
// For THE change that introduced this file (version 1 → 2: messages/sessions moved from whole
// blob to index+element collections) there is deliberately NO migration — no real user data
// existed yet at that point, and old keys are simply no longer read by the new code. For this
// change the function is write-only; its only purpose is that a FUTURE schema change (once there
// are real users) finds a real comparison value instead of having to introduce one
// retroactively.
import AsyncStorage from '@react-native-async-storage/async-storage';

const SCHEMA_VERSION_KEY = 'oniveil:schemaVersion';

// 1 = format before this change (implicit starting value, never written explicitly).
// 2 = messages/group messages as index+element collections, sessions per contact.
export const CURRENT_SCHEMA_VERSION = 2;

export async function getSchemaVersion(): Promise<number> {
  const raw = await AsyncStorage.getItem(SCHEMA_VERSION_KEY);
  return raw ? Number(raw) : 1;
}

export async function markSchemaVersion(version: number): Promise<void> {
  await AsyncStorage.setItem(SCHEMA_VERSION_KEY, String(version));
}
