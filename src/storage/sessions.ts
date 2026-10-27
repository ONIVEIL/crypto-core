// sessions.ts — Persistence of the ratchet sessions (src/crypto/session.ts), one per contact.
// The session state (chain keys, counters) must survive app restarts, otherwise the expected
// sequence counter would be reset and legitimate messages rejected as replays.
//
// Storage layout: earlier, ONE fixed key `oniveil:sessions` held ALL contacts in a
// `Record<contactId, Session>` — every single message sent/received for ANY contact thereby
// rewrote the complete session state of ALL OTHER contacts (the worst performance hotspot,
// confirmed). Now there is ONE key PER contact — `saveSession` for contact A no longer touches any
// other contact. Deliberately NOT moved to the index+element schema (encryptedCollection.ts): a
// session is ONE coherent object per contact, not a growing list, so a simple whole blob PER
// CONTACT is already the right granularity here.
//
// Swap protection: while all sessions lay under a single AsyncStorage key, swapping ciphertexts
// between two contacts was meaningless (there was only ONE key). The split into one key PER
// CONTACT (above) structurally introduces the same class of swap risk that encryptedCollection.ts
// already closes for messages/group messages via AAD (additional authenticated data): without a
// binding to the contact, a ciphertext that really belongs to contact A but is stored under
// contact B's key (e.g. through a bug in future cleanup/backup code, or external manipulation on
// a rooted device) would decrypt without complaint under the same vaultKey — only to the wrong
// session. Hence the same AAD binding as in encryptedCollection.ts, used directly through the
// already existing `encryptBlob`/`decodeEncrypted` exports of encryptedStore.ts (no index/element
// structure needed, see above) instead of through encryptedCollection.ts itself.
import {isValidSession, Session} from '../crypto/session';
import AsyncStorage from '@react-native-async-storage/async-storage';
import {
  decodeEncrypted,
  encryptBlob,
  withCollectionLock,
} from './encryptedStore';
import {getOrCreateVaultKey} from './vaultKey';

function sessionsStorageKey(contactId: string): string {
  return `oniveil:sessions:${contactId}`;
}

function sessionAAD(contactId: string): Uint8Array {
  return new TextEncoder().encode(`oniveil-session-v1|${contactId}`);
}

// Returns `null` if no session is stored for the contact OR if the stored value does not (any
// longer) match the current session shape (isValidSession, see crypto/session.ts) — e.g. a
// session stored before the Double-Ratchet changeover, without the new ratchet fields. The caller
// treats both identically: build a fresh session as usual, as for a new contact. Deliberately
// unlocked (as before) — a pure read access, the same eventual-consistency expectation as for
// the other read functions.
export async function getSession(contactId: string): Promise<Session | null> {
  const key = sessionsStorageKey(contactId);
  const stored = await AsyncStorage.getItem(key);
  if (!stored) {
    return null;
  }
  const vaultKey = await getOrCreateVaultKey();
  const session = decodeEncrypted<Session | null>(
    key,
    vaultKey,
    stored,
    null,
    sessionAAD(contactId),
  );
  return session !== null && isValidSession(session) ? session : null;
}

export async function saveSession(
  contactId: string,
  session: Session,
): Promise<void> {
  const key = sessionsStorageKey(contactId);
  return withCollectionLock(key, async () => {
    const vaultKey = await getOrCreateVaultKey();
    const blob = encryptBlob(
      vaultKey,
      new TextEncoder().encode(JSON.stringify(session)),
      sessionAAD(contactId),
    );
    await AsyncStorage.setItem(key, blob);
  });
}

// For an atomic joint commit with other storage areas (outbox, replay-freshness store): returns
// only the encrypted write pair without writing. Same format as saveSession.
export function buildSessionPair(
  contactId: string,
  session: Session,
  vaultKey: Uint8Array,
): [string, string] {
  return [
    sessionsStorageKey(contactId),
    encryptBlob(
      vaultKey,
      new TextEncoder().encode(JSON.stringify(session)),
      sessionAAD(contactId),
    ),
  ];
}

// The lock that saveSession/deleteSession also take for this contact.
export async function withSessionStorageLock<T>(
  contactId: string,
  operation: () => Promise<T>,
): Promise<T> {
  return withCollectionLock(sessionsStorageKey(contactId), operation);
}

// Deletes the session of a contact (e.g. when removing the contact) — otherwise the chain-key
// state would stay stored permanently as an orphan.
export async function deleteSession(contactId: string): Promise<void> {
  const key = sessionsStorageKey(contactId);
  return withCollectionLock(key, async () => {
    await AsyncStorage.removeItem(key);
  });
}
