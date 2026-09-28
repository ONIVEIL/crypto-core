// encryptedCollection.ts — Generic storage infrastructure primitive for an ordered collection in
// which every element is encrypted and stored INDIVIDUALLY, instead of (like encryptedStore.ts's
// readEncrypted/writeEncrypted) treating the whole collection as one single blob. In short: with
// a whole-blob collection, every change (e.g. a new message) had to decrypt and re-encrypt the
// COMPLETE existing collection — O(size of the whole collection) instead of O(1) per change.
//
// A collection instance is identified by a `baseKey` — exactly the same string that the messages
// modules use as their storage key, and exactly the same string with which `withCollectionLock`
// (unchanged) continues to lock — this module does not know `withCollectionLock` itself, that
// stays the callers' business; this module is purely storage infrastructure, no business logic
// about messages.
//
// Security binding (AAD): in addition to the normal XChaCha20-Poly1305 authentication, every
// index/element ciphertext is bound to its LOGICAL context (schema version + record type +
// baseKey [+ itemId]) — see buildIndexAAD/buildItemAAD below. Without it, the same `vaultKey`
// (identical for ALL collections/elements) would not detect a swap: a ciphertext that really
// belongs to element A but is stored under the AsyncStorage key of element B would decrypt
// without complaint under the same vaultKey and its own (still valid) nonce — only to the wrong
// logical record. With AAD, exactly that now fails (the Poly1305 tag check takes the AAD into
// account). Additionally, as a second defense layer independent of the AAD:
// `readCollectionItem`/`readCollectionItems` check `decoded.id === expectedId` after decrypting
// (see there) — if the calling structure itself carries an `id` field that does not contain the
// expected value, that is treated as a tampering/swap case and not silently passed through.
import AsyncStorage from '@react-native-async-storage/async-storage';
import {decodeEncrypted, encryptBlob} from './encryptedStore';
import {diagLog} from '../diagnostics';

const AAD_SCHEMA = 'oniveil-collection-v1';

function textEncode(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function buildIndexAAD(baseKey: string): Uint8Array {
  return textEncode(`${AAD_SCHEMA}|index|${baseKey}`);
}

function buildItemAAD(baseKey: string, itemId: string): Uint8Array {
  return textEncode(`${AAD_SCHEMA}|item|${baseKey}|${itemId}`);
}

export function collectionIndexKey(baseKey: string): string {
  return `${baseKey}:index`;
}

export function collectionItemKey(baseKey: string, itemId: string): string {
  return `${baseKey}:item:${itemId}`;
}

export interface CollectionIndexRecord<TSummary> {
  // Chronological order (append=push to the end, delete=splice) — callers use
  // `ids[ids.length-1]` as the "last message", following the same append-only-at-the-end
  // principle as an in-memory array.
  ids: string[];
  summary: TSummary;
}

function emptyIndex<TSummary>(emptySummary: TSummary): CollectionIndexRecord<TSummary> {
  return {ids: [], summary: emptySummary};
}

export async function readCollectionIndex<TSummary>(
  baseKey: string,
  vaultKey: Uint8Array,
  emptySummary: TSummary,
): Promise<CollectionIndexRecord<TSummary>> {
  const key = collectionIndexKey(baseKey);
  const stored = await AsyncStorage.getItem(key);
  if (!stored) {
    return emptyIndex(emptySummary);
  }
  return decodeEncrypted<CollectionIndexRecord<TSummary>>(
    key,
    vaultKey,
    stored,
    emptyIndex(emptySummary),
    buildIndexAAD(baseKey),
  );
}

export async function writeCollectionIndex<TSummary>(
  baseKey: string,
  vaultKey: Uint8Array,
  index: CollectionIndexRecord<TSummary>,
): Promise<void> {
  const key = collectionIndexKey(baseKey);
  const plaintext = textEncode(JSON.stringify(index));
  const blob = encryptBlob(vaultKey, plaintext, buildIndexAAD(baseKey));
  await AsyncStorage.setItem(key, blob);
  diagLog(`oniveil[diag]: wrote collection index "${key}" len=${blob.length}`);
}

// Second defense layer independent of the AAD (see module documentation above): an element that
// decrypts successfully under the EXPECTED AAD but whose `id` field does not match the requested
// `itemId` is treated like tampering (throws), not silently returned. `TItem` must carry an
// `id: string` field for this — both stored message types already do.
function assertMatchingId<TItem extends {id: string}>(
  itemKeyForLogging: string,
  requestedId: string,
  decoded: TItem,
): TItem {
  if (decoded.id !== requestedId) {
    diagLog(
      `oniveil[diag]: encryptedCollection: Element unter "${itemKeyForLogging}" hat id="${decoded.id}", erwartet war "${requestedId}" — als Manipulation/Vertauschung behandelt.`,
    );
    throw new Error(
      `oniveil: Element-ID-Mismatch für "${itemKeyForLogging}" (erwartet "${requestedId}", erhalten "${decoded.id}").`,
    );
  }
  return decoded;
}

export async function readCollectionItem<TItem extends {id: string}>(
  baseKey: string,
  vaultKey: Uint8Array,
  itemId: string,
): Promise<TItem | null> {
  const key = collectionItemKey(baseKey, itemId);
  const stored = await AsyncStorage.getItem(key);
  if (!stored) {
    return null;
  }
  const decoded = decodeEncrypted<TItem | null>(
    key,
    vaultKey,
    stored,
    null,
    buildItemAAD(baseKey, itemId),
  );
  if (decoded === null) {
    // Fail-safe branch of decodeEncrypted (decrypted successfully, but not valid JSON, e.g. an
    // interrupted write) — already logged there, only passed through consistently here, no
    // ID check again (there is nothing to check).
    return null;
  }
  return assertMatchingId(key, itemId, decoded);
}

// Full collection read (open a chat) — ONE multiGet round trip instead of N individual getItem
// calls. Deliberately still O(n) decryptions — that is correct here and not a regression: opening
// a conversation needs every message anyway.
export async function readCollectionItems<TItem extends {id: string}>(
  baseKey: string,
  vaultKey: Uint8Array,
  ids: string[],
): Promise<TItem[]> {
  if (ids.length === 0) {
    return [];
  }
  const keys = ids.map(id => collectionItemKey(baseKey, id));
  const pairs = await AsyncStorage.multiGet(keys);
  const byKey = new Map(pairs);
  const items: TItem[] = [];
  for (const id of ids) {
    const key = collectionItemKey(baseKey, id);
    const stored = byKey.get(key);
    if (!stored) {
      // The index refers to an ID whose element key does not (any longer) exist — not expected in
      // normal operation (every mutation of this module keeps index and elements consistent in
      // the same locked section), but a MISSING key is different from a PRESENT but tampered one
      // — the latter still throws (see below). A single missing element must not make the whole
      // conversation unreadable — skip + log loudly instead of throwing.
      diagLog(
        `oniveil[diag]: encryptedCollection: im Index gelistetes Element "${key}" nicht vorhanden — übersprungen.`,
      );
      continue;
    }
    const decoded = decodeEncrypted<TItem | null>(
      key,
      vaultKey,
      stored,
      null,
      buildItemAAD(baseKey, id),
    );
    if (decoded === null) {
      continue; // fail-safe branch (broken JSON) — already logged in decodeEncrypted
    }
    items.push(assertMatchingId(key, id, decoded));
  }
  return items;
}

export async function writeCollectionItem<TItem>(
  baseKey: string,
  vaultKey: Uint8Array,
  itemId: string,
  value: TItem,
): Promise<void> {
  const key = collectionItemKey(baseKey, itemId);
  const plaintext = textEncode(JSON.stringify(value));
  const blob = encryptBlob(vaultKey, plaintext, buildItemAAD(baseKey, itemId));
  await AsyncStorage.setItem(key, blob);
}

// Batched multi-element + index write in ONE multiSet call — for operations that affect more
// than one element at once (e.g. "mark all unread messages as read"). Android:
// `AsyncStorage.multiSet` runs in a real SQLite transaction (verified against the installed
// native source) — all keys/values of this call commit atomically together or not at all.
export async function writeCollectionItemsAndIndex<TItem, TSummary>(
  baseKey: string,
  vaultKey: Uint8Array,
  items: {id: string; value: TItem}[],
  index: CollectionIndexRecord<TSummary>,
): Promise<void> {
  const pairs: [string, string][] = items.map(({id, value}) => [
    collectionItemKey(baseKey, id),
    encryptBlob(
      vaultKey,
      textEncode(JSON.stringify(value)),
      buildItemAAD(baseKey, id),
    ),
  ]);
  pairs.push([
    collectionIndexKey(baseKey),
    encryptBlob(vaultKey, textEncode(JSON.stringify(index)), buildIndexAAD(baseKey)),
  ]);
  await AsyncStorage.multiSet(pairs);
}

export async function removeCollectionItem(
  baseKey: string,
  itemId: string,
): Promise<void> {
  await AsyncStorage.removeItem(collectionItemKey(baseKey, itemId));
}

// Deletes a complete collection instance: index + every element currently listed in the index, in
// ONE multiRemove. Returns the IDs previously listed in the index, in case the caller (e.g. a
// clear-messages function) still had to do something per element before deleting (clean up
// attachment files) — for that, the elements must already have been read BEFORE calling this
// function, it does not read them again itself.
export async function clearCollection<TSummary>(
  baseKey: string,
  vaultKey: Uint8Array,
  emptySummary: TSummary,
): Promise<string[]> {
  const index = await readCollectionIndex(baseKey, vaultKey, emptySummary);
  const keys = [
    collectionIndexKey(baseKey),
    ...index.ids.map(id => collectionItemKey(baseKey, id)),
  ];
  await AsyncStorage.multiRemove(keys);
  return index.ids;
}
