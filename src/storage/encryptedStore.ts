// encryptedStore.ts — Generic encrypted key-value storage primitive. Each collection (e.g.
// contacts, messages per contact) is encrypted as one blob with XChaCha20-Poly1305 (authenticated
// encryption) and persisted via AsyncStorage.
//
// Deliberately our own encryption instead of a native "storage encryption" (e.g. MMKV): that way
// the cryptographic scheme actually used stays visible in our own, auditable code instead of
// being hidden in a black-box library.
//
// A blob that was tampered with or read with the wrong key makes decrypt() fail (Poly1305 tag
// check) instead of silently returning wrong data — fail-closed on tampering.
import AsyncStorage from '@react-native-async-storage/async-storage';
import {xchacha20poly1305} from '@noble/ciphers/chacha.js';
import {
  bytesToHex,
  concatBytes,
  hexToBytes,
  randomBytes,
} from '@noble/hashes/utils.js';
import {bytesToUtf8} from '../crypto/textCodec';
import {diagLog} from '../diagnostics';

const NONCE_LENGTH = 24; // XChaCha20 uses a 24-byte nonce (safe for random nonces)

// `aad` (additional authenticated data, optional) binds the ciphertext to its logical context
// (e.g. "this is the index entry of EXACTLY this collection", "this is EXACTLY this element of
// this collection") — without it, the same `vaultKey` for ALL collections/elements would not
// detect a swap: a ciphertext that really belongs under key A but ends up stored under key B
// (e.g. through a bug in cleanup/copy code, or external manipulation of the AsyncStorage
// database) would decrypt without complaint under the same `vaultKey` and its own (still valid)
// nonce — only to the wrong logical record. Optional (no third parameter = `undefined`) and thus
// exactly backward compatible: `@noble/ciphers`'s `xchacha20poly1305(key, nonce, AAD)` treats an
// omitted AAD identically to an explicit `undefined` (see its implementation), so all existing
// callers (readEncrypted/writeEncrypted, without AAD) are unchanged.
export function encryptBlob(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): string {
  const nonce = randomBytes(NONCE_LENGTH);
  const ciphertext = xchacha20poly1305(key, nonce, aad).encrypt(plaintext);
  return bytesToHex(concatBytes(nonce, ciphertext));
}

function decryptBlob(key: Uint8Array, stored: string, aad?: Uint8Array): Uint8Array {
  const bytes = hexToBytes(stored);
  const nonce = bytes.slice(0, NONCE_LENGTH);
  const ciphertext = bytes.slice(NONCE_LENGTH);
  return xchacha20poly1305(key, nonce, aad).decrypt(ciphertext);
}

// NOT cryptographic, diagnostics only: makes it possible to tell in logs whether two calls return
// the same vaultKey, without logging the key itself. Exported so that vaultKey.ts can log the
// same fingerprint — both modules yield comparable values (instead of e.g. the hex length, which
// is always a constant 64 for a 32-byte key).
//
// Position-dependent (not just a sum): a plain byte sum is insensitive to swapped bytes and thus
// collides easily between two actually DIFFERENT keys — exactly the mix-up this value is meant to
// make visible when debugging. Multiplying by an odd constant per byte makes the byte order part
// of the result. Logging is off by default (see diagnostics.ts); the value is a 17-bit reduction
// of the key and only ever reaches a log when diagnostic logging is switched on explicitly.
export function fingerprint(key: Uint8Array): number {
  let hash = 0;
  for (const byte of key) {
    hash = (hash * 31 + byte) % 99991;
  }
  return hash;
}

// Generic over the value type (not just arrays): a collection is e.g. `Contact[]`, a session
// table e.g. `Record<string, Session>`. `defaultValue` covers the case that nothing has been
// stored under this key yet.
// Extracted from readEncrypted() so that encryptedCollection.ts can apply the same
// fail-closed/fail-safe handling to a value already loaded via multiGet, without repeating the
// AsyncStorage access itself — NO behavior change compared to before, a pure move of the
// existing code into its own reusable function.
// `storageKeyForLogging` is passed separately from the actual AsyncStorage access, so that a
// caller (e.g. a multiGet over several elements) can still log the exact affected logical key.
export function decodeEncrypted<T>(
  storageKeyForLogging: string,
  vaultKey: Uint8Array,
  stored: string,
  defaultValue: T,
  aad?: Uint8Array,
): T {
  // decryptBlob() deliberately NOT included in the try/catch below: a failed Poly1305 auth tag
  // (tampered data, wrong key, OR — with per-element AAD — a record that sits in the wrong place)
  // must keep throwing instead of falling back fail-safe to defaultValue — otherwise a detected
  // tampering/swap would silently be treated like "no data yet" instead of staying visible to the
  // caller. This diagnostics block catches ONLY to log and then rethrows unchanged (no behavior
  // difference), so that an auth failure becomes visible when debugging.
  let plaintext: Uint8Array;
  try {
    plaintext = decryptBlob(vaultKey, stored, aad);
  } catch (err) {
    diagLog(
      `oniveil[diag]: decryptBlob für "${storageKeyForLogging}" fehlgeschlagen (Auth-Tag ungültig, falscher Schlüssel, oder falscher Kontext), keyFp=${fingerprint(vaultKey)}`,
    );
    throw err;
  }
  const decoded = bytesToUtf8(plaintext);
  try {
    return JSON.parse(decoded) as T;
  } catch {
    // Decrypted successfully, but not valid JSON (e.g. damaged by an interrupted write) — fail-safe
    // instead of a crash is the right choice here, since authenticity has already been confirmed.
    // Deliberately no error object in the log.
    // The (authentic but unreadable) blob is kept as a backup before a later overwrite with the
    // default value — at most ONE backup per key. Fire-and-forget: a failure to back up must not
    // disturb reading.
    AsyncStorage.setItem(`${storageKeyForLogging}:unreadable-backup`, stored).catch(
      () => {},
    );
    diagLog(
      `oniveil[diag]: konnte "${storageKeyForLogging}" nicht parsen, verwende Standardwert (Sicherung angelegt).`,
    );
    // Structure only, no content: also used for contacts etc., a plaintext excerpt could write
    // personal data (display names, onion addresses) into logcat here. First/last character
    // suffice to tell e.g. a truncated write (missing closing bracket/quote) from empty/random
    // content.
    diagLog(
      `oniveil[diag]: plaintext len=${decoded.length} first=${JSON.stringify(decoded.slice(0, 1))} last=${JSON.stringify(decoded.slice(-1))}`,
    );
    return defaultValue;
  }
}

export async function readEncrypted<T>(
  storageKey: string,
  vaultKey: Uint8Array,
  defaultValue: T,
): Promise<T> {
  const stored = await AsyncStorage.getItem(storageKey);
  diagLog(
    `oniveil[diag]: read "${storageKey}" len=${stored?.length ?? 'null'} keyFp=${fingerprint(vaultKey)}`,
  );
  if (!stored) {
    return defaultValue;
  }
  return decodeEncrypted(storageKey, vaultKey, stored, defaultValue);
}

export async function writeEncrypted<T>(
  storageKey: string,
  vaultKey: Uint8Array,
  value: T,
  options?: {verify?: boolean},
): Promise<void> {
  const plaintext = new TextEncoder().encode(JSON.stringify(value));
  const blob = encryptBlob(vaultKey, plaintext);
  await AsyncStorage.setItem(storageKey, blob);
  diagLog(
    `oniveil[diag]: wrote "${storageKey}" len=${blob.length} keyFp=${fingerprint(vaultKey)}`,
  );
  if (!options?.verify) {
    return;
  }
  // Read back immediately and confirm that the write actually arrived — AsyncStorage actually
  // guarantees that already through the `await` above, but a case observed in the field (a stored
  // value "vanished" on the next read without any error ever being seen) points to an otherwise
  // invisible persistence problem. A plain string comparison of the finished ciphertext (no
  // decrypting again) — cheap.
  //
  // Deliberately NOT active automatically for every caller (`verify` must be requested
  // explicitly): a failure HERE for session/message writes (both on the hot receive path of the
  // messaging layer, where the session is already committed BEFORE the message append that would
  // be affected here) could leave the session ratchet already advanced but the message itself not
  // stored — worse than the original failure case this read-back was meant to fix. Deliberately
  // enabled only where a single, self-contained write (no multi-step, session-dependent flow) is
  // affected AND a silent loss would stay unnoticed particularly long (currently only the stored
  // reachable onion address).
  const verify = await AsyncStorage.getItem(storageKey);
  if (verify !== blob) {
    throw new Error(
      `oniveil: Schreibvorgang für "${storageKey}" konnte nicht verifiziert werden.`,
    );
  }
}

// Serializes all operations on the same storageKey. Without it, a read-modify-write call (e.g.
// addContact) running in parallel with a second one would read the same intermediate state and
// overwrite its result on write-back (lost update) — e.g. when an incoming message is stored
// while the user is sending a message to the same contact at that moment.
const locks = new Map<string, Promise<unknown>>();

export function withCollectionLock<T>(
  storageKey: string,
  operation: () => Promise<T>,
): Promise<T> {
  const previous = locks.get(storageKey) ?? Promise.resolve();
  const next = previous.then(operation, operation);
  locks.set(
    storageKey,
    next.catch(() => undefined),
  );
  return next;
}
