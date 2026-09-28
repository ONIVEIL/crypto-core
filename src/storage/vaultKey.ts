// vaultKey.ts — Persistent master key for the encrypted local storage (contacts, messages).
// Deliberately separate from the identity key pair in src/crypto/identity.ts, since it serves a
// different purpose (storage encryption instead of signing/key exchange) — no key reuse across
// different cryptographic purposes.
import 'react-native-get-random-values';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Keychain from 'react-native-keychain';
import {bytesToHex, hexToBytes, randomBytes} from '@noble/hashes/utils.js';
import {
  hardenedGetOptions,
  hardenedSetOptions,
} from '../crypto/keychainOptions';
import {fingerprint} from './encryptedStore';
import {diagLog} from '../diagnostics';

// Exported (only) for tests that must reset the keychain mock between cases.
export const VAULT_KEYCHAIN_SERVICE = 'oniveil-vault';
const VAULT_KEY_LENGTH = 32; // 256 bit, matches XChaCha20-Poly1305

const SET_OPTIONS = hardenedSetOptions(VAULT_KEYCHAIN_SERVICE);
const GET_OPTIONS = hardenedGetOptions(VAULT_KEYCHAIN_SERVICE);

// Unencrypted marker (no secret, just one bit "has a vault key ever been created here") — see
// its use below.
const EVER_CREATED_MARKER = 'oniveil:vault-key-ever-created';

// Serializes overlapping calls onto the same in-flight promise: without it, two simultaneous
// first calls (e.g. several screens loading in parallel on the very first app start) could both
// see "no key yet" and each generate and write to the keychain its OWN, different random key —
// the second write would overwrite the first, making everything the first (now lost) key already
// encrypted permanently undecryptable.
let inFlight: Promise<Uint8Array> | null = null;

// Loads the existing vault key or, on the very first call, creates a new one.
export async function getOrCreateVaultKey(): Promise<Uint8Array> {
  if (inFlight) {
    return inFlight;
  }
  inFlight = (async () => {
    try {
      // Diagnostics: a separate try/catch ONLY around this one native call, to tell whether an
      // observed load failure comes from Keychain.getGenericPassword() itself throwing (instead of
      // simply returning "not present") — this case had not been logged at all, although it would
      // have the same visible effect (a load error in the UI).
      let existing: Awaited<ReturnType<typeof Keychain.getGenericPassword>>;
      try {
        existing = await Keychain.getGenericPassword(GET_OPTIONS);
      } catch (err) {
        diagLog(
          `oniveil[diag]: Keychain.getGenericPassword() selbst hat geworfen: ${err instanceof Error ? `${err.name}: ${err.message}` : String(err)}`,
        );
        throw err;
      }
      if (existing) {
        const key = hexToBytes(existing.password);
        diagLog(
          `oniveil[diag]: vaultKey from Keychain, keyFp=${fingerprint(key)}`,
        );
        return key;
      }

      // If a key was already successfully created here ONCE (marker set) but the keychain now
      // reports "not present", do NOT silently create a new key and thereby overwrite the old
      // one — a bug observed on a real device (stored values "vanish" for no apparent reason): an
      // Android Keystore entry can transiently come back as "not found" because of OS/hardware
      // quirks (e.g. a hardware security layer that is momentarily unreachable) even though it
      // does exist — silently re-creating it would in that case make everything encrypted with the
      // old (now unreachable) key permanently undecryptable, without the user ever seeing an error
      // (only seemingly empty/reset fields). Better to fail loudly (the existing error displays in
      // the UI already catch this) than to lose data silently.
      const everCreated = await AsyncStorage.getItem(EVER_CREATED_MARKER);
      if (everCreated) {
        diagLog(
          'oniveil[diag]: Keychain meldet "nicht vorhanden", obwohl EVER_CREATED_MARKER gesetzt ist — verweigere Neuerzeugung.',
        );
        throw new Error(
          'Vault-Schlüssel im Android-Keystore nicht auffindbar, obwohl zuvor bereits einer erzeugt wurde — wird nicht automatisch ersetzt.',
        );
      }

      const key = randomBytes(VAULT_KEY_LENGTH);
      diagLog(
        `oniveil[diag]: erzeuge NEUEN vaultKey (noch keiner vorhanden), keyFp=${fingerprint(key)}`,
      );
      await Keychain.setGenericPassword(
        'vault-key',
        bytesToHex(key),
        SET_OPTIONS,
      );
      await AsyncStorage.setItem(EVER_CREATED_MARKER, '1');
      return key;
    } finally {
      inFlight = null;
    }
  })();
  return inFlight;
}
