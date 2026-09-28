// consumedInitialFreshness.ts — Persists already consumed `initialFreshness` values
// (crypto/session.ts, KCI/reset hardening) per static X25519 peer key — INDEPENDENT of the
// session object in sessions.ts (which is deleted on deleteContact).
//
// Why this is needed: the Ed25519 signature on the first message of each direction (session.ts,
// buildInitialAuthTranscript) binds only (freshness, both static keys) — NOT a concrete session
// episode, and an Ed25519 signature never expires. If only the signature were checked, an
// attacker who already knows a REAL, previously observed (freshness, signature) pair (the
// freshness component is sent in the clear — any network observer sees it, independent of any key
// compromise) could replay it after a deleteContact() + re-adding the same contact (which
// reproduces a bit-identical base chain key) and thereby recover the same message key as in the
// original pairing — the signature protection alone does NOT cover this replay path. This store
// closes exactly that gap: a freshness that was once successfully used counts as consumed
// FOREVER, regardless of how often the contact is deleted/re-created in between.
import {
  readEncrypted,
  withCollectionLock,
  writeEncrypted,
} from './encryptedStore';
import {getOrCreateVaultKey} from './vaultKey';

const CONSUMED_INITIAL_FRESHNESS_STORAGE_KEY =
  'oniveil:consumedInitialFreshness';

// Static X25519 peer key (hex) -> list of already consumed freshness values (hex). Structurally
// bounded per peer to a handful of entries at most (two directions × number of re-pairings that
// ever took place with exactly this contact) — an entry arises only for a self-verified,
// NON-repeated sequenceNumber===0 message, not on every delivery attempt (the caller skips this
// check on the existing `duplicate` branch of decryptMessage on purpose, otherwise a legitimate
// repeat — lost ack, see session.ts — would wrongly be rejected as a replay of this freshness).
type ConsumedFreshnessByPeer = Record<string, string[]>;

// Checks whether this freshness has already been consumed once for this peer, and, if not,
// marks it as consumed in the SAME operation serialized by withCollectionLock — no
// read-then-write window in which two concurrent attempts with the same freshness could both pass
// as "new". Return value `true`: this freshness was new, the message may be accepted. `false`:
// already consumed once — replay, reject.
export async function checkAndRecordInitialFreshness(
  peerStaticPublicKey: string,
  freshness: string,
): Promise<boolean> {
  return withCollectionLock(
    CONSUMED_INITIAL_FRESHNESS_STORAGE_KEY,
    async () => {
      const vaultKey = await getOrCreateVaultKey();
      const store = await readEncrypted<ConsumedFreshnessByPeer>(
        CONSUMED_INITIAL_FRESHNESS_STORAGE_KEY,
        vaultKey,
        {},
      );
      const existing = store[peerStaticPublicKey] ?? [];
      if (existing.includes(freshness)) {
        return false;
      }
      store[peerStaticPublicKey] = [...existing, freshness];
      await writeEncrypted(
        CONSUMED_INITIAL_FRESHNESS_STORAGE_KEY,
        vaultKey,
        store,
      );
      return true;
    },
  );
}
