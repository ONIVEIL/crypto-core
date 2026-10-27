// contactCode.ts — Combines the three values needed to add a contact (onion address, signing
// public key, encryption public key) into ONE shareable string. Typing or copying three separate
// 56-/64-character values one after another is error-prone, especially between two devices.
// Deliberately plain text (no QR code, no new native camera dependency/permission) — it can be
// sent through the normal Android share dialog (any channel: chat apps, e-mail, ...).
import {
  HEX_32_BYTES_PATTERN,
  ONION_V3_PATTERN,
  normalizeOnionAddress,
} from './validation';

// Onion addresses (a-z2-7 + ".onion") and hex keys (0-9a-f) never contain a colon — so it is
// unambiguous as a separator and needs no escaping.
const CONTACT_CODE_SEPARATOR = ':';
// Fixed prefix instead of a raw ":"-separated string — clearly rules out accidentally pasted,
// completely different text (e.g. an ordinary message) before any attempt is made to split it
// into three parts.
const CONTACT_CODE_PREFIX = `oniveil-kontakt${CONTACT_CODE_SEPARATOR}`;
// Codes created before the rename to ONIVEIL stay valid (contacts must not be lost or have to
// exchange codes again because of the rename).
const LEGACY_CONTACT_CODE_PREFIX = `onyvia-kontakt${CONTACT_CODE_SEPARATOR}`;

export interface ContactCodeFields {
  onionAddress: string;
  signingPublicKey: string;
  encryptionPublicKey: string;
}

export function buildContactCode({
  onionAddress,
  signingPublicKey,
  encryptionPublicKey,
}: ContactCodeFields): string {
  return (
    CONTACT_CODE_PREFIX +
    [onionAddress, signingPublicKey, encryptionPublicKey].join(
      CONTACT_CODE_SEPARATOR,
    )
  );
}

// Returns `null` instead of throwing — a pasted contact code is a convenience shortcut, not a
// required field (the UI simply leaves the three individual fields unchanged on `null`, with no
// error message for every keystroke while pasting). Validates address/key format with the same
// patterns as filling in the individual fields manually (ONION_V3_PATTERN/HEX_32_BYTES_PATTERN) —
// a code with an obviously wrong format is discarded instead of being adopted unchecked into the
// fields, from which addContact() checks again anyway.
export function parseContactCode(code: string): ContactCodeFields | null {
  const trimmed = code.trim();
  const lower = trimmed.toLowerCase();
  const prefix = lower.startsWith(CONTACT_CODE_PREFIX)
    ? CONTACT_CODE_PREFIX
    : lower.startsWith(LEGACY_CONTACT_CODE_PREFIX)
    ? LEGACY_CONTACT_CODE_PREFIX
    : null;
  if (prefix === null) {
    return null;
  }
  const parts = trimmed.slice(prefix.length).split(CONTACT_CODE_SEPARATOR);
  if (parts.length !== 3) {
    return null;
  }
  const [rawOnionAddress, rawSigningKey, rawEncryptionKey] = parts;
  const onionAddress = normalizeOnionAddress(rawOnionAddress);
  const signingPublicKey = rawSigningKey.trim().toLowerCase();
  const encryptionPublicKey = rawEncryptionKey.trim().toLowerCase();
  if (
    !ONION_V3_PATTERN.test(onionAddress) ||
    !HEX_32_BYTES_PATTERN.test(signingPublicKey) ||
    !HEX_32_BYTES_PATTERN.test(encryptionPublicKey)
  ) {
    return null;
  }
  // Deliberately NO check that onionAddress is derivable from signingPublicKey: that is simply
  // not an invariant of this app. When an onion service is set up manually through Orbot's own
  // interface, Orbot assigns a Tor-generated key pair of its own — there is no supported way to
  // hand Orbot a key brought along. The onionAddress actually shared is therefore ALWAYS the
  // separately stored reachable address, NOT deriveOnionAddressFromPublicKey(signingPublicKey) —
  // for a normal, real contact code the two are practically never identical. A check of that kind
  // was tried once and rejected valid, unmodified contact codes in live testing on real devices.
  return {onionAddress, signingPublicKey, encryptionPublicKey};
}
