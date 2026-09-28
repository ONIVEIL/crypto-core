// validation.ts — Shared format checks for values that cross trust boundaries (e.g. contact data
// entered manually by users, or message text received from a contact).
import {deriveOnionAddressFromPublicKey} from './onionAddress';

export const ONION_V3_PATTERN = /^[a-z2-7]{56}\.onion$/;
const ONION_V3_ADDRESS_WITHOUT_SUFFIX_PATTERN = /^[a-z2-7]{56}$/;
export const HEX_32_BYTES_PATTERN = /^[0-9a-f]{64}$/;
// Single source for this text.
export const INVALID_ONION_ADDRESS_MESSAGE = 'Ungültige Onion-Adresse.';

// A dedicated error class (instead of a bare `new Error(...)`) — in line with the existing
// pattern of this codebase for distinguishable error causes (see ReplayOrOutOfOrderError in
// crypto/session.ts, ProtocolError in transport/wireProtocol.ts). The UI can use `instanceof` to
// distinguish this (format) error cause from another (storage error) — an `instanceof`
// comparison does not silently break if the message text here changes in future, unlike a
// comparison on exact string equality.
export class InvalidOnionAddressError extends Error {
  constructor() {
    super(INVALID_ONION_ADDRESS_MESSAGE);
    this.name = 'InvalidOnionAddressError';
  }
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

// Some Orbot versions show/copy only the bare Base32 string WITHOUT the ".onion" suffix in their
// own interface — a user who takes it over exactly that way via copy+paste or manual typing would
// otherwise wrongly get a validation error for an otherwise correct value. If, after
// trim/lowercasing, a well-formed 56-character Base32 v3 address part is present but the ".onion"
// suffix is missing, it is added automatically here instead of rejecting the value.
//
// Some Orbot versions, on "copy onion service", instead copy the RAW, 32-byte Ed25519 public key
// of the service as a hex string (64 hex characters, e.g. from the internal
// "hs_ed25519_public_key" file) instead of the finished .onion address — the actual address can
// be computed from it deterministically according to the official Tor v3 specification
// (rend-spec-v3), exactly the same procedure as in identity.ts for the own, independently
// generated identity (see crypto/onionAddress.ts).
export function normalizeOnionAddress(address: string): string {
  const trimmed = address.trim().toLowerCase();
  if (trimmed.endsWith('.onion')) {
    return trimmed;
  }
  if (ONION_V3_ADDRESS_WITHOUT_SUFFIX_PATTERN.test(trimmed)) {
    return `${trimmed}.onion`;
  }
  if (HEX_32_BYTES_PATTERN.test(trimmed)) {
    return deriveOnionAddressFromPublicKey(hexToBytes(trimmed));
  }
  return trimmed;
}
// All message/attachment IDs in this app are always generated as bytesToHex(randomBytes(16)) —
// 32 hex characters. Important for every field received from a contact that is interpreted as
// such an ID, ESPECIALLY if a file-system path is built from it (as for an attachment message,
// see crypto/messageContent.ts 'media'): without this check, a malicious contact could force a
// path-traversal write outside the intended attachment storage folder via a manipulated `id`
// field (e.g. "../../../something").
export const HEX_16_BYTES_PATTERN = /^[0-9a-f]{32}$/;

// Upper bounds against unbounded growth (storage space/render cost), now that messages can
// actually come from a contact instead of only being typed locally.
export const MAX_DISPLAY_NAME_LENGTH = 40;
export const MAX_MESSAGE_LENGTH = 4000;

// Remove bidi embedding/override control characters (U+202A-U+202E, e.g. RIGHT-TO-LEFT
// OVERRIDE), bidi isolates (U+2066-U+2069), zero-width space (U+200B) and BOM/ZWNBSP (U+FEFF):
// these are not needed for normal text or name display (real RTL text works without them via the
// normal Unicode bidi algorithm), but can be used to make displayed text differ from the actual
// content (visual spoofing) — security-relevant for contact/message text from potentially
// malicious contacts. Deliberately NOT removed: zero-width joiner/non-joiner (U+200C/U+200D,
// needed for composite emoji and some scripts) and LRM/RLM (U+200E/U+200F, legitimate formatting
// hints in mixed RTL text).
const UNSAFE_TEXT_PATTERN = /[\u200B\u202A-\u202E\u2066-\u2069\uFEFF]/g;

export function sanitizeUserText(input: string, maxLength: number): string {
  return input.replace(UNSAFE_TEXT_PATTERN, '').slice(0, maxLength);
}
