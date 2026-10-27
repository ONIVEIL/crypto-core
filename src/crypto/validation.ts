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

// Characters that are not needed for normal text or name display but can be used to make
// displayed text differ from the actual content (visual spoofing) or to carry an invisible
// payload — security-relevant for contact/message text from potentially malicious contacts:
//   - control characters (C0 except line feed and tab, DEL, C1), line/paragraph separators
//     U+2028/U+2029
//   - bidi embeddings/overrides U+202A-202E, isolates U+2066-2069, Arabic Letter Mark U+061C,
//     deprecated format characters U+206A-206F
//   - zero-width space U+200B, word joiner and invisible operators U+2060-2064, Mongolian vowel
//     separator U+180E, combining grapheme joiner U+034F, BOM/ZWNBSP U+FEFF
//   - interlinear annotation characters U+FFF9-FFFB
//   - Unicode tag characters U+E0000-E007F (invisible, can carry hidden text)
//   - variation selectors except VS15/VS16 (U+FE0E/U+FE0F, needed for emoji presentation):
//     U+FE00-FE0D and U+E0100-E01EF
// Deliberately NOT removed: zero-width joiner/non-joiner (U+200C/U+200D, needed for composite
// emoji and some scripts) and LRM/RLM (U+200E/U+200F, legitimate formatting hints in mixed RTL
// text; real RTL text works without overrides).
function isUnsafeCodePoint(cp: number): boolean {
  if (cp < 0x20) {
    return cp !== 0x0a && cp !== 0x09;
  }
  return (
    cp === 0x7f ||
    (cp >= 0x80 && cp <= 0x9f) ||
    cp === 0x034f ||
    cp === 0x061c ||
    cp === 0x180e ||
    cp === 0x200b ||
    (cp >= 0x2028 && cp <= 0x202e) ||
    (cp >= 0x2060 && cp <= 0x206f) ||
    cp === 0xfeff ||
    (cp >= 0xfe00 && cp <= 0xfe0d) ||
    (cp >= 0xfff9 && cp <= 0xfffb) ||
    (cp >= 0xe0000 && cp <= 0xe007f) ||
    (cp >= 0xe0100 && cp <= 0xe01ef)
  );
}

// `maxLength` counts UTF-16 units (like the message size check in messageContent.ts), but a
// surrogate pair is never split in the middle.
export function sanitizeUserText(input: string, maxLength: number): string {
  let result = '';
  for (const char of input) {
    const codePoint = char.codePointAt(0)!;
    if (isUnsafeCodePoint(codePoint)) {
      continue;
    }
    if (result.length + char.length > maxLength) {
      break;
    }
    result += char;
  }
  return result;
}

// For names, file names and similar single-line fields: like sanitizeUserText, additionally
// without line breaks and tabs (turned into spaces) and without whitespace at the edges.
export function sanitizeSingleLineText(
  input: string,
  maxLength: number,
): string {
  const cleaned = sanitizeUserText(input, input.length)
    .replace(/\s+/g, ' ')
    .trim();
  return sanitizeUserText(cleaned, maxLength);
}
