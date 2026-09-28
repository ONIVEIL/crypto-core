// messageContent.ts — The structured, JSON-encoded format behind every encrypted plaintext (see
// session.ts). Practically every feature (reactions, read receipts, editing, deleting, media,
// groups) needs its own content type that the receiver can distinguish — this module is the
// common foundation for that, instead of inventing an ad-hoc format per feature.
//
// Important: `text` messages carry an `id` assigned by the SENDER. Without it, every device would
// assign its own random local ID when storing (two independent devices would never arrive at the
// same ID for "the same" message), so later reactions/read receipts/edits/deletes (which
// reference a message by ID) would never find anything at the receiver. The ID is generated once
// by the sender, sent along with the message, and used unchanged on both devices as the local
// message ID — which makes it the same, stable identifier for the same message on both sides.
//
// `encryptMessage`/`decryptMessage` in session.ts still only know "plaintext in/out" — the
// encoding/decoding of this format happens one layer above.
import {
  HEX_16_BYTES_PATTERN,
  HEX_32_BYTES_PATTERN,
  MAX_DISPLAY_NAME_LENGTH,
  MAX_MESSAGE_LENGTH,
  ONION_V3_PATTERN,
  sanitizeUserText,
} from './validation';

export const MAX_FILENAME_LENGTH = 255;
export const MAX_MIME_TYPE_LENGTH = 128;

// Upper bound for the total size of the encoded JSON object itself (not just individual text
// fields) — checked BEFORE JSON.parse is called at all. Without it, a maliciously large but
// otherwise formally valid object (e.g. a huge messageIds list in a 'read' message) would be a
// memory-DoS vector on the receiver side — same principle as the existing frame-length check in
// src/transport/wireProtocol.ts. Well above MAX_MESSAGE_LENGTH, so that legitimate text messages
// (which additionally carry JSON structure overhead) safely fit.
export const MAX_CONTENT_BYTES = 8 * 1024;

// Upper bound for the total size of an attachment (plaintext bytes, before encryption) — coarse
// memory/bandwidth DoS protection and (for transfer over Tor with potentially limited speed) a
// limit on transfer duration. Checked both when sending (before anything is encrypted/transferred)
// and when receiving, against the `size` claimed by the sender in the 'media' content — and
// additionally against the byte count ACTUALLY received, so that lying about `size` (declaring
// too little, then sending more data) does not bypass the check.
export const MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024;

// Upper bound for the participant list of a group (group-meta) — a pure structure check
// analogous to MAX_MEDIA_CHUNKS in wireProtocol.ts: prevents a maliciously inflated `members`
// array from binding unbounded memory/processing time on its own (before any further
// processing). IMPORTANT: must be chosen so that a group-meta with this many members, when
// encoded, actually stays below MAX_CONTENT_BYTES — otherwise decodeMessageContent would simply
// discard an otherwise valid group-meta at the receiver (null) without any error becoming
// visible. 25 members encode, even with a maximum-length group name, to about 6.6 KB (well below
// the 8 KB of MAX_CONTENT_BYTES, see __tests__/messageContent.test.ts) — the messaging layer
// additionally checks the actual encoded length at runtime, this value is only the upstream
// structure check. With this fan-out architecture it makes sense to keep it small anyway: every
// additional member means another complete 1:1 send per message.
export const MAX_GROUP_MEMBERS = 25;

export type MessageContent =
  | {v: 1; type: 'text'; id: string; body: string; replyToId?: string}
  | {v: 1; type: 'reaction'; targetId: string; emoji: string | null}
  | {v: 1; type: 'read'; messageIds: string[]}
  | {v: 1; type: 'edit'; targetId: string; body: string}
  | {v: 1; type: 'delete'; targetId: string}
  | {
      v: 1;
      type: 'media';
      id: string;
      transferId: string;
      filename: string;
      mimeType: string;
      size: number;
      // hex, 32 bytes — single-use key for THIS attachment only (see
      // crypto/attachmentCrypto.ts). Travels along here because this content is already
      // encrypted/authenticated by the session ratchet (session.ts) — the attachment bytes
      // themselves do NOT run through the ratchet for size reasons, so they need their own
      // encryption, transported confidentially here.
      key: string;
      replyToId?: string;
      // Optional accompanying text, sent together with the attachment in ONE message (instead of
      // as a separate 'text' message in front of it). Deliberately validated separately from the
      // attachment itself (sanitizeUserText, same upper bound as a normal text message) — the
      // attachment stays independently sendable/displayable even if `caption` is missing or empty.
      caption?: string;
    }
  // Group variants (fan-out architecture): the same message is sent to each member individually
  // over that member's own 1:1 session, so every variant carries a `groupId` that the receiver
  // uses to assign it to the right group thread.
  // IMPORTANT: the sender of a group-* message is NOT part of the content itself — at the
  // receiver it results from WHOSE 1:1 session decrypted the message successfully, and is checked
  // there against the locally known member list (a sender who, according to the current group
  // state, is no longer a member is discarded instead of accepted).
  | {v: 1; type: 'group-text'; groupId: string; id: string; body: string; replyToId?: string}
  | {
      v: 1;
      type: 'group-reaction';
      groupId: string;
      targetId: string;
      emoji: string | null;
    }
  | {v: 1; type: 'group-read'; groupId: string; messageIds: string[]}
  | {v: 1; type: 'group-edit'; groupId: string; targetId: string; body: string}
  | {v: 1; type: 'group-delete'; groupId: string; targetId: string}
  | {
      v: 1;
      type: 'group-media';
      groupId: string;
      id: string;
      transferId: string;
      filename: string;
      mimeType: string;
      size: number;
      key: string;
      replyToId?: string;
      // See 'media' above — the same optional caption, here for the group fan-out.
      caption?: string;
    }
  // Owner→member, directly over the 1:1 session of each individual member (never relayed via
  // another member — the 1:1 session authentication IS already the proof "came from the owner"
  // here). `stateVersion` is a counter assigned by the owner and incremented by 1 on every
  // membership change — a receiver accepts a group-meta only if its stateVersion is greater than
  // the locally known state AND it comes from the locally known owner. `members` lists ALL
  // participants including the owner AND including the receiver itself (uniform broadcast
  // content to every member, no individually assembled payload) — identified via globally unique
  // keys/address instead of local contact IDs, which are randomly assigned per device and
  // meaningless between devices. The receiver recognizes its own entry by its own
  // signingPublicKey and omits it when building the local member list.
  | {
      v: 1;
      type: 'group-meta';
      groupId: string;
      stateVersion: number;
      name: string;
      members: {
        onionAddress: string;
        signingPublicKey: string;
        encryptionPublicKey: string;
      }[];
    }
  // Voluntary owner handover (v1: only while the current owner is online and triggers it
  // themselves — NO recovery mechanism for a permanently offline owner, that would be a separate,
  // much larger takeover attack vector). Owner→member, just like group-meta directly over the 1:1
  // session of each individual member (never relayed via another member) — same stateVersion as
  // group-meta (ONE shared counter, not two separate ones), so that a transfer cannot compete
  // with a concurrent normal group-meta change for "the last valid version".
  // `newOwnerSigningPublicKey` identifies the new owner member via its globally unique key (not
  // via a local contact ID, which is random per device and meaningless between devices — see the
  // group-meta comment above) — the receiver resolves it against its locally already known member
  // list.
  | {
      v: 1;
      type: 'group-owner-transfer';
      groupId: string;
      stateVersion: number;
      newOwnerSigningPublicKey: string;
    }
  // Feedback that a previously received message could not be processed by THIS app version (see
  // detectUnrecognizedMessageType below) — e.g. because it carries a content type introduced only
  // in a newer version. `targetId` references the original message ID (from the original
  // sender's point of view), so that the delivery status shown there can be corrected. `groupId`
  // is only set if the unknown message itself carried a `groupId` field (see
  // detectUnrecognizedMessageType) — it tells the receiver (the original author of the group
  // message) in which group thread `targetId` is to be found, instead of searching the 1:1
  // history.
  | {v: 1; type: 'unsupported'; targetId: string; groupId?: string};

export function encodeMessageContent(content: MessageContent): string {
  return JSON.stringify(content);
}

// Returns `null` for any kind of invalid, unknown or oversized content instead of throwing — a
// single broken content type, or one from a newer/older app version, must not crash the rest of
// the processing (advance the session, send an ack) (forward/backward compatibility). Free-text
// fields are sanitized right here — at the transition from no-longer-trusted network data to
// locally stored/displayed content — instead of leaving that to each caller individually.
export function decodeMessageContent(raw: string): MessageContent | null {
  if (raw.length > MAX_CONTENT_BYTES) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null) {
    return null;
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.v !== 1) {
    return null;
  }

  switch (obj.type) {
    case 'text': {
      if (typeof obj.id !== 'string' || !HEX_16_BYTES_PATTERN.test(obj.id)) {
        return null;
      }
      if (typeof obj.body !== 'string') {
        return null;
      }
      if (
        obj.replyToId !== undefined &&
        (typeof obj.replyToId !== 'string' ||
          !HEX_16_BYTES_PATTERN.test(obj.replyToId))
      ) {
        return null;
      }
      return {
        v: 1,
        type: 'text',
        id: obj.id,
        body: sanitizeUserText(obj.body, MAX_MESSAGE_LENGTH),
        replyToId: obj.replyToId,
      };
    }
    case 'reaction': {
      if (
        typeof obj.targetId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.targetId)
      ) {
        return null;
      }
      if (obj.emoji !== null && typeof obj.emoji !== 'string') {
        return null;
      }
      return {
        v: 1,
        type: 'reaction',
        targetId: obj.targetId,
        emoji: obj.emoji === null ? null : sanitizeUserText(obj.emoji, 16),
      };
    }
    case 'read': {
      if (
        !Array.isArray(obj.messageIds) ||
        !obj.messageIds.every(
          id => typeof id === 'string' && HEX_16_BYTES_PATTERN.test(id),
        )
      ) {
        return null;
      }
      return {v: 1, type: 'read', messageIds: obj.messageIds as string[]};
    }
    case 'edit': {
      if (
        typeof obj.targetId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.targetId) ||
        typeof obj.body !== 'string'
      ) {
        return null;
      }
      return {
        v: 1,
        type: 'edit',
        targetId: obj.targetId,
        body: sanitizeUserText(obj.body, MAX_MESSAGE_LENGTH),
      };
    }
    case 'delete': {
      if (
        typeof obj.targetId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.targetId)
      ) {
        return null;
      }
      return {v: 1, type: 'delete', targetId: obj.targetId};
    }
    case 'media': {
      // `id` is used, among other things, as the file name for local attachment storage — without
      // this strict format check, a malicious contact could force a path-traversal write outside
      // the intended storage folder via a manipulated `id` field (e.g. "../../../something").
      if (typeof obj.id !== 'string' || !HEX_16_BYTES_PATTERN.test(obj.id)) {
        return null;
      }
      if (
        typeof obj.transferId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.transferId)
      ) {
        return null;
      }
      if (
        typeof obj.filename !== 'string' ||
        typeof obj.mimeType !== 'string'
      ) {
        return null;
      }
      if (
        typeof obj.size !== 'number' ||
        !Number.isInteger(obj.size) ||
        obj.size <= 0 ||
        obj.size > MAX_ATTACHMENT_BYTES
      ) {
        return null;
      }
      if (typeof obj.key !== 'string' || !HEX_32_BYTES_PATTERN.test(obj.key)) {
        return null;
      }
      if (
        obj.replyToId !== undefined &&
        (typeof obj.replyToId !== 'string' ||
          !HEX_16_BYTES_PATTERN.test(obj.replyToId))
      ) {
        return null;
      }
      if (obj.caption !== undefined && typeof obj.caption !== 'string') {
        return null;
      }
      return {
        v: 1,
        type: 'media',
        id: obj.id,
        transferId: obj.transferId,
        filename: sanitizeUserText(obj.filename, MAX_FILENAME_LENGTH),
        mimeType: sanitizeUserText(obj.mimeType, MAX_MIME_TYPE_LENGTH),
        size: obj.size,
        key: obj.key,
        replyToId: obj.replyToId,
        caption:
          obj.caption === undefined
            ? undefined
            : sanitizeUserText(obj.caption, MAX_MESSAGE_LENGTH),
      };
    }
    case 'group-text': {
      if (
        typeof obj.groupId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.groupId)
      ) {
        return null;
      }
      if (typeof obj.id !== 'string' || !HEX_16_BYTES_PATTERN.test(obj.id)) {
        return null;
      }
      if (typeof obj.body !== 'string') {
        return null;
      }
      if (
        obj.replyToId !== undefined &&
        (typeof obj.replyToId !== 'string' ||
          !HEX_16_BYTES_PATTERN.test(obj.replyToId))
      ) {
        return null;
      }
      return {
        v: 1,
        type: 'group-text',
        groupId: obj.groupId,
        id: obj.id,
        body: sanitizeUserText(obj.body, MAX_MESSAGE_LENGTH),
        replyToId: obj.replyToId,
      };
    }
    case 'group-reaction': {
      if (
        typeof obj.groupId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.groupId)
      ) {
        return null;
      }
      if (
        typeof obj.targetId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.targetId)
      ) {
        return null;
      }
      if (obj.emoji !== null && typeof obj.emoji !== 'string') {
        return null;
      }
      return {
        v: 1,
        type: 'group-reaction',
        groupId: obj.groupId,
        targetId: obj.targetId,
        emoji: obj.emoji === null ? null : sanitizeUserText(obj.emoji, 16),
      };
    }
    case 'group-read': {
      if (
        typeof obj.groupId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.groupId)
      ) {
        return null;
      }
      if (
        !Array.isArray(obj.messageIds) ||
        !obj.messageIds.every(
          id => typeof id === 'string' && HEX_16_BYTES_PATTERN.test(id),
        )
      ) {
        return null;
      }
      return {
        v: 1,
        type: 'group-read',
        groupId: obj.groupId,
        messageIds: obj.messageIds as string[],
      };
    }
    case 'group-edit': {
      if (
        typeof obj.groupId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.groupId)
      ) {
        return null;
      }
      if (
        typeof obj.targetId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.targetId) ||
        typeof obj.body !== 'string'
      ) {
        return null;
      }
      return {
        v: 1,
        type: 'group-edit',
        groupId: obj.groupId,
        targetId: obj.targetId,
        body: sanitizeUserText(obj.body, MAX_MESSAGE_LENGTH),
      };
    }
    case 'group-delete': {
      if (
        typeof obj.groupId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.groupId)
      ) {
        return null;
      }
      if (
        typeof obj.targetId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.targetId)
      ) {
        return null;
      }
      return {
        v: 1,
        type: 'group-delete',
        groupId: obj.groupId,
        targetId: obj.targetId,
      };
    }
    case 'group-media': {
      if (
        typeof obj.groupId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.groupId)
      ) {
        return null;
      }
      // Same path-traversal rationale as for the 1:1 'media' type above — `id` is used as a
      // file-system path component.
      if (typeof obj.id !== 'string' || !HEX_16_BYTES_PATTERN.test(obj.id)) {
        return null;
      }
      if (
        typeof obj.transferId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.transferId)
      ) {
        return null;
      }
      if (
        typeof obj.filename !== 'string' ||
        typeof obj.mimeType !== 'string'
      ) {
        return null;
      }
      if (
        typeof obj.size !== 'number' ||
        !Number.isInteger(obj.size) ||
        obj.size <= 0 ||
        obj.size > MAX_ATTACHMENT_BYTES
      ) {
        return null;
      }
      if (typeof obj.key !== 'string' || !HEX_32_BYTES_PATTERN.test(obj.key)) {
        return null;
      }
      if (
        obj.replyToId !== undefined &&
        (typeof obj.replyToId !== 'string' ||
          !HEX_16_BYTES_PATTERN.test(obj.replyToId))
      ) {
        return null;
      }
      if (obj.caption !== undefined && typeof obj.caption !== 'string') {
        return null;
      }
      return {
        v: 1,
        type: 'group-media',
        groupId: obj.groupId,
        id: obj.id,
        transferId: obj.transferId,
        filename: sanitizeUserText(obj.filename, MAX_FILENAME_LENGTH),
        mimeType: sanitizeUserText(obj.mimeType, MAX_MIME_TYPE_LENGTH),
        size: obj.size,
        key: obj.key,
        replyToId: obj.replyToId,
        caption:
          obj.caption === undefined
            ? undefined
            : sanitizeUserText(obj.caption, MAX_MESSAGE_LENGTH),
      };
    }
    case 'group-meta': {
      if (
        typeof obj.groupId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.groupId)
      ) {
        return null;
      }
      if (
        typeof obj.stateVersion !== 'number' ||
        !Number.isInteger(obj.stateVersion) ||
        obj.stateVersion < 0
      ) {
        return null;
      }
      if (typeof obj.name !== 'string') {
        return null;
      }
      if (
        !Array.isArray(obj.members) ||
        obj.members.length === 0 ||
        obj.members.length > MAX_GROUP_MEMBERS
      ) {
        return null;
      }
      const members: {
        onionAddress: string;
        signingPublicKey: string;
        encryptionPublicKey: string;
      }[] = [];
      for (const raw of obj.members) {
        if (typeof raw !== 'object' || raw === null) {
          return null;
        }
        const m = raw as Record<string, unknown>;
        if (
          typeof m.onionAddress !== 'string' ||
          !ONION_V3_PATTERN.test(m.onionAddress)
        ) {
          return null;
        }
        if (
          typeof m.signingPublicKey !== 'string' ||
          !HEX_32_BYTES_PATTERN.test(m.signingPublicKey)
        ) {
          return null;
        }
        if (
          typeof m.encryptionPublicKey !== 'string' ||
          !HEX_32_BYTES_PATTERN.test(m.encryptionPublicKey)
        ) {
          return null;
        }
        members.push({
          onionAddress: m.onionAddress,
          signingPublicKey: m.signingPublicKey,
          encryptionPublicKey: m.encryptionPublicKey,
        });
      }
      return {
        v: 1,
        type: 'group-meta',
        groupId: obj.groupId,
        stateVersion: obj.stateVersion,
        name: sanitizeUserText(obj.name, MAX_DISPLAY_NAME_LENGTH),
        members,
      };
    }
    case 'group-owner-transfer': {
      if (
        typeof obj.groupId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.groupId)
      ) {
        return null;
      }
      if (
        typeof obj.stateVersion !== 'number' ||
        !Number.isInteger(obj.stateVersion) ||
        obj.stateVersion < 0
      ) {
        return null;
      }
      if (
        typeof obj.newOwnerSigningPublicKey !== 'string' ||
        !HEX_32_BYTES_PATTERN.test(obj.newOwnerSigningPublicKey)
      ) {
        return null;
      }
      return {
        v: 1,
        type: 'group-owner-transfer',
        groupId: obj.groupId,
        stateVersion: obj.stateVersion,
        newOwnerSigningPublicKey: obj.newOwnerSigningPublicKey,
      };
    }
    case 'unsupported': {
      if (
        typeof obj.targetId !== 'string' ||
        !HEX_16_BYTES_PATTERN.test(obj.targetId)
      ) {
        return null;
      }
      if (
        obj.groupId !== undefined &&
        (typeof obj.groupId !== 'string' ||
          !HEX_16_BYTES_PATTERN.test(obj.groupId))
      ) {
        return null;
      }
      return {
        v: 1,
        type: 'unsupported',
        targetId: obj.targetId,
        groupId: obj.groupId,
      };
    }
    default:
      // Unknown/future type — ignore instead of throwing.
      return null;
  }
}

// All `type` values this app version knows (see MessageContent above) — basis for
// detectUnrecognizedMessageType below. Typed as `Record<MessageContent['type'], true>` instead of
// a plain literal list: an independent list could otherwise silently drift apart from the actual
// `case` branches in decodeMessageContent (a future new MessageContent type whose entry is
// forgotten here would be misclassified by detectUnrecognizedMessageType as an "unknown future
// type" instead of a broken/manipulated KNOWN type). The TypeScript compiler now enforces that
// exactly one entry exists here for EVERY `type` value of MessageContent (no more, no fewer) — if
// one is missing or superfluous, the build fails instead of the discrepancy staying unnoticed
// until runtime.
const KNOWN_MESSAGE_TYPES_RECORD: Record<MessageContent['type'], true> = {
  text: true,
  reaction: true,
  read: true,
  edit: true,
  delete: true,
  media: true,
  'group-text': true,
  'group-reaction': true,
  'group-read': true,
  'group-edit': true,
  'group-delete': true,
  'group-media': true,
  'group-meta': true,
  'group-owner-transfer': true,
  unsupported: true,
};
const KNOWN_MESSAGE_TYPES = new Set(Object.keys(KNOWN_MESSAGE_TYPES_RECORD));

// Detects a structurally well-formed envelope (correct version, JSON object, size within limits)
// whose `type` is UNKNOWN to this app version — the forward-compatibility case of a newer peer
// using a feature not implemented here yet (version mismatch). Deliberately distinguished
// STRICTLY from structurally broken/manipulated content of a KNOWN type (which is still silently
// discarded without any feedback, see decodeMessageContent) — otherwise this feedback would
// itself become an oracle that tells an attacker which exact check a manipulated content failed.
//
// For `group-*` content types (today: group-text/-reaction/-read/-edit/-delete/-media/-meta) the
// 1:1 sender that delivered the message via the session ratchet is in fact ALWAYS also the
// author — there is no relaying via a third member (see the comment at group-meta above; the
// group-content handler checks the sender contact directly against the group's member IDs). An
// "unsupported" can therefore be sent straight back to the 1:1 sender for this case, exactly as
// in the 1:1 case — `groupId` is only passed along additionally so that the author can assign
// the feedback to the right group thread, not because a different recipient would be needed.
export function detectUnrecognizedMessageType(
  raw: string,
): {targetId: string; groupId?: string} | null {
  if (raw.length > MAX_CONTENT_BYTES) {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null) {
    return null;
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.v !== 1) {
    return null;
  }
  if (typeof obj.type !== 'string' || KNOWN_MESSAGE_TYPES.has(obj.type)) {
    return null;
  }
  // All ID-carrying content types so far use `id` in the established 16-byte hex format (see
  // above) — without an ID recognizable that way, the signal cannot be attributed to a specific
  // message and is dropped without consequence (no unspecific "something did not arrive"
  // signal).
  if (typeof obj.id !== 'string' || !HEX_16_BYTES_PATTERN.test(obj.id)) {
    return null;
  }
  if (
    obj.groupId !== undefined &&
    (typeof obj.groupId !== 'string' ||
      !HEX_16_BYTES_PATTERN.test(obj.groupId))
  ) {
    // A groupId field is present but not in a valid format — just as inconsequential as an
    // invalid id: no inference oracle for structurally broken/manipulated group fields.
    return null;
  }
  return {
    targetId: obj.id,
    groupId: typeof obj.groupId === 'string' ? obj.groupId : undefined,
  };
}
