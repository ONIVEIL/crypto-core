/**
 * @format
 */
import {describe, it, expect} from '@jest/globals';
import {
  decodeMessageContent,
  detectUnrecognizedMessageType,
  encodeMessageContent,
  MAX_ATTACHMENT_BYTES,
  MAX_CONTENT_BYTES,
  MAX_GROUP_MEMBERS,
  MessageContent,
} from '../src/crypto/messageContent';

const VALID_KEY = 'ab'.repeat(32);
// All IDs must now match the format that the messaging layer actually generates
// (bytesToHex(randomBytes(16)) — 32 hex characters), see HEX_16_BYTES_PATTERN in validation.ts
// (path-traversal protection for 'media'.id, which is used as a file name).
const ID_1 = '11'.repeat(16);
const ID_2 = '22'.repeat(16);
const TRANSFER_ID = '33'.repeat(16);
const GROUP_ID = '44'.repeat(16);
const VALID_ONION = `${'a'.repeat(56)}.onion`;
const VALID_MEMBER = {
  onionAddress: VALID_ONION,
  signingPublicKey: VALID_KEY,
  encryptionPublicKey: VALID_KEY,
};

describe('messageContent', () => {
  it('encodes and decodes a text message without loss', () => {
    const content: MessageContent = {
      v: 1,
      type: 'text',
      id: ID_1,
      body: 'hallo welt',
      replyToId: ID_2,
    };

    const decoded = decodeMessageContent(encodeMessageContent(content));

    expect(decoded).toEqual(content);
  });

  it('encodes a text message without replyToId without setting the field', () => {
    const encoded = encodeMessageContent({
      v: 1,
      type: 'text',
      id: ID_1,
      body: 'hi',
    });
    expect(JSON.parse(encoded)).not.toHaveProperty('replyToId');
  });

  it('returns null if a text message lacks the ID', () => {
    expect(
      decodeMessageContent(JSON.stringify({v: 1, type: 'text', body: 'x'})),
    ).toBeNull();
    expect(
      decodeMessageContent(
        JSON.stringify({v: 1, type: 'text', id: '', body: 'x'}),
      ),
    ).toBeNull();
  });

  it('round-trips reaction/read/edit/delete without loss', () => {
    const cases: MessageContent[] = [
      {v: 1, type: 'reaction', targetId: ID_1, emoji: '👍'},
      {v: 1, type: 'reaction', targetId: ID_1, emoji: null},
      {v: 1, type: 'read', messageIds: [ID_1, ID_2]},
      {v: 1, type: 'edit', targetId: ID_1, body: 'neuer text'},
      {v: 1, type: 'delete', targetId: ID_1},
    ];
    for (const content of cases) {
      expect(decodeMessageContent(encodeMessageContent(content))).toEqual(
        content,
      );
    }
  });

  it('returns null for broken JSON instead of throwing', () => {
    expect(decodeMessageContent('{nicht valide')).toBeNull();
  });

  it('returns null for a JSON value that is not an object', () => {
    expect(decodeMessageContent('"nur ein string"')).toBeNull();
    expect(decodeMessageContent('42')).toBeNull();
    expect(decodeMessageContent('null')).toBeNull();
  });

  it('returns null for a wrong/missing version number', () => {
    expect(
      decodeMessageContent(JSON.stringify({v: 2, type: 'text', body: 'x'})),
    ).toBeNull();
    expect(
      decodeMessageContent(JSON.stringify({type: 'text', body: 'x'})),
    ).toBeNull();
  });

  it('returns null for an unknown type instead of throwing (forward compatibility)', () => {
    expect(
      decodeMessageContent(
        JSON.stringify({v: 1, type: 'zukunfts-feature', irgendwas: true}),
      ),
    ).toBeNull();
  });

  it('returns null if required fields are missing or have the wrong type', () => {
    expect(
      decodeMessageContent(JSON.stringify({v: 1, type: 'text'})),
    ).toBeNull();
    expect(
      decodeMessageContent(JSON.stringify({v: 1, type: 'text', body: 42})),
    ).toBeNull();
    expect(
      decodeMessageContent(
        JSON.stringify({v: 1, type: 'reaction', targetId: 'm1'}),
      ),
    ).toBeNull();
    expect(
      decodeMessageContent(
        JSON.stringify({v: 1, type: 'read', messageIds: 'nicht-array'}),
      ),
    ).toBeNull();
    expect(
      decodeMessageContent(
        JSON.stringify({v: 1, type: 'read', messageIds: ['ok', 42]}),
      ),
    ).toBeNull();
  });

  it('encodes and decodes an unsupported feedback without loss', () => {
    const content: MessageContent = {
      v: 1,
      type: 'unsupported',
      targetId: ID_1,
    };
    expect(decodeMessageContent(encodeMessageContent(content))).toEqual(
      content,
    );
  });

  it('returns null for unsupported if targetId is missing or wrongly formatted', () => {
    expect(
      decodeMessageContent(JSON.stringify({v: 1, type: 'unsupported'})),
    ).toBeNull();
    expect(
      decodeMessageContent(
        JSON.stringify({v: 1, type: 'unsupported', targetId: 'zu-kurz'}),
      ),
    ).toBeNull();
  });

  it('encodes and decodes an unsupported feedback WITH groupId without loss (group case)', () => {
    const content: MessageContent = {
      v: 1,
      type: 'unsupported',
      targetId: ID_1,
      groupId: GROUP_ID,
    };
    expect(decodeMessageContent(encodeMessageContent(content))).toEqual(
      content,
    );
  });

  it('returns null for unsupported if groupId is present but wrongly formatted', () => {
    expect(
      decodeMessageContent(
        JSON.stringify({
          v: 1,
          type: 'unsupported',
          targetId: ID_1,
          groupId: 'nicht-hex',
        }),
      ),
    ).toBeNull();
  });

  describe('detectUnrecognizedMessageType (version compatibility)', () => {
    it('recognizes a well-formed envelope with an unknown type and returns its id', () => {
      const raw = JSON.stringify({
        v: 1,
        type: 'zukunfts-feature',
        id: ID_1,
        irgendwas: true,
      });
      expect(detectUnrecognizedMessageType(raw)).toEqual({
        targetId: ID_1,
        groupId: undefined,
      });
    });

    it('returns null if the unknown type carries no recognizable id', () => {
      const raw = JSON.stringify({v: 1, type: 'zukunfts-feature'});
      expect(detectUnrecognizedMessageType(raw)).toBeNull();
    });

    it('returns null for a KNOWN type, even if its fields are invalid (no oracle for broken/manipulated content)', () => {
      // 'text' is known — only `body` is missing here, which is a validation error of a known
      // type, not a forward-compatibility case. Must NOT be recognized as "unknown", otherwise
      // detectUnrecognizedMessageType itself would become an oracle for the reason of a decoding
      // failure.
      const raw = JSON.stringify({v: 1, type: 'text', id: ID_1});
      expect(detectUnrecognizedMessageType(raw)).toBeNull();
    });

    it('returns null for broken JSON, a wrong version or an oversized object', () => {
      expect(detectUnrecognizedMessageType('{kaputt')).toBeNull();
      expect(
        detectUnrecognizedMessageType(
          JSON.stringify({v: 2, type: 'zukunfts-feature', id: ID_1}),
        ),
      ).toBeNull();
      expect(
        detectUnrecognizedMessageType(
          JSON.stringify({
            v: 1,
            type: 'zukunfts-feature',
            id: ID_1,
            body: 'x'.repeat(MAX_CONTENT_BYTES + 1),
          }),
        ),
      ).toBeNull();
    });

    it('recognizes an unknown type WITH groupId and returns targetId+groupId (group case)', () => {
      const raw = JSON.stringify({
        v: 1,
        type: 'group-zukunfts-feature',
        groupId: GROUP_ID,
        id: ID_1,
      });
      expect(detectUnrecognizedMessageType(raw)).toEqual({
        targetId: ID_1,
        groupId: GROUP_ID,
      });
    });

    it('returns null if groupId is present but not a valid hex format', () => {
      const raw = JSON.stringify({
        v: 1,
        type: 'group-zukunfts-feature',
        groupId: 'nicht-hex',
        id: ID_1,
      });
      expect(detectUnrecognizedMessageType(raw)).toBeNull();
    });
  });

  it('rejects an oversized encoded object before parsing at all', () => {
    const huge = JSON.stringify({
      v: 1,
      type: 'text',
      body: 'x'.repeat(MAX_CONTENT_BYTES + 1),
    });
    expect(huge.length).toBeGreaterThan(MAX_CONTENT_BYTES);
    expect(decodeMessageContent(huge)).toBeNull();
  });

  it('sanitizes the text of a text message on decoding (spoofing characters/length)', () => {
    const malicious = 'y'.repeat(5000) + '‮' + 'z'.repeat(10);
    const decoded = decodeMessageContent(
      JSON.stringify({v: 1, type: 'text', id: ID_1, body: malicious}),
    );
    expect(decoded?.type).toBe('text');
    expect((decoded as {body: string}).body).toHaveLength(4000);
    expect((decoded as {body: string}).body).not.toContain('‮');
  });

  describe('media', () => {
    it('encodes and decodes an attachment announcement without loss', () => {
      const content: MessageContent = {
        v: 1,
        type: 'media',
        id: ID_1,
        transferId: TRANSFER_ID,
        filename: 'urlaub.jpg',
        mimeType: 'image/jpeg',
        size: 12345,
        key: VALID_KEY,
        replyToId: ID_2,
      };
      expect(decodeMessageContent(encodeMessageContent(content))).toEqual(
        content,
      );
    });

    it('encodes and decodes an attachment announcement WITH accompanying text (caption) without loss', () => {
      const content: MessageContent = {
        v: 1,
        type: 'media',
        id: ID_1,
        transferId: TRANSFER_ID,
        filename: 'urlaub.jpg',
        mimeType: 'image/jpeg',
        size: 12345,
        key: VALID_KEY,
        caption: 'schau mal hier!',
      };
      expect(decodeMessageContent(encodeMessageContent(content))).toEqual(
        content,
      );
    });

    it('leaves caption out (undefined) if none was sent — no empty string forced', () => {
      const decoded = decodeMessageContent(
        JSON.stringify({
          v: 1,
          type: 'media',
          id: ID_1,
          transferId: TRANSFER_ID,
          filename: 'a.jpg',
          mimeType: 'image/jpeg',
          size: 10,
          key: VALID_KEY,
        }),
      );
      expect(decoded?.type).toBe('media');
      expect(
        (decoded as Extract<MessageContent, {type: 'media'}>).caption,
      ).toBeUndefined();
    });

    it('sanitizes an oversized/malicious caption on decoding exactly like a normal text message', () => {
      const malicious = 'y'.repeat(5000) + '‮' + 'z'.repeat(10);
      const decoded = decodeMessageContent(
        JSON.stringify({
          v: 1,
          type: 'media',
          id: ID_1,
          transferId: TRANSFER_ID,
          filename: 'a.jpg',
          mimeType: 'image/jpeg',
          size: 10,
          key: VALID_KEY,
          caption: malicious,
        }),
      );
      expect(decoded?.type).toBe('media');
      const media = decoded as Extract<MessageContent, {type: 'media'}>;
      expect(media.caption).toHaveLength(4000);
      expect(media.caption).not.toContain('‮');
    });

    it('returns null if caption is present but not a string', () => {
      expect(
        decodeMessageContent(
          JSON.stringify({
            v: 1,
            type: 'media',
            id: ID_1,
            transferId: TRANSFER_ID,
            filename: 'a.jpg',
            mimeType: 'image/jpeg',
            size: 10,
            key: VALID_KEY,
            caption: 123,
          }),
        ),
      ).toBeNull();
    });

    it('returns null if the key is not a valid 32-byte hex value', () => {
      expect(
        decodeMessageContent(
          JSON.stringify({
            v: 1,
            type: 'media',
            id: 'm1',
            transferId: 't1',
            filename: 'a.jpg',
            mimeType: 'image/jpeg',
            size: 10,
            key: 'zu-kurz',
          }),
        ),
      ).toBeNull();
    });

    it('returns null if size exceeds the upper limit, is negative or not an integer', () => {
      // IMPORTANT: id/transferId must be valid HEX_16_BYTES_PATTERN values here (not 'm1'/'t1') —
      // otherwise the decode already fails earlier because of id/transferId and this test would no
      // longer exercise the size check itself at all (it would always get null back regardless of
      // the actual size value, and so stay green unnoticed even with a broken/removed size
      // check).
      const base = {
        v: 1,
        type: 'media',
        id: ID_1,
        transferId: TRANSFER_ID,
        filename: 'a.jpg',
        mimeType: 'image/jpeg',
        key: VALID_KEY,
      };
      expect(
        decodeMessageContent(
          JSON.stringify({...base, size: MAX_ATTACHMENT_BYTES + 1}),
        ),
      ).toBeNull();
      expect(
        decodeMessageContent(JSON.stringify({...base, size: -1})),
      ).toBeNull();
      expect(
        decodeMessageContent(JSON.stringify({...base, size: 1.5})),
      ).toBeNull();
      expect(
        decodeMessageContent(JSON.stringify({...base, size: 0})),
      ).toBeNull();
    });

    // registerIncomingTransfer (in the attachment registry) is called ONLY if
    // decodeMessageContent previously returned a non-null 'media' object (in the messaging
    // layer's content processing, `else if (content?.type === 'media')`) — the size check here is
    // thus the only instance BEFORE any actual memory/file resource reservation for an incoming
    // transfer. Only `MAX_ATTACHMENT_BYTES + 1` was tested so far; an absurdly high but still
    // technically valid integer value (Number.MAX_SAFE_INTEGER, as a malicious sender could
    // freely write it into the JSON) must be rejected just as reliably BEFORE any follow-up
    // processing, not only just above the limit.
    it('rejects an absurdly high size (Number.MAX_SAFE_INTEGER) before any resource would be reserved', () => {
      const base = {
        v: 1,
        type: 'media',
        id: ID_1,
        transferId: TRANSFER_ID,
        filename: 'a.jpg',
        mimeType: 'image/jpeg',
        key: VALID_KEY,
      };
      expect(
        decodeMessageContent(
          JSON.stringify({...base, size: Number.MAX_SAFE_INTEGER}),
        ),
      ).toBeNull();
    });

    it('accepts size exactly at the upper limit (the boundary value itself is still valid)', () => {
      const base = {
        v: 1,
        type: 'media',
        id: ID_1,
        transferId: TRANSFER_ID,
        filename: 'a.jpg',
        mimeType: 'image/jpeg',
        key: VALID_KEY,
      };
      const decoded = decodeMessageContent(
        JSON.stringify({...base, size: MAX_ATTACHMENT_BYTES}),
      );
      expect(decoded?.type).toBe('media');
      expect(
        (decoded as Extract<MessageContent, {type: 'media'}>).size,
      ).toBe(MAX_ATTACHMENT_BYTES);
    });

    it('sanitizes file name and MIME type on decoding', () => {
      const decoded = decodeMessageContent(
        JSON.stringify({
          v: 1,
          type: 'media',
          id: ID_1,
          transferId: TRANSFER_ID,
          filename: 'x'.repeat(500),
          mimeType: 'y'.repeat(500),
          size: 10,
          key: VALID_KEY,
        }),
      );
      expect(decoded?.type).toBe('media');
      const media = decoded as Extract<MessageContent, {type: 'media'}>;
      expect(media.filename).toHaveLength(255);
      expect(media.mimeType).toHaveLength(128);
    });

    it('returns null if transferId, filename or mimeType are missing', () => {
      const base = {
        v: 1,
        type: 'media',
        id: ID_1,
        size: 10,
        key: VALID_KEY,
      };
      expect(
        decodeMessageContent(
          JSON.stringify({...base, filename: 'a', mimeType: 'b'}),
        ),
      ).toBeNull(); // transferId missing
      expect(
        decodeMessageContent(
          JSON.stringify({...base, transferId: 't1', mimeType: 'b'}),
        ),
      ).toBeNull(); // filename missing
    });
  });

  describe('groups', () => {
    it('encodes and decodes group-text/reaction/read/edit/delete without loss', () => {
      const cases: MessageContent[] = [
        {
          v: 1,
          type: 'group-text',
          groupId: GROUP_ID,
          id: ID_1,
          body: 'hallo gruppe',
          replyToId: ID_2,
        },
        {
          v: 1,
          type: 'group-reaction',
          groupId: GROUP_ID,
          targetId: ID_1,
          emoji: '👍',
        },
        {
          v: 1,
          type: 'group-read',
          groupId: GROUP_ID,
          messageIds: [ID_1, ID_2],
        },
        {
          v: 1,
          type: 'group-edit',
          groupId: GROUP_ID,
          targetId: ID_1,
          body: 'neuer text',
        },
        {v: 1, type: 'group-delete', groupId: GROUP_ID, targetId: ID_1},
      ];
      for (const content of cases) {
        expect(decodeMessageContent(encodeMessageContent(content))).toEqual(
          content,
        );
      }
    });

    it('returns null if group-* messages carry no valid groupId', () => {
      expect(
        decodeMessageContent(
          JSON.stringify({
            v: 1,
            type: 'group-text',
            groupId: 'nicht-hex',
            id: ID_1,
            body: 'x',
          }),
        ),
      ).toBeNull();
      expect(
        decodeMessageContent(
          JSON.stringify({
            v: 1,
            type: 'group-delete',
            groupId: 'nicht-hex',
            targetId: ID_1,
          }),
        ),
      ).toBeNull();
    });

    it('encodes and decodes group-media without loss', () => {
      const content: MessageContent = {
        v: 1,
        type: 'group-media',
        groupId: GROUP_ID,
        id: ID_1,
        transferId: TRANSFER_ID,
        filename: 'urlaub.jpg',
        mimeType: 'image/jpeg',
        size: 12345,
        key: VALID_KEY,
        replyToId: ID_2,
      };
      expect(decodeMessageContent(encodeMessageContent(content))).toEqual(
        content,
      );
    });

    it('encodes and decodes group-media WITH accompanying text (caption) without loss', () => {
      const content: MessageContent = {
        v: 1,
        type: 'group-media',
        groupId: GROUP_ID,
        id: ID_1,
        transferId: TRANSFER_ID,
        filename: 'urlaub.jpg',
        mimeType: 'image/jpeg',
        size: 12345,
        key: VALID_KEY,
        caption: 'gruppen-begleittext',
      };
      expect(decodeMessageContent(encodeMessageContent(content))).toEqual(
        content,
      );
    });

    it('returns null for group-media if caption is present but not a string', () => {
      expect(
        decodeMessageContent(
          JSON.stringify({
            v: 1,
            type: 'group-media',
            groupId: GROUP_ID,
            id: ID_1,
            transferId: TRANSFER_ID,
            filename: 'a.jpg',
            mimeType: 'image/jpeg',
            size: 10,
            key: VALID_KEY,
            caption: 123,
          }),
        ),
      ).toBeNull();
    });

    it('encodes and decodes group-meta without loss', () => {
      const content: MessageContent = {
        v: 1,
        type: 'group-meta',
        groupId: GROUP_ID,
        stateVersion: 3,
        name: 'Freunde',
        members: [VALID_MEMBER, VALID_MEMBER],
      };
      expect(decodeMessageContent(encodeMessageContent(content))).toEqual(
        content,
      );
    });

    it('returns null if group-meta carries a negative/non-integer stateVersion', () => {
      const base = {
        v: 1,
        type: 'group-meta',
        groupId: GROUP_ID,
        name: 'Freunde',
        members: [VALID_MEMBER],
      };
      expect(
        decodeMessageContent(JSON.stringify({...base, stateVersion: -1})),
      ).toBeNull();
      expect(
        decodeMessageContent(JSON.stringify({...base, stateVersion: 1.5})),
      ).toBeNull();
      expect(
        decodeMessageContent(JSON.stringify({...base})),
      ).toBeNull(); // missing entirely
    });

    it('returns null if group-meta carries an empty or oversized member list', () => {
      const base = {
        v: 1,
        type: 'group-meta',
        groupId: GROUP_ID,
        stateVersion: 1,
        name: 'Freunde',
      };
      expect(
        decodeMessageContent(JSON.stringify({...base, members: []})),
      ).toBeNull();
      expect(
        decodeMessageContent(
          JSON.stringify({
            ...base,
            members: Array.from({length: MAX_GROUP_MEMBERS + 1}, () => VALID_MEMBER),
          }),
        ),
      ).toBeNull();
    });

    it('returns null if a member in group-meta carries an invalid onion address or invalid keys', () => {
      const base = {
        v: 1,
        type: 'group-meta',
        groupId: GROUP_ID,
        stateVersion: 1,
        name: 'Freunde',
      };
      expect(
        decodeMessageContent(
          JSON.stringify({
            ...base,
            members: [{...VALID_MEMBER, onionAddress: 'nicht-valide'}],
          }),
        ),
      ).toBeNull();
      expect(
        decodeMessageContent(
          JSON.stringify({
            ...base,
            members: [{...VALID_MEMBER, signingPublicKey: 'zu-kurz'}],
          }),
        ),
      ).toBeNull();
      expect(
        decodeMessageContent(
          JSON.stringify({
            ...base,
            members: [{...VALID_MEMBER, encryptionPublicKey: 'zu-kurz'}],
          }),
        ),
      ).toBeNull();
    });

    it('sanitizes the group name in group-meta on decoding', () => {
      const decoded = decodeMessageContent(
        JSON.stringify({
          v: 1,
          type: 'group-meta',
          groupId: GROUP_ID,
          stateVersion: 1,
          name: 'x'.repeat(200),
          members: [VALID_MEMBER],
        }),
      );
      expect(decoded?.type).toBe('group-meta');
      const meta = decoded as Extract<MessageContent, {type: 'group-meta'}>;
      expect(meta.name).toHaveLength(40);
    });
  });

  describe('group-owner-transfer (owner handover)', () => {
    it('encodes and decodes an owner transfer without loss', () => {
      const content: MessageContent = {
        v: 1,
        type: 'group-owner-transfer',
        groupId: GROUP_ID,
        stateVersion: 3,
        newOwnerSigningPublicKey: VALID_KEY,
      };
      expect(decodeMessageContent(encodeMessageContent(content))).toEqual(
        content,
      );
    });

    it('returns null if groupId is missing or invalid', () => {
      const base = {
        v: 1,
        type: 'group-owner-transfer',
        stateVersion: 1,
        newOwnerSigningPublicKey: VALID_KEY,
      };
      expect(
        decodeMessageContent(JSON.stringify({...base, groupId: 'zu-kurz'})),
      ).toBeNull();
      expect(decodeMessageContent(JSON.stringify(base))).toBeNull(); // missing entirely
    });

    it('returns null if stateVersion is negative or not an integer', () => {
      const base = {
        v: 1,
        type: 'group-owner-transfer',
        groupId: GROUP_ID,
        newOwnerSigningPublicKey: VALID_KEY,
      };
      expect(
        decodeMessageContent(JSON.stringify({...base, stateVersion: -1})),
      ).toBeNull();
      expect(
        decodeMessageContent(JSON.stringify({...base, stateVersion: 1.5})),
      ).toBeNull();
      expect(decodeMessageContent(JSON.stringify(base))).toBeNull(); // missing entirely
    });

    it('returns null if newOwnerSigningPublicKey is missing, too short or not hex (manipulated payload)', () => {
      const base = {
        v: 1,
        type: 'group-owner-transfer',
        groupId: GROUP_ID,
        stateVersion: 1,
      };
      expect(decodeMessageContent(JSON.stringify(base))).toBeNull(); // missing entirely
      expect(
        decodeMessageContent(
          JSON.stringify({...base, newOwnerSigningPublicKey: 'zu-kurz'}),
        ),
      ).toBeNull();
      expect(
        decodeMessageContent(
          JSON.stringify({
            ...base,
            // right length, but not a valid hex alphabet.
            newOwnerSigningPublicKey: 'zz'.repeat(32),
          }),
        ),
      ).toBeNull();
      expect(
        decodeMessageContent(
          JSON.stringify({...base, newOwnerSigningPublicKey: 12345}),
        ),
      ).toBeNull();
    });
  });

  it('limits the length of an emoji field for reactions', () => {
    const decoded = decodeMessageContent(
      JSON.stringify({
        v: 1,
        type: 'reaction',
        targetId: ID_1,
        emoji: 'x'.repeat(100),
      }),
    );
    expect(decoded?.type).toBe('reaction');
    expect((decoded as {emoji: string}).emoji).toHaveLength(16);
  });
});
