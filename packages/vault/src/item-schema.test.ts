import { ITEM_BODY_MAX_BYTES } from '@ruvee/crypto';
import {
  decodeItemBody,
  encodeItemBody,
  ITEM_LIMITS,
  parseTags,
  type ItemBody,
} from './item-schema.js';

const login: ItemBody = {
  v: 1,
  type: 'login',
  title: 'Synthetic Mail',
  favorite: false,
  trashedAtMs: null,
  tags: ['work'],
  createdAtMs: 1,
  updatedAtMs: 2,
  login: {
    username: 'someone@mail.example',
    password: 'synthetic-not-a-secret',
    urls: ['https://mail.example'],
    notes: '',
  },
};

describe('item body schema v1', () => {
  it('round-trips a login and a note', () => {
    expect(decodeItemBody(encodeItemBody(login))).toEqual(login);
    const note: ItemBody = {
      v: 1,
      type: 'note',
      title: 'Synthetic note',
      favorite: true,
      trashedAtMs: 5,
      tags: [],
      createdAtMs: 1,
      updatedAtMs: 1,
      note: { text: 'line 1\nline 2' },
    };
    expect(decodeItemBody(encodeItemBody(note))).toEqual(note);
  });

  it('refuses anything that is not a valid version-1 body', () => {
    const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
    for (const bad of [
      { ...login, v: 2 },
      { ...login, extra: true },
      { ...login, title: '' },
      { ...login, type: 'card' },
      { ...login, tags: ['a,b'] },
      { ...login, login: { ...login.login, urls: [''] } },
    ])
      expect(decodeItemBody(bytes(bad))).toBeUndefined();
    expect(decodeItemBody(new Uint8Array([0xff, 0xfe]))).toBeUndefined();
    expect(decodeItemBody(new TextEncoder().encode('not json'))).toBeUndefined();
    expect(() => encodeItemBody({ ...login, title: '' })).toThrow();
  });

  it('keeps a body with every field at its maximum below the encryptable size', () => {
    const wide = '\u{1f511}';
    const full: ItemBody = {
      ...login,
      title: wide.repeat(ITEM_LIMITS.title / 2),
      tags: Array.from({ length: ITEM_LIMITS.tags }, (_, i) => `${i}`.padEnd(ITEM_LIMITS.tag, 'x')),
      login: {
        username: wide.repeat(ITEM_LIMITS.username / 2),
        password: wide.repeat(ITEM_LIMITS.password / 2),
        urls: Array.from({ length: ITEM_LIMITS.urls }, () => wide.repeat(ITEM_LIMITS.url / 2)),
        notes: wide.repeat(ITEM_LIMITS.notes / 2),
      },
    };
    expect(encodeItemBody(full).length).toBeLessThanOrEqual(ITEM_BODY_MAX_BYTES);
    const note: ItemBody = {
      v: 1,
      type: 'note',
      title: full.title,
      favorite: false,
      trashedAtMs: null,
      tags: full.tags,
      createdAtMs: 1,
      updatedAtMs: 1,
      note: { text: wide.repeat(ITEM_LIMITS.noteText / 2) },
    };
    expect(encodeItemBody(note).length).toBeLessThanOrEqual(ITEM_BODY_MAX_BYTES);
  });

  it('parses comma-separated tags', () => {
    expect(parseTags(' work, travel ,, work,')).toEqual(['work', 'travel']);
    expect(parseTags('')).toEqual([]);
  });
});
