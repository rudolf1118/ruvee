import { ITEM_BODY_MAX_BYTES } from '@ruvee/crypto';
import { readFileSync } from 'node:fs';
import { z } from 'zod';
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
        totp: { secret: 'A'.repeat(103), algorithm: 'SHA512', digits: 8, period: 300 },
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

describe('authenticator field (D-35, totp-authenticator.md §2)', () => {
  const totp = {
    secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ',
    algorithm: 'SHA1',
    digits: 6,
    period: 30,
  } as const;
  const withTotp: ItemBody = { ...login, login: { ...login.login, totp } };
  // The login schema as it was before D-35, pinned here: strict, no totp.
  const before = z.strictObject({
    v: z.literal(1),
    title: z.string().min(1).max(200),
    favorite: z.boolean(),
    trashedAtMs: z.int().min(0).nullable(),
    tags: z.array(z.string()),
    createdAtMs: z.int().min(0),
    updatedAtMs: z.int().min(0),
    type: z.literal('login'),
    login: z.strictObject({
      username: z.string(),
      password: z.string(),
      urls: z.array(z.string().min(1)),
      notes: z.string(),
    }),
  });

  const bytes = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));

  it('round-trips, and refuses a malformed authenticator as a whole body', () => {
    expect(decodeItemBody(encodeItemBody(withTotp))).toEqual(withTotp);
    for (const bad of [
      { ...totp, secret: totp.secret.toLowerCase() },
      { ...totp, digits: 5 },
      { ...totp, extra: 1 },
      null,
      totp.secret,
    ])
      expect(
        decodeItemBody(bytes({ ...login, login: { ...login.login, totp: bad } })),
        JSON.stringify(bad),
      ).toBeUndefined();
  });

  it('encodes a login without one exactly as before the field existed', () => {
    // The previous encoder was JSON.stringify of the body as the old schema parsed it.
    expect(encodeItemBody(login)).toEqual(bytes(before.parse(login)));
    expect(new TextDecoder().decode(encodeItemBody(login))).not.toContain('totp');
  });

  it('every body in the export fixture still decodes (no migration needed)', () => {
    const expected = JSON.parse(
      readFileSync(new URL('../test/fixtures/export-v1.expected.json', import.meta.url), 'utf8'),
    ) as { items: { type: string }[] };
    expect(expected.items.length).toBeGreaterThan(0);
    // The fixture's bodies are opened through decodeItemBody by import.test.ts; this pins that no
    // fixture item carries a totp key, so their encoding is unchanged.
    expect(JSON.stringify(expected)).not.toContain('totp');
  });

  it('a client from before the field refuses a body that has one (unreadable, never stripped)', () => {
    expect(before.safeParse(JSON.parse(JSON.stringify(login))).success).toBe(true);
    expect(before.safeParse(JSON.parse(JSON.stringify(withTotp))).success).toBe(false);
  });
});
