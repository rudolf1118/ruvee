import { z } from 'zod';

/**
 * Item body schema version 1 (cryptographic-design §5.2: "Item schemas are defined in Phase 3").
 * Everything here is inside the `ITEM_BODY` envelope; the server sees none of it. The version
 * number is part of the AAD, so a body can only be read as the version it was written with.
 *
 * Bounds keep a body well inside the 65,535-byte unpadded limit even with every field full of
 * four-byte characters, so a valid item always encrypts.
 */
export const ITEM_SCHEMA_VERSION = 1;

export const ITEM_LIMITS = {
  title: 200,
  username: 500,
  password: 1024,
  url: 2048,
  urls: 5,
  notes: 4000,
  noteText: 8000,
  tag: 40,
  tags: 20,
} as const;

const text = (max: number) => z.string().max(max);
const tag = z
  .string()
  .min(1)
  .max(ITEM_LIMITS.tag)
  .refine((t) => t === t.trim() && !t.includes(','), { message: 'tag' });
const timestamp = z.int().min(0).max(Number.MAX_SAFE_INTEGER);

const common = {
  v: z.literal(ITEM_SCHEMA_VERSION),
  title: text(ITEM_LIMITS.title).min(1),
  favorite: z.boolean(),
  /** Trash is a field inside the ciphertext (sync-protocol §8); null when not trashed. */
  trashedAtMs: timestamp.nullable(),
  tags: z.array(tag).max(ITEM_LIMITS.tags),
  createdAtMs: timestamp,
  updatedAtMs: timestamp,
};

export const loginBodySchema = z.strictObject({
  ...common,
  type: z.literal('login'),
  login: z.strictObject({
    username: text(ITEM_LIMITS.username),
    password: text(ITEM_LIMITS.password),
    urls: z.array(text(ITEM_LIMITS.url).min(1)).max(ITEM_LIMITS.urls),
    notes: text(ITEM_LIMITS.notes),
  }),
});

export const noteBodySchema = z.strictObject({
  ...common,
  type: z.literal('note'),
  note: z.strictObject({ text: text(ITEM_LIMITS.noteText) }),
});

export const itemBodySchema = z.discriminatedUnion('type', [loginBodySchema, noteBodySchema]);
export type ItemBody = z.infer<typeof itemBodySchema>;
export type LoginBody = z.infer<typeof loginBodySchema>;
export type NoteBody = z.infer<typeof noteBodySchema>;

const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

/** Compact JSON of a validated body; the caller encrypts it. */
export function encodeItemBody(body: ItemBody): Uint8Array {
  return encoder.encode(JSON.stringify(itemBodySchema.parse(body)));
}

/**
 * Strict decoding of decrypted bytes. Anything that is not a valid version-1 body is refused;
 * the caller marks the item unreadable and keeps its record (cryptographic-design §7).
 */
export function decodeItemBody(bytes: Uint8Array): ItemBody | undefined {
  try {
    const parsed = itemBodySchema.safeParse(JSON.parse(decoder.decode(bytes)));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

/** Tags as the editor accepts them: comma separated, trimmed, unique, empty ones dropped. */
export function parseTags(input: string): string[] {
  const seen = new Set<string>();
  for (const raw of input.split(',')) {
    const t = raw.trim();
    if (t) seen.add(t);
  }
  return [...seen];
}
