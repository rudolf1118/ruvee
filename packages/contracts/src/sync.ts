import { z } from 'zod';
import { uuidSchema } from './auth.js';
import { base64urlBytes } from './bytes.js';

/**
 * Vault sync contracts (sync-protocol.md, api-design.md §Sync). Records and manifests are
 * client ciphertext; the server checks only their framing and headers.
 */

export const ITEM_RECORD_MAX_BYTES = 65_702;
export const MANIFEST_BYTES = 198;
export const MAX_MUTATIONS_PER_COMMIT = 100;
/** Decoded record bytes in one commit (sync-protocol §4.2). */
export const MAX_COMMIT_RECORD_BYTES = 2 * 1024 * 1024;
/** Request body limit for `POST /sync/commits`: 2 MiB of records in base64url plus framing. */
export const MAX_COMMIT_BODY_BYTES = 4 * 1024 * 1024;
export const SYNC_PAGE_MIN = 100;
export const SYNC_PAGE_MAX = 500;
/** Manifests returned in one page; a longer history is paged by `nextCursor`. */
export const SYNC_MANIFESTS_PER_PAGE_MAX = 1000;

/** Positive integers below 2^53, which is far beyond any V1 sequence or revision. */
const counter = z.int().min(0).max(Number.MAX_SAFE_INTEGER);

export const recordSchema = base64urlBytes({ min: 1, max: ITEM_RECORD_MAX_BYTES });
export const manifestSchema = base64urlBytes({ length: MANIFEST_BYTES });

export const vaultStateResponseSchema = z.strictObject({
  vaultId: uuidSchema,
  vkId: base64urlBytes({ length: 16 }),
  currentSeq: counter,
});
export type VaultStateResponse = z.infer<typeof vaultStateResponseSchema>;

/** Query of `GET /sync/changes`, as strings. */
export const syncChangesQuerySchema = z.strictObject({
  since: z.string().regex(/^(0|[1-9][0-9]{0,15})$/),
  limit: z
    .string()
    .regex(/^[1-9][0-9]{2}$/)
    .refine((v) => Number(v) >= SYNC_PAGE_MIN && Number(v) <= SYNC_PAGE_MAX)
    .optional(),
});
export type SyncChangesQuery = z.infer<typeof syncChangesQuerySchema>;

export const syncItemSchema = z.strictObject({
  itemId: uuidSchema,
  revision: counter.min(1),
  updatedSeq: counter.min(1),
  record: recordSchema.nullable(),
});
export type SyncItem = z.infer<typeof syncItemSchema>;

export const syncChangesResponseSchema = z.strictObject({
  vaultId: uuidSchema,
  currentSeq: counter,
  /** The last `seq` this page covers; items and manifests above it come in later pages. */
  pageEndSeq: counter,
  items: z.array(syncItemSchema).max(SYNC_PAGE_MAX),
  manifests: z
    .array(z.strictObject({ seq: counter.min(1), manifest: manifestSchema }))
    .max(SYNC_MANIFESTS_PER_PAGE_MAX),
  nextCursor: counter.optional(),
});
export type SyncChangesResponse = z.infer<typeof syncChangesResponseSchema>;

export const mutationSchema = z.strictObject({
  itemId: uuidSchema,
  baseRevision: counter,
  newRevision: counter.min(1),
  /** Null for a permanent deletion (tombstone). */
  record: recordSchema.nullable(),
});
export type Mutation = z.infer<typeof mutationSchema>;

export const commitRequestSchema = z.strictObject({
  vaultId: uuidSchema,
  commitId: uuidSchema,
  baseSeq: counter,
  mutations: z.array(mutationSchema).max(MAX_MUTATIONS_PER_COMMIT),
  manifest: manifestSchema,
});
export type CommitRequest = z.infer<typeof commitRequestSchema>;

export const commitResponseSchema = z.strictObject({ seq: counter.min(1) });
export type CommitResponse = z.infer<typeof commitResponseSchema>;

export const seqConflictDetailsSchema = z.strictObject({ currentSeq: counter });
export const revisionConflictDetailsSchema = z.strictObject({
  conflicts: z
    .array(
      z.strictObject({
        itemId: uuidSchema,
        /** Null when the item does not exist on the server. */
        currentRevision: counter.nullable(),
        tombstone: z.boolean(),
      }),
    )
    .max(MAX_MUTATIONS_PER_COMMIT),
});
