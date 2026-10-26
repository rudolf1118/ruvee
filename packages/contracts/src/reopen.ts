import { z } from 'zod';
import { OPAQUE_BYTES, U32_MAX, kdfProfileSchema, uuidSchema, usernameSchema } from './auth.js';
import { base64urlBytes } from './bytes.js';
import { recoveryStartRequestSchema } from './recovery.js';

/**
 * Reopening a restored installation (backup-restore.md §3.13, D-30 option B, approved for
 * development). While the restore guard is `reopening`, only these endpoints answer. A reopening
 * needs a single-use code printed on the server host **and** the snapshot-time credentials: the
 * master password from a device active in the snapshot, or the Recovery Key. It yields a
 * restricted session (its own cookie, 30 minutes) that can only read the encrypted material,
 * register a new password, and complete: new password and new Recovery Kit in one transaction.
 * Completion uses `recoveryCompleteRequestSchema`.
 */

export const REOPEN_SESSION_MS = 30 * 60_000;
export const REOPEN_COOKIE_SECURE = '__Host-ruvee_reopen';
export const REOPEN_COOKIE_INSECURE_DEV = 'ruvee_reopen';

/** `RC1-` and 32 random bytes in unpadded base64url; never in a URL, log or browser storage. */
export const reopenCodeSchema = z.string().regex(/^RC1-[A-Za-z0-9_-]{43}$/);

export const reopenLoginStartRequestSchema = z.strictObject({
  reopenCode: reopenCodeSchema,
  username: usernameSchema,
  startLoginRequest: base64urlBytes({ length: OPAQUE_BYTES.startLoginRequest }),
  /** The password path needs a device that is active in the snapshot: it holds `SK`. */
  deviceId: uuidSchema,
});
export type ReopenLoginStartRequest = z.infer<typeof reopenLoginStartRequestSchema>;

export const reopenRecoveryStartRequestSchema = recoveryStartRequestSchema.extend({
  reopenCode: reopenCodeSchema,
});
export type ReopenRecoveryStartRequest = z.infer<typeof reopenRecoveryStartRequestSchema>;

export const reopenStartResponseSchema = z.strictObject({
  accountId: uuidSchema,
  deviceId: uuidSchema,
  via: z.enum(['password', 'recovery']),
  expiresAt: z.iso.datetime({ offset: false }),
});
export type ReopenStartResponse = z.infer<typeof reopenStartResponseSchema>;

/**
 * The encrypted material a reopen session may read: the wrap of its own path (the password wrap
 * opens only with `SK`; the recovery wrap only with `RK`), the keyset, and the ids to rotate.
 */
export const reopenMaterialResponseSchema = z.strictObject({
  accountId: uuidSchema,
  via: z.enum(['password', 'recovery']),
  akId: base64urlBytes({ length: 16 }),
  akEpoch: z.int().min(0).max(U32_MAX),
  keysetVersion: z.int().min(0).max(U32_MAX),
  keyset: base64urlBytes({ min: 61, max: 16_445 }),
  recoveryKeyId: base64urlBytes({ length: 16 }),
  rowVersion: z.int().min(1),
  password: z
    .strictObject({
      kdfProfile: kdfProfileSchema,
      saltPw: base64urlBytes({ length: 16 }),
      wrappedAkPassword: base64urlBytes({ length: 93 }),
    })
    .optional(),
  wrappedAkRecovery: base64urlBytes({ length: 93 }).optional(),
});
export type ReopenMaterialResponse = z.infer<typeof reopenMaterialResponseSchema>;
