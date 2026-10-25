import { z } from 'zod';
import {
  OPAQUE_BYTES,
  U32_MAX,
  deviceLabelSchema,
  kdfProfileSchema,
  webPlatformSchema,
  uuidSchema,
  usernameSchema,
} from './auth.js';
import { base64urlBytes } from './bytes.js';

/**
 * Recovery with the Recovery Key (account-recovery.md §3), with `RAK` as the proof of possession
 * (D-22, approved for development). A recovery session is a separate session kind, accepted only
 * by these endpoints, and lasts 15 minutes.
 */

export const RECOVERY_SESSION_MS = 15 * 60_000;
export const RECOVERY_COOKIE_SECURE = '__Host-ruvee_recovery';
export const RECOVERY_COOKIE_INSECURE_DEV = 'ruvee_recovery';

export const recoveryStartRequestSchema = z.strictObject({
  username: usernameSchema,
  /** `RAK`, 32 bytes. Compared as `SHA-256(RAK)` in constant time. */
  recoveryAuthKey: base64urlBytes({ length: 32 }),
  device: z.strictObject({ id: uuidSchema, platform: webPlatformSchema }),
});
export type RecoveryStartRequest = z.infer<typeof recoveryStartRequestSchema>;

export const recoveryStartResponseSchema = z.strictObject({
  accountId: uuidSchema,
  deviceId: uuidSchema,
  expiresAt: z.iso.datetime({ offset: false }),
});
export type RecoveryStartResponse = z.infer<typeof recoveryStartResponseSchema>;

/** `GET /recovery/material`: everything `RK` and a new password need. Recovery sessions only. */
export const recoveryMaterialResponseSchema = z.strictObject({
  accountId: uuidSchema,
  recoveryKeyId: base64urlBytes({ length: 16 }),
  wrappedAkRecovery: base64urlBytes({ length: 93 }),
  akId: base64urlBytes({ length: 16 }),
  akEpoch: z.int().min(0).max(U32_MAX),
  keysetVersion: z.int().min(0).max(U32_MAX),
  keyset: base64urlBytes({ min: 61, max: 16_445 }),
  rowVersion: z.int().min(1),
});
export type RecoveryMaterialResponse = z.infer<typeof recoveryMaterialResponseSchema>;

export const recoveryPasswordStartRequestSchema = z.strictObject({
  registrationRequest: base64urlBytes({ length: OPAQUE_BYTES.registrationRequest }),
});
export type RecoveryPasswordStartRequest = z.infer<typeof recoveryPasswordStartRequestSchema>;

/**
 * Replaces the OPAQUE record, the password wrap and the rotated recovery wrap and verifier in one
 * transaction, conditioned on `row_version`. The Recovery Key rotation is mandatory (§3 step 5).
 */
export const recoveryCompleteRequestSchema = z.strictObject({
  registrationRecord: base64urlBytes({ length: OPAQUE_BYTES.registrationRecord }),
  kdfProfile: kdfProfileSchema,
  saltPw: base64urlBytes({ length: 16 }),
  wrappedAkPassword: base64urlBytes({ length: 93 }),
  recoveryKeyId: base64urlBytes({ length: 16 }),
  wrappedAkRecovery: base64urlBytes({ length: 93 }),
  recoveryVerifier: base64urlBytes({ length: 32 }),
  label: deviceLabelSchema.optional(),
  expectedRowVersion: z.int().min(1),
});
export type RecoveryCompleteRequest = z.infer<typeof recoveryCompleteRequestSchema>;
