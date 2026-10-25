import { z } from 'zod';
import { base64urlBytes } from './bytes.js';

/**
 * Account and authentication contracts (api-design.md §Authentication, authentication.md).
 * OPAQUE messages are the canonical unpadded base64url strings `@serenity-kit/opaque` 1.1.0
 * produces; the byte lengths are those of its ristretto255/SHA-512 configuration (D-02).
 */

export const OPAQUE_BYTES = {
  registrationRequest: 32,
  registrationResponse: 64,
  registrationRecord: 192,
  startLoginRequest: 96,
  loginResponse: 320,
  finishLoginRequest: 64,
} as const;

/** Fixed OPAQUE configuration label stored with each record (database-design.md). */
export const OPAQUE_CONFIG_ID = 'serenity-opaque-1.1.0/ristretto255-sha512/memory-constrained';

export const USERNAME_MAX_LENGTH = 64;
const USERNAME_CHARACTERS = /^[\p{L}\p{M}\p{N}._-]+$/u;

/**
 * D-17: NFC, then lowercase. Letters, marks, digits, `.`, `_` and `-`, 1 to 64 code points.
 * Returns undefined for input that cannot be a username. The server accepts only usernames that
 * are already in this form, so the same string always names the same account.
 */
export function normalizeUsername(input: string): string | undefined {
  if (input.length > USERNAME_MAX_LENGTH * 4) return undefined;
  const normalized = input.normalize('NFC').toLowerCase().normalize('NFC');
  const length = normalized.match(/./gsu)?.length ?? 0;
  if (length < 1 || length > USERNAME_MAX_LENGTH || !USERNAME_CHARACTERS.test(normalized))
    return undefined;
  return normalized;
}

export const usernameSchema = z
  .string()
  .min(1)
  .max(USERNAME_MAX_LENGTH * 2)
  .regex(USERNAME_CHARACTERS)
  .refine((value) => normalizeUsername(value) === value, { message: 'not normalized' });

/** Canonical lowercase RFC 9562 text form; identifiers are random version 4 UUIDs. */
export const uuidSchema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);

/** Token clients (extension, mobile) arrive in Phase 5; the web app is the only platform now. */
export const platformSchema = z.literal('web');
export const devicePlatformSchema = z.enum(['web', 'extension', 'ios', 'android']);
export const deviceStatusSchema = z.enum(['pending', 'active', 'revoked']);

/** A `DEVICE_LABEL` envelope (61 to 189 bytes). */
export const deviceLabelSchema = base64urlBytes({ min: 61, max: 189 });

export const BOOTSTRAP_TOKEN_BYTES = 32;
export const bootstrapTokenSchema = base64urlBytes({ length: BOOTSTRAP_TOKEN_BYTES });

/** Argon2id profiles a client may store (cryptographic-design §3.2); profile 2 is reserved. */
export const kdfProfileSchema = z.literal(1);

export const U32_MAX = 0xffff_ffff;

export const registerStartRequestSchema = z.strictObject({
  bootstrapToken: bootstrapTokenSchema,
  username: usernameSchema,
  registrationRequest: base64urlBytes({ length: OPAQUE_BYTES.registrationRequest }),
});
export type RegisterStartRequest = z.infer<typeof registerStartRequestSchema>;

export const registerStartResponseSchema = z.strictObject({
  registrationResponse: base64urlBytes({ length: OPAQUE_BYTES.registrationResponse }),
});
export type RegisterStartResponse = z.infer<typeof registerStartResponseSchema>;

export const accountKeyMaterialSchema = z.strictObject({
  kdfProfile: kdfProfileSchema,
  saltPw: base64urlBytes({ length: 16 }),
  akId: base64urlBytes({ length: 16 }),
  akEpoch: z.int().min(0).max(U32_MAX),
  wrappedAkPassword: base64urlBytes({ length: 93 }),
  recoveryKeyId: base64urlBytes({ length: 16 }),
  wrappedAkRecovery: base64urlBytes({ length: 93 }),
  recoveryVerifier: base64urlBytes({ length: 32 }),
  keysetVersion: z.int().min(0).max(U32_MAX),
  keyset: base64urlBytes({ min: 61, max: 16_445 }),
});
export type AccountKeyMaterial = z.infer<typeof accountKeyMaterialSchema>;

/**
 * Creates the account, its key material, the first device, its session and the empty vault in
 * one transaction. The vault is created here because the keyset already names it.
 */
export const registerFinishRequestSchema = z.strictObject({
  bootstrapToken: bootstrapTokenSchema,
  username: usernameSchema,
  registrationRecord: base64urlBytes({ length: OPAQUE_BYTES.registrationRecord }),
  accountId: uuidSchema,
  device: z.strictObject({
    id: uuidSchema,
    platform: platformSchema,
    label: deviceLabelSchema.optional(),
  }),
  keys: accountKeyMaterialSchema,
  vault: z.strictObject({ id: uuidSchema, vkId: base64urlBytes({ length: 16 }) }),
});
export type RegisterFinishRequest = z.infer<typeof registerFinishRequestSchema>;

export const LOGIN_ID_BYTES = 16;
export const loginIdSchema = base64urlBytes({ length: LOGIN_ID_BYTES });

export const loginStartRequestSchema = z.strictObject({
  username: usernameSchema,
  startLoginRequest: base64urlBytes({ length: OPAQUE_BYTES.startLoginRequest }),
  deviceId: uuidSchema.optional(),
  platform: platformSchema,
});
export type LoginStartRequest = z.infer<typeof loginStartRequestSchema>;

export const loginStartResponseSchema = z.strictObject({
  loginId: loginIdSchema,
  loginResponse: base64urlBytes({ length: OPAQUE_BYTES.loginResponse }),
});
export type LoginStartResponse = z.infer<typeof loginStartResponseSchema>;

export const loginFinishRequestSchema = z.strictObject({
  loginId: loginIdSchema,
  finishLoginRequest: base64urlBytes({ length: OPAQUE_BYTES.finishLoginRequest }),
});
export type LoginFinishRequest = z.infer<typeof loginFinishRequestSchema>;

/** Returned with the `Set-Cookie` header of a new web session. */
export const sessionResponseSchema = z.strictObject({
  accountId: uuidSchema,
  device: z.strictObject({ id: uuidSchema, status: deviceStatusSchema }),
});
export type SessionResponse = z.infer<typeof sessionResponseSchema>;

const timestamp = z.iso.datetime({ offset: false });

export const accountResponseSchema = z.strictObject({
  accountId: uuidSchema,
  username: usernameSchema,
  createdAt: timestamp,
  passwordChangedAt: timestamp,
});
export type AccountResponse = z.infer<typeof accountResponseSchema>;

/** `GET /account/keys`. The recovery wrap and verifier are never returned here. */
export const accountKeysResponseSchema = z.strictObject({
  kdfProfile: kdfProfileSchema,
  saltPw: base64urlBytes({ length: 16 }),
  akId: base64urlBytes({ length: 16 }),
  akEpoch: z.int().min(0).max(U32_MAX),
  wrappedAkPassword: base64urlBytes({ length: 93 }),
  keysetVersion: z.int().min(0).max(U32_MAX),
  keyset: base64urlBytes({ min: 61, max: 16_445 }),
  rowVersion: z.int().min(1),
});
export type AccountKeysResponse = z.infer<typeof accountKeysResponseSchema>;

export const deviceSchema = z.strictObject({
  id: uuidSchema,
  platform: devicePlatformSchema,
  status: deviceStatusSchema,
  enrolledVia: z.enum(['bootstrap', 'pairing', 'recovery']).nullable(),
  label: deviceLabelSchema.nullable(),
  createdAt: timestamp,
  enrolledAt: timestamp.nullable(),
  lastSeenAt: timestamp.nullable(),
  revokedAt: timestamp.nullable(),
});
export type Device = z.infer<typeof deviceSchema>;

export const devicesResponseSchema = z.strictObject({ devices: z.array(deviceSchema).max(1000) });
export type DevicesResponse = z.infer<typeof devicesResponseSchema>;

/** Session cookie names. `__Host-` needs `Secure`, so loopback HTTP development uses the other. */
export const SESSION_COOKIE_SECURE = '__Host-ruvee_session';
export const SESSION_COOKIE_INSECURE_DEV = 'ruvee_session';

/** CSRF header required on every state-changing cookie request (authentication.md §6). */
export const CSRF_HEADER = 'x-ruvee-request';
export const CSRF_HEADER_VALUE = '1';
