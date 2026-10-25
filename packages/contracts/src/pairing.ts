import { z } from 'zod';
import { deviceLabelSchema, devicePlatformSchema, platformSchema, uuidSchema } from './auth.js';
import { base64urlBytes } from './bytes.js';

/**
 * Pairing contracts (device-enrollment.md §3, api-design.md §Devices and pairing). The server
 * relays opaque values: it learns `pairing_id` but never `S`, and checks neither MAC.
 */

export const PAIRING_TTL_MS = 10 * 60_000;
export const MAX_OPEN_PAIRINGS = 3;
export const MAX_PAIRINGS_PER_HOUR = 10;
/** A sealed box of the pairing payload: 48 bytes of overhead, at most 4,096 bytes in all. */
export const PAIRING_CIPHERTEXT_MAX_BYTES = 4096;

export const pairingIdSchema = base64urlBytes({ length: 16 });
/** Path parameter form of the pairing id. */
export const pairingIdParamSchema = z.string().regex(/^[A-Za-z0-9_-]{22}$/);

export const createPairingRequestSchema = z.strictObject({ pairingId: pairingIdSchema });
export type CreatePairingRequest = z.infer<typeof createPairingRequestSchema>;

export const pairingJoinRequestSchema = z.strictObject({
  epk: base64urlBytes({ length: 32 }),
  platform: platformSchema,
  mac: base64urlBytes({ length: 32 }),
});
export type PairingJoinRequest = z.infer<typeof pairingJoinRequestSchema>;

export const pairingApproveRequestSchema = z.strictObject({
  ciphertext: base64urlBytes({ min: 49, max: PAIRING_CIPHERTEXT_MAX_BYTES }),
  mac: base64urlBytes({ length: 32 }),
  label: deviceLabelSchema.optional(),
});
export type PairingApproveRequest = z.infer<typeof pairingApproveRequestSchema>;

export const pairingCancelRequestSchema = z.strictObject({
  /** `mac_failed` records that the request did not come from the device being paired. */
  reason: z.enum(['user', 'mac_failed']).optional(),
});
export type PairingCancelRequest = z.infer<typeof pairingCancelRequestSchema>;

const timestamp = z.iso.datetime({ offset: false });

/** What each side may see: A gets the request, B gets the reply after approval. */
export const pairingStateResponseSchema = z.strictObject({
  pairingId: pairingIdSchema,
  state: z.enum(['open', 'requested', 'approved']),
  role: z.enum(['initiator', 'requester']),
  expiresAt: timestamp,
  request: z
    .strictObject({
      requesterDeviceId: uuidSchema,
      platform: devicePlatformSchema,
      epk: base64urlBytes({ length: 32 }),
      mac: base64urlBytes({ length: 32 }),
      requestedAt: timestamp,
    })
    .optional(),
  response: z
    .strictObject({
      ciphertext: base64urlBytes({ min: 49, max: PAIRING_CIPHERTEXT_MAX_BYTES }),
      mac: base64urlBytes({ length: 32 }),
    })
    .optional(),
});
export type PairingStateResponse = z.infer<typeof pairingStateResponseSchema>;
