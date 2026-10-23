import { z } from 'zod';

export const livenessResponseSchema = z.strictObject({ status: z.literal('ok') });

export type LivenessResponse = z.infer<typeof livenessResponseSchema>;

/** `GET /health/ready` with status 200. */
export const readyResponseSchema = z.strictObject({
  status: z.literal('ok'),
  checks: z.strictObject({ database: z.literal('up') }),
});

/** `GET /health/ready` with status 503. */
export const notReadyResponseSchema = z.strictObject({
  status: z.literal('unavailable'),
  checks: z.strictObject({ database: z.literal('down') }),
});

export const readinessResponseSchema = z.discriminatedUnion('status', [
  readyResponseSchema,
  notReadyResponseSchema,
]);

export type ReadinessResponse = z.infer<typeof readinessResponseSchema>;
