import { z } from 'zod';
import { base64urlBytes } from './bytes.js';

/**
 * Web reload tickets (D-34, docs/security/web-reload-unlock.md §5). The server learns the ticket
 * id and hands out its half `H_srv` to the live web session that created it; the tab's half and
 * the sealed `AK` never reach the server.
 */

/** A ticket ends this long after its last heartbeat (§5.2). */
export const RELOAD_TICKET_HEARTBEAT_TTL_MS = 3 * 60_000;
/** How often an open tab sends a heartbeat; three may be missed before the ticket ends. */
export const RELOAD_TICKET_HEARTBEAT_MS = 60_000;
/** D-10: auto-lock is 1 minute to 8 hours. */
export const RELOAD_TICKET_IDLE_MIN_SECONDS = 60;
export const RELOAD_TICKET_IDLE_MAX_SECONDS = 8 * 60 * 60;

export const reloadTicketIdSchema = base64urlBytes({ length: 16 });

export const reloadTicketCreateRequestSchema = z.strictObject({
  /** The auto-lock period; the ticket ends after this long without user activity. */
  idleSeconds: z
    .number()
    .int()
    .min(RELOAD_TICKET_IDLE_MIN_SECONDS)
    .max(RELOAD_TICKET_IDLE_MAX_SECONDS),
});
export type ReloadTicketCreateRequest = z.infer<typeof reloadTicketCreateRequestSchema>;

export const reloadTicketCreateResponseSchema = z.strictObject({
  ticketId: reloadTicketIdSchema,
  serverHalf: base64urlBytes({ length: 32 }),
});
export type ReloadTicketCreateResponse = z.infer<typeof reloadTicketCreateResponseSchema>;

export const reloadTicketHeartbeatRequestSchema = z.strictObject({
  ticketId: reloadTicketIdSchema,
  /** The user interacted since the last heartbeat: the idle limit starts again. */
  active: z.boolean(),
});
export type ReloadTicketHeartbeatRequest = z.infer<typeof reloadTicketHeartbeatRequestSchema>;

export const reloadTicketRedeemRequestSchema = z.strictObject({ ticketId: reloadTicketIdSchema });
export type ReloadTicketRedeemRequest = z.infer<typeof reloadTicketRedeemRequestSchema>;

export const reloadTicketRedeemResponseSchema = z.strictObject({
  serverHalf: base64urlBytes({ length: 32 }),
});
export type ReloadTicketRedeemResponse = z.infer<typeof reloadTicketRedeemResponseSchema>;
