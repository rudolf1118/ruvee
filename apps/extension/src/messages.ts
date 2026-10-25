import { z } from 'zod';

/**
 * Messages from the extension's own pages to the service worker (extension-design.md §1). Every
 * message is validated before it is acted on. Account setup and recovery happen in the web app,
 * and the popup never receives a password: there is no `secret`, and filling happens in the
 * worker.
 */
export const EXTENSION_VAULT_METHODS = [
  'phase',
  'login',
  'unlock',
  'items',
  'detail',
  'sync',
  'pairingNeedsPassword',
  'pairingJoin',
  'pairingWait',
  'acknowledgeRecoveryNotice',
  'logout',
] as const;
export type ExtensionVaultMethod = (typeof EXTENSION_VAULT_METHODS)[number];

const tabId = z
  .int()
  .min(0)
  .max(2 ** 31);

export const requestSchema = z.discriminatedUnion('kind', [
  z.strictObject({
    kind: z.literal('vault'),
    method: z.enum(EXTENSION_VAULT_METHODS),
    params: z.unknown().optional(),
  }),
  z.strictObject({ kind: z.literal('status') }),
  z.strictObject({ kind: z.literal('setServer'), origin: z.string().max(256) }),
  z.strictObject({ kind: z.literal('candidates'), tabId }),
  z.strictObject({ kind: z.literal('fill'), tabId, itemId: z.uuid() }),
  z.strictObject({ kind: z.literal('lock') }),
]);
export type ExtensionRequest = z.infer<typeof requestSchema>;

export interface Status {
  readonly serverOrigin: string | null;
  readonly unlocked: boolean;
}

export interface Candidate {
  readonly id: string;
  readonly title: string;
  readonly username: string;
}

export interface Candidates {
  /** The tab's origin, or null when the page cannot be filled (extension-design.md §4). */
  readonly origin: string | null;
  readonly items: readonly Candidate[];
}

export type SetServerResult = 'saved' | 'not_an_origin' | 'device_exists' | 'no_permission';

export type FillOutcome = 'filled' | 'origin_changed' | 'no_password_field' | 'not_allowed';

export type ExtensionResponse =
  | { readonly ok: true; readonly result: unknown }
  | { readonly ok: false; readonly code: string; readonly retryAfterSeconds?: number };
