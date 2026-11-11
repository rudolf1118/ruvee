import { z } from 'zod';

/**
 * Messages from the extension's own pages to the service worker (extension-design.md §1). Every
 * message is validated before it is acted on. Account setup and recovery happen in the web app,
 * and the popup never receives a password: there is no `secret`, and filling happens in the
 * worker. Exactly the methods the extension's pages call (follow-up review F-21): `items`, `detail`
 * and `acknowledgeRecoveryNotice` were allowed but never used, and are not.
 */
export const EXTENSION_VAULT_METHODS = [
  'phase',
  'login',
  'unlock',
  'sync',
  'pairingNeedsPassword',
  'pairingJoin',
  'pairingWait',
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
  z.strictObject({ kind: z.literal('pairing') }),
  z.strictObject({ kind: z.literal('inlineSettings') }),
  z.strictObject({ kind: z.literal('setInline'), enabled: z.boolean() }),
]);
export type ExtensionRequest = z.infer<typeof requestSchema>;

export interface Status {
  readonly serverOrigin: string | null;
  readonly unlocked: boolean;
}

/**
 * The join as the worker holds it (`kind: 'pairing'`). The worker, not the popup, owns a join:
 * it keeps polling after the popup closes, and a reopened popup resumes from this.
 */
export interface PairingView {
  readonly state: 'none' | 'joined' | 'enrolled';
  /** A join is waiting but the password from the login is gone; the popup asks for it. */
  readonly needsPassword: boolean;
  /** Why the last join stopped or is not progressing, as an error code; null if nothing. */
  readonly problem: string | null;
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

/** Whether the inline icon is on (extension-inline-autofill.md §5.1). Off by default. */
export interface InlineSettings {
  readonly enabled: boolean;
}

export type SetInlineResult = 'saved' | 'no_permission';

export type SetServerResult = 'saved' | 'not_an_origin' | 'device_exists' | 'no_permission';

export type FillOutcome = 'filled' | 'origin_changed' | 'no_password_field' | 'not_allowed';

export type ExtensionResponse =
  | { readonly ok: true; readonly result: unknown }
  | { readonly ok: false; readonly code: string; readonly retryAfterSeconds?: number };
