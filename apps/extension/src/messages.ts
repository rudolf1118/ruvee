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
  z.strictObject({ kind: z.literal('setAutoOpenSave'), enabled: z.boolean() }),
  z.strictObject({ kind: z.literal('offerLog') }),
  z.strictObject({ kind: z.literal('pendingSave'), tabId }),
  z.strictObject({ kind: z.literal('savePending'), tabId }),
  z.strictObject({ kind: z.literal('dismissPending'), tabId }),
]);
export type ExtensionRequest = z.infer<typeof requestSchema>;

export interface Status {
  readonly serverOrigin: string | null;
  readonly unlocked: boolean;
  /** The worker's build id. A worker older than the popup does not send it at all. */
  readonly build?: string;
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
  /** Open the popup by itself after a sign-in to offer saving it (§5.2a). Off by default. */
  readonly autoOpenSave: boolean;
}

export type SetInlineResult = 'saved' | 'no_permission';

/** A login the user submitted on a page, waiting for "Save" in the popup (phase B). No password. */
export interface PendingSave {
  readonly origin: string;
  readonly username: string;
}

export type SavePendingResult = 'saved' | 'gone';

/**
 * What happened to a sign-in the content script reported (§8.3): kept or not, and whether the
 * popup opened by itself, was skipped (and why) or was refused by Chrome. No username or password.
 */
export interface OfferLogEntry {
  readonly atMs: number;
  readonly origin: string;
  readonly result: string;
}

export type SetServerResult = 'saved' | 'not_an_origin' | 'device_exists' | 'no_permission';

export type FillOutcome =
  | 'filled'
  | 'origin_changed'
  | 'no_password_field'
  | 'not_allowed'
  /** The item was deleted or moved to Trash, usually on another device, after it was listed. */
  | 'gone';

export type ExtensionResponse =
  | { readonly ok: true; readonly result: unknown }
  | { readonly ok: false; readonly code: string; readonly retryAfterSeconds?: number };
