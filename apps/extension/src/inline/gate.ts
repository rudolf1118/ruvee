import { z } from 'zod';
import { fillableOrigin } from '../origin';

/**
 * The content-script channel (extension-inline-autofill.md §5.1, E-20). It is separate from the
 * extension pages' channel and carries exactly one message: "the user clicked the inline icon".
 * Nothing in it names an origin, a tab or an item; the worker takes all of that from the browser.
 */
export const contentRequestSchema = z.strictObject({ kind: z.literal('inlineOpen') });
export type ContentRequest = z.infer<typeof contentRequestSchema>;

/** Patterns the content script is registered for, and the host permission it needs. */
export const INLINE_ORIGINS: readonly string[] = __RUVEE_TEST__
  ? ['http://127.0.0.1/*']
  : ['https://*/*'];

export interface InlineSender {
  readonly id?: string;
  readonly origin?: string;
  readonly frameId?: number;
  readonly tab?: { readonly id?: number; readonly url?: string; readonly windowId?: number };
}

export interface InlineTarget {
  readonly tabId: number;
  readonly windowId: number | undefined;
  readonly origin: string;
}

/**
 * A content script of this extension, in the top frame of a fillable page whose origin is the
 * tab's own: the only sender the inline channel answers. Everything checked here is set by the
 * browser, not by the page (§3). The worker re-reads the tab before acting on it.
 */
export function inlineTarget(
  sender: InlineSender,
  runtimeId: string,
  extensionOrigin: string,
): InlineTarget | null {
  if (sender.id !== runtimeId) return null;
  // The extension's own pages use the other channel; they never open the popup this way.
  if (sender.origin === undefined || sender.origin === extensionOrigin) return null;
  if (sender.frameId !== 0) return null;
  const tabId = sender.tab?.id;
  if (tabId === undefined || tabId < 0) return null;
  const origin = fillableOrigin(sender.origin);
  if (origin === null || origin !== sender.origin) return null;
  if (fillableOrigin(sender.tab?.url) !== origin) return null;
  return { tabId, windowId: sender.tab?.windowId, origin };
}
