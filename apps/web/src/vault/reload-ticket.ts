import type { ReloadTicket } from '@ruvee/vault';

/**
 * D-34 (docs/security/web-reload-unlock.md §5): the tab's half of a reload ticket, in this tab's
 * `sessionStorage`. It holds the ticket id, the tab half `H_tab` and the sealed `AK`; it opens
 * nothing without the server half, which the server gives once, to this session, while the ticket
 * lives. A new tab starts without it; a reload keeps it.
 */
const KEY = 'ruvee-reload-ticket';

/** Takes the stored ticket and removes it at once, so a failed resume leaves nothing behind. */
export function takeReloadTicket(): ReloadTicket | null {
  try {
    const text = sessionStorage.getItem(KEY);
    sessionStorage.removeItem(KEY);
    if (text === null) return null;
    const value = JSON.parse(text) as Partial<Record<keyof ReloadTicket, unknown>>;
    if (
      typeof value.ticketId !== 'string' ||
      typeof value.tabHalf !== 'string' ||
      typeof value.envelope !== 'string'
    )
      return null;
    return { ticketId: value.ticketId, tabHalf: value.tabHalf, envelope: value.envelope };
  } catch {
    return null;
  }
}

export function storeReloadTicket(ticket: ReloadTicket): void {
  try {
    sessionStorage.setItem(
      KEY,
      JSON.stringify({
        ticketId: ticket.ticketId,
        tabHalf: ticket.tabHalf,
        envelope: ticket.envelope,
      }),
    );
  } catch {
    // Storage refused (a private mode, a quota): the next reload asks for the password.
  }
}

/** Every lock path calls this before anything else (INV-15 as amended by D-34). */
export function clearReloadTicket(): void {
  try {
    sessionStorage.removeItem(KEY);
  } catch {
    // Nothing stored, or storage unavailable.
  }
}
