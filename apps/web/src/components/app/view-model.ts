import type { VaultItemView } from '../vault/types';
import type { ItemSummary } from '@ruvee/vault';

/** V1 has one vault; the shell's vault switcher shows it under this name. */
export const PERSONAL_VAULT = { id: 'personal', name: 'Personal' } as const;

export function relativeTime(ms: number, now = Date.now()): string {
  const minutes = Math.round((now - ms) / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const date = new Date(ms);
  if (date.toDateString() === new Date(now).toDateString())
    return `today at ${date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
  return date.toLocaleDateString();
}

/** What the shell lists. Fields are loaded by the live detail view from the worker. */
export function toView(item: ItemSummary): VaultItemView {
  return {
    id: item.id,
    kind: item.type,
    title: item.title,
    subtitle: item.subtitle,
    vaultId: PERSONAL_VAULT.id,
    favorite: item.favorite,
    trashed: item.trashed,
    edited: item.updatedAtMs ? `Edited ${relativeTime(item.updatedAtMs)}` : '',
    tags: [...item.tags],
    fields: [],
    searchText: [item.subtitle, ...item.urls],
  };
}

/** Only http(s) links are rendered as links; anything else stays text (item content is data). */
export function safeHref(url: string): string | null {
  try {
    const parsed = new URL(url);
    return parsed.protocol === 'https:' || parsed.protocol === 'http:' ? parsed.href : null;
  } catch {
    return null;
  }
}
