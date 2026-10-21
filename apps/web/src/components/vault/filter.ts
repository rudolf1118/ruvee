import {
  ALL_VAULTS,
  type ItemKind,
  type KindFilter,
  type Section,
  type VaultItemView,
} from './types';

export interface ListQuery {
  section: Section;
  vaultId: string;
  query: string;
  kindFilter: KindFilter;
  tag: string | null;
}

export const KINDS: readonly ItemKind[] = ['login', 'note', 'card', 'identity'];

export const SECTION_TITLES: Record<Section, string> = {
  all: 'All items',
  favorites: 'Favorites',
  login: 'Logins',
  note: 'Secure notes',
  card: 'Payment cards',
  identity: 'Identities',
  trash: 'Trash',
};

export const KIND_LABELS: Record<ItemKind, string> = {
  login: 'Login',
  note: 'Secure note',
  card: 'Payment card',
  identity: 'Identity',
};

function isKind(section: Section): section is ItemKind {
  return (KINDS as readonly string[]).includes(section);
}

function inVault(item: VaultItemView, vaultId: string): boolean {
  return vaultId === ALL_VAULTS || item.vaultId === vaultId;
}

export function matchesQuery(item: VaultItemView, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [item.title, ...item.searchText, item.tags.join(' ')].some((text) =>
    text.toLowerCase().includes(q),
  );
}

/**
 * Applies navigation, vault, tag and search filters. `base` is the result
 * before the kind chips are applied, so chip counts reflect the other filters.
 */
export function filterItems(
  items: readonly VaultItemView[],
  q: ListQuery,
): { items: VaultItemView[]; base: VaultItemView[] } {
  const base = items.filter(
    (item) =>
      inVault(item, q.vaultId) &&
      (q.section === 'trash' ? item.trashed : !item.trashed) &&
      (q.section !== 'favorites' || item.favorite) &&
      (!isKind(q.section) || item.kind === q.section) &&
      (q.tag === null || item.tags.includes(q.tag)) &&
      matchesQuery(item, q.query),
  );
  const chipsApply = q.section === 'all' || q.section === 'favorites';
  const filtered =
    chipsApply && q.kindFilter !== 'all' ? base.filter((item) => item.kind === q.kindFilter) : base;
  return { items: [...filtered].sort((a, b) => a.title.localeCompare(b.title)), base };
}

export function sectionCounts(
  items: readonly VaultItemView[],
  vaultId: string,
): Record<Section, number> {
  const scoped = items.filter((item) => inVault(item, vaultId));
  const live = scoped.filter((item) => !item.trashed);
  return {
    all: live.length,
    favorites: live.filter((item) => item.favorite).length,
    login: live.filter((item) => item.kind === 'login').length,
    note: live.filter((item) => item.kind === 'note').length,
    card: live.filter((item) => item.kind === 'card').length,
    identity: live.filter((item) => item.kind === 'identity').length,
    trash: scoped.filter((item) => item.trashed).length,
  };
}

export function countLabel(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}
