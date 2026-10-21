/**
 * Display models for the vault interface. These describe what the UI renders,
 * not how vault data is stored or protected; that model is still undecided.
 */

export type ItemKind = 'login' | 'note' | 'card' | 'identity';

export interface ItemField {
  label: string;
  /** Text to show. For concealed fields this is a mask, never a secret. */
  display: string;
  mono?: boolean;
  /** The real value is hidden; reveal and copy are not built yet. */
  concealed?: boolean;
  /** Defaults to true. The design offers no Copy action for notes. */
  copyable?: boolean;
}

export interface VaultItemView {
  id: string;
  kind: ItemKind;
  title: string;
  subtitle: string;
  vaultId: string;
  favorite: boolean;
  trashed: boolean;
  edited: string;
  tags: string[];
  fields: ItemField[];
  /** Non-secret text the list search matches against. */
  searchText: string[];
}

export interface VaultSummary {
  id: string;
  name: string;
}

export type Section = 'all' | 'favorites' | ItemKind | 'trash';
export type KindFilter = 'all' | ItemKind;
export const ALL_VAULTS = 'all';
