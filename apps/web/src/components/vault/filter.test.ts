import { filterItems, type ListQuery, sectionCounts } from './filter';
import type { VaultItemView } from './types';

function item(
  overrides: Partial<VaultItemView> & Pick<VaultItemView, 'id' | 'title'>,
): VaultItemView {
  return {
    kind: 'login',
    subtitle: '',
    vaultId: 'personal',
    favorite: false,
    trashed: false,
    edited: '',
    tags: [],
    fields: [],
    searchText: [],
    ...overrides,
  };
}

const items = [
  item({
    id: 'a',
    title: 'Zeta Mail',
    favorite: true,
    tags: ['email'],
    searchText: ['zeta@mail.example'],
  }),
  item({ id: 'b', title: 'Alpha Bank', vaultId: 'household', tags: ['finance'] }),
  item({ id: 'c', title: 'Wifi', kind: 'note', vaultId: 'household', tags: ['home'] }),
  item({ id: 'd', title: 'Debit', kind: 'card', tags: ['finance'] }),
  item({ id: 'e', title: 'Old Forum', trashed: true }),
];

const query = (patch: Partial<ListQuery> = {}): ListQuery => ({
  section: 'all',
  vaultId: 'all',
  query: '',
  kindFilter: 'all',
  tag: null,
  ...patch,
});

const ids = (list: VaultItemView[]) => list.map((i) => i.id);

describe('filterItems', () => {
  it('lists live items sorted by title', () => {
    expect(ids(filterItems(items, query()).items)).toEqual(['b', 'd', 'c', 'a']);
  });

  it('scopes to a vault', () => {
    expect(ids(filterItems(items, query({ vaultId: 'household' })).items)).toEqual(['b', 'c']);
  });

  it('shows only trashed items in Trash', () => {
    expect(ids(filterItems(items, query({ section: 'trash' })).items)).toEqual(['e']);
  });

  it('filters favorites and categories', () => {
    expect(ids(filterItems(items, query({ section: 'favorites' })).items)).toEqual(['a']);
    expect(ids(filterItems(items, query({ section: 'note' })).items)).toEqual(['c']);
  });

  it('filters by tag', () => {
    expect(ids(filterItems(items, query({ tag: 'finance' })).items)).toEqual(['b', 'd']);
  });

  it('searches title, search text and tags case-insensitively', () => {
    expect(ids(filterItems(items, query({ query: 'ZETA@' })).items)).toEqual(['a']);
    expect(ids(filterItems(items, query({ query: 'alpha' })).items)).toEqual(['b']);
    expect(ids(filterItems(items, query({ query: 'home' })).items)).toEqual(['c']);
    expect(filterItems(items, query({ query: 'nothing-matches' })).items).toEqual([]);
  });

  it('applies kind chips after the base filters, keeping base for chip counts', () => {
    const result = filterItems(items, query({ kindFilter: 'card' }));
    expect(ids(result.items)).toEqual(['d']);
    expect(result.base).toHaveLength(4);
  });

  it('ignores kind chips outside All items and Favorites', () => {
    expect(ids(filterItems(items, query({ section: 'trash', kindFilter: 'card' })).items)).toEqual([
      'e',
    ]);
  });
});

describe('sectionCounts', () => {
  it('counts sections within the chosen vault', () => {
    expect(sectionCounts(items, 'all')).toEqual({
      all: 4,
      favorites: 1,
      login: 2,
      note: 1,
      card: 1,
      identity: 0,
      trash: 1,
    });
    expect(sectionCounts(items, 'household')).toMatchObject({ all: 2, trash: 0 });
  });
});
