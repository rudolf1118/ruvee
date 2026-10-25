'use client';

import {
  type ReactNode,
  type RefObject,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { Button } from '../ui/button';
import { CloseIcon, MenuIcon } from '../ui/icons';
import { Logo } from '../ui/logo';
import { cx } from '../ui/cx';
import { countLabel, filterItems, type ListQuery, SECTION_TITLES, sectionCounts } from './filter';
import { ItemDetail, NoItemSelected } from './item-detail';
import { type ChipOption, type EmptyStateContent, ItemList } from './item-list';
import { Sidebar } from './sidebar';
import {
  ALL_VAULTS,
  type KindFilter,
  type Section,
  type VaultItemView,
  type VaultSummary,
} from './types';

/** Context handed to a live detail renderer. */
export interface DetailContext {
  vaultName: string;
  headingRef: RefObject<HTMLHeadingElement | null>;
  onBack: () => void;
  onTag: (tag: string) => void;
}

/**
 * Hooks for real vault data. Without them the shell is the design preview: every action for a
 * feature that is not built is visibly unavailable.
 */
export interface VaultShellLive {
  onAddItem: () => void;
  onLock: () => void;
  statusPanel: ReactNode;
  extraNav?: ReactNode;
  renderDetail: (item: VaultItemView, context: DetailContext) => ReactNode;
  /** When set, replaces the detail pane (the item editor, a conflict, devices). */
  detailOverride?: ReactNode;
  rowBadge?: (item: VaultItemView) => string | null;
  /** Selects this item, e.g. after saving a new one. */
  selectId?: string | null;
}

export interface VaultShellProps {
  items: VaultItemView[];
  vaults: VaultSummary[];
  initialSelectedId?: string;
  /** Rendered above the shell, e.g. the preview ribbon. */
  banner?: ReactNode;
  live?: VaultShellLive;
}

type Pane = 'list' | 'detail';

/**
 * The main application layout from the design: navigation, item list and
 * item detail. Below the `lg` breakpoint navigation moves into a drawer; below
 * `md` the list and detail become separate screens.
 */
export function VaultShell({ items, vaults, initialSelectedId, banner, live }: VaultShellProps) {
  const [listQuery, setListQuery] = useState<ListQuery>({
    section: 'all',
    vaultId: ALL_VAULTS,
    query: '',
    kindFilter: 'all',
    tag: null,
  });
  const [selectedId, setSelectedId] = useState<string | null>(initialSelectedId ?? null);
  const [pane, setPane] = useState<Pane>('list');
  const [drawerOpen, setDrawerOpen] = useState(false);

  const rowRefs = useRef(new Map<string, HTMLButtonElement>());
  const detailHeadingRef = useRef<HTMLHeadingElement>(null);
  const menuButtonRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);
  const focusDetailRef = useRef(false);

  const { items: visible, base } = useMemo(() => filterItems(items, listQuery), [items, listQuery]);
  const counts = useMemo(() => sectionCounts(items, listQuery.vaultId), [items, listQuery.vaultId]);
  const vaultName = useCallback(
    (id: string) =>
      id === ALL_VAULTS ? 'All vaults' : (vaults.find((vault) => vault.id === id)?.name ?? id),
    [vaults],
  );

  const selected = visible.find((item) => item.id === selectedId) ?? null;

  // Requests from the live app (select a saved item, show the editor) adjust state during
  // render, as React recommends for state derived from changing props.
  const requestedId = live?.selectId ?? null;
  const [handledId, setHandledId] = useState<string | null>(null);
  if (requestedId !== handledId) {
    setHandledId(requestedId);
    if (requestedId) setSelectedId(requestedId);
  }
  const override = live?.detailOverride;
  const [overrideShown, setOverrideShown] = useState(false);
  if (Boolean(override) !== overrideShown) {
    setOverrideShown(Boolean(override));
    if (override) setPane('detail');
  }

  /** Updates filters and keeps a valid selection, like the design prototype. */
  const updateQuery = (patch: Partial<ListQuery>) => {
    const next = { ...listQuery, ...patch };
    const nextVisible = filterItems(items, next).items;
    setListQuery(next);
    if (!nextVisible.some((item) => item.id === selectedId)) {
      setSelectedId(nextVisible[0]?.id ?? null);
    }
  };

  const selectItem = (id: string) => {
    setSelectedId(id);
    setPane('detail');
    focusDetailRef.current = true;
  };

  useEffect(() => {
    if (focusDetailRef.current && pane === 'detail') {
      focusDetailRef.current = false;
      // Only narrow screens swap panes, so only move focus there.
      if (window.matchMedia('(max-width: 767px)').matches) detailHeadingRef.current?.focus();
    }
  }, [pane, selectedId]);

  const backToList = () => {
    setPane('list');
    const id = selectedId;
    requestAnimationFrame(() => {
      if (id) rowRefs.current.get(id)?.focus();
    });
  };

  const restoreMenuFocusRef = useRef(false);
  const closeDrawer = useCallback(() => {
    restoreMenuFocusRef.current = true;
    setDrawerOpen(false);
  }, []);

  useEffect(() => {
    if (!drawerOpen) {
      // The header is inert while the drawer is open, so focus can only return afterwards.
      if (restoreMenuFocusRef.current) menuButtonRef.current?.focus();
      restoreMenuFocusRef.current = false;
      return;
    }
    drawerRef.current?.querySelector<HTMLElement>('button')?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') closeDrawer();
    };
    const desktop = window.matchMedia('(min-width: 1024px)');
    const onResize = () => {
      if (desktop.matches) setDrawerOpen(false);
    };
    document.addEventListener('keydown', onKeyDown);
    desktop.addEventListener('change', onResize);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      desktop.removeEventListener('change', onResize);
    };
  }, [drawerOpen, closeDrawer]);

  const onSection = (section: Section) => {
    updateQuery({ section, kindFilter: 'all', tag: null });
    setPane('list');
    if (drawerOpen) closeDrawer();
  };

  const onVault = (vaultId: string) => {
    updateQuery({ vaultId });
    setPane('list');
  };

  const showChips = listQuery.section === 'all' || listQuery.section === 'favorites';
  const kindCount = (kind: KindFilter) =>
    kind === 'all' ? base.length : base.filter((item) => item.kind === kind).length;
  const chips: ChipOption[] | null = showChips
    ? (
        [
          ['all', 'All'],
          ['login', 'Logins'],
          ['note', 'Notes'],
          ['card', 'Cards'],
          ['identity', 'Identities'],
        ] as const
      ).map(([value, label]) => ({ value, label, count: kindCount(value) }))
    : null;

  const sectionTitle = SECTION_TITLES[listQuery.section];
  const scopeName = listQuery.vaultId === ALL_VAULTS ? 'all vaults' : vaultName(listQuery.vaultId);
  const empty = emptyStateFor(
    listQuery,
    counts.all,
    vaultName(listQuery.vaultId),
    () => {
      updateQuery({ query: '' });
    },
    live?.onAddItem,
  );

  const vaultOptions = [
    { id: ALL_VAULTS, name: 'All vaults', count: items.filter((item) => !item.trashed).length },
    ...vaults.map((vault) => ({
      ...vault,
      count: items.filter((item) => !item.trashed && item.vaultId === vault.id).length,
    })),
  ];

  const sidebarProps = {
    section: listQuery.section,
    onSection,
    counts,
    vaultOptions,
    vaultId: listQuery.vaultId,
    onVault,
    ...(live
      ? { onLock: live.onLock, statusPanel: live.statusPanel, extraNav: live.extraNav }
      : {}),
  };

  return (
    <div className="flex h-dvh min-h-[560px] flex-col overflow-hidden">
      <a
        href="#item-list"
        className="sr-only z-50 rounded-control bg-surface px-3 py-2 font-semibold focus:not-sr-only focus:absolute focus:top-2 focus:left-2"
      >
        Skip to items
      </a>
      {banner}

      <header
        inert={drawerOpen}
        className="flex h-14 shrink-0 items-center gap-2 border-b border-line px-3 lg:hidden"
      >
        <Button
          ref={menuButtonRef}
          variant="ghost"
          iconOnly
          aria-label="Open navigation"
          aria-expanded={drawerOpen}
          aria-controls="vault-drawer"
          onClick={() => {
            setDrawerOpen(true);
          }}
          icon={<MenuIcon size={20} />}
        />
        <Logo />
      </header>

      <div className="flex min-h-0 flex-1">
        <aside className="hidden w-sidebar shrink-0 border-r border-line lg:block">
          <Sidebar {...sidebarProps} />
        </aside>

        <div inert={drawerOpen} className="flex min-w-0 flex-1">
          <section
            aria-label="Items"
            className={cx(
              'min-h-0 w-full flex-col border-line bg-surface md:flex md:w-list md:max-w-[400px] md:shrink-0 md:border-r',
              pane === 'detail' ? 'hidden' : 'flex',
            )}
          >
            <ItemList
              title={sectionTitle}
              subtitle={`${countLabel(visible.length, 'item')} in ${scopeName}`}
              query={listQuery.query}
              onQuery={(query) => {
                updateQuery({ query });
              }}
              searchPlaceholder={`Search ${sectionTitle.toLowerCase()}`}
              chips={chips}
              kindFilter={listQuery.kindFilter}
              onKindFilter={(kindFilter) => {
                updateQuery({ kindFilter });
              }}
              tag={listQuery.tag}
              onClearTag={() => {
                updateQuery({ tag: null });
              }}
              items={visible}
              selectedId={selected?.id ?? null}
              onSelect={selectItem}
              empty={empty}
              rowRef={(id, node) => {
                if (node) rowRefs.current.set(id, node);
                else rowRefs.current.delete(id);
              }}
              {...(live ? { onAdd: live.onAddItem } : {})}
              {...(live?.rowBadge ? { rowBadge: live.rowBadge } : {})}
            />
          </section>

          <section
            aria-label="Item details"
            className={cx(
              'min-h-0 min-w-0 flex-1 overflow-y-auto px-4 pt-4 pb-12 md:block md:px-8 md:pt-6',
              pane === 'list' ? 'hidden' : 'block',
            )}
          >
            {override ??
              (selected ? (
                live ? (
                  // The ref is only forwarded to the detail's heading, never read here.
                  // eslint-disable-next-line react-hooks/refs
                  live.renderDetail(selected, {
                    vaultName: vaultName(selected.vaultId),
                    headingRef: detailHeadingRef,
                    onBack: backToList,
                    onTag: (tag) => {
                      updateQuery({ tag, section: 'all', kindFilter: 'all', query: '' });
                      setSelectedId(selected.id);
                    },
                  })
                ) : (
                  <ItemDetail
                    item={selected}
                    vaultName={vaultName(selected.vaultId)}
                    headingRef={detailHeadingRef}
                    onBack={backToList}
                    onTag={(tag) => {
                      updateQuery({ tag, section: 'all', kindFilter: 'all', query: '' });
                      setSelectedId(selected.id);
                    }}
                  />
                )
              ) : (
                <NoItemSelected />
              ))}
          </section>
        </div>
      </div>

      {drawerOpen ? (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div aria-hidden="true" className="absolute inset-0 bg-ink/30" onClick={closeDrawer} />
          <div
            ref={drawerRef}
            id="vault-drawer"
            role="dialog"
            aria-modal="true"
            aria-label="Navigation"
            className="absolute inset-y-0 left-0 w-[min(288px,85vw)] bg-canvas shadow-menu"
          >
            <Sidebar
              {...sidebarProps}
              headerAction={
                <Button
                  variant="ghost"
                  iconOnly
                  aria-label="Close navigation"
                  onClick={closeDrawer}
                  icon={<CloseIcon size={18} />}
                />
              }
            />
          </div>
        </div>
      ) : null}
    </div>
  );
}

function emptyStateFor(
  q: ListQuery,
  liveCount: number,
  vaultName: string,
  clearSearch: () => void,
  onAdd?: () => void,
): EmptyStateContent {
  const trimmed = q.query.trim();
  if (trimmed) {
    return {
      title: `No items match “${trimmed}”`,
      body: 'Check the spelling, or search by website, username or tag.',
      isSearch: true,
      action: <Button onClick={clearSearch}>Clear search</Button>,
    };
  }
  if (q.section === 'all' && liveCount === 0 && q.tag === null) {
    return {
      title: `${vaultName} is empty`,
      body: 'Add your first login, or import items from another password manager or your browser.',
      isSearch: false,
      action: (
        <>
          <Button
            variant="primary"
            {...(onAdd ? { onClick: onAdd } : { unavailable: true, title: 'Not available yet' })}
          >
            Add a login
          </Button>
          <Button unavailable title="Not available yet">
            Import items
          </Button>
        </>
      ),
    };
  }
  if (q.section === 'trash') {
    return {
      title: 'Trash is empty',
      body: 'Items you move to Trash appear here until you delete them permanently.',
      isSearch: false,
    };
  }
  if (q.section === 'favorites') {
    return {
      title: 'No favorites yet',
      body: 'Mark items you use often as Favorites to find them faster.',
      isSearch: false,
    };
  }
  return {
    title: 'Nothing here yet',
    body: `Items of this kind in ${vaultName} will appear here.`,
    isSearch: false,
  };
}
