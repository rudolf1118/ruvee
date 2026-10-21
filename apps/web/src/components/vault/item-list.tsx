import { type KeyboardEvent, type ReactNode, useRef } from 'react';
import { Button } from '../ui/button';
import { Chip } from '../ui/chip';
import { CloseIcon, PlusIcon, SearchIcon, StarIcon, VaultIcon } from '../ui/icons';
import { SearchField } from '../ui/search-field';
import { cx } from '../ui/cx';
import { ItemAvatar } from './item-avatar';
import type { KindFilter, VaultItemView } from './types';

export interface ChipOption {
  value: KindFilter;
  label: string;
  count: number;
}

export interface EmptyStateContent {
  title: string;
  body: string;
  isSearch: boolean;
  action?: ReactNode;
}

interface ItemListProps {
  title: string;
  subtitle: string;
  query: string;
  onQuery: (query: string) => void;
  searchPlaceholder: string;
  chips: ChipOption[] | null;
  kindFilter: KindFilter;
  onKindFilter: (kind: KindFilter) => void;
  tag: string | null;
  onClearTag: () => void;
  items: VaultItemView[];
  selectedId: string | null;
  onSelect: (id: string) => void;
  empty: EmptyStateContent;
  rowRef: (id: string, node: HTMLButtonElement | null) => void;
}

/** Moves focus between rows with the arrow, Home and End keys. */
function onRowKeyDown(event: KeyboardEvent<HTMLButtonElement>) {
  const keys = ['ArrowDown', 'ArrowUp', 'Home', 'End'];
  if (!keys.includes(event.key)) return;
  const list = event.currentTarget.closest('ul');
  if (!list) return;
  const rows = Array.from(list.querySelectorAll<HTMLButtonElement>('[data-row]'));
  const index = rows.indexOf(event.currentTarget);
  if (index === -1) return;
  event.preventDefault();
  const next =
    event.key === 'Home'
      ? 0
      : event.key === 'End'
        ? rows.length - 1
        : Math.min(rows.length - 1, Math.max(0, index + (event.key === 'ArrowDown' ? 1 : -1)));
  rows[next]?.focus();
}

export function ItemList(props: ItemListProps) {
  const listRef = useRef<HTMLUListElement>(null);
  const trimmed = props.query.trim();
  const caption = trimmed
    ? `${props.items.length} ${props.items.length === 1 ? 'result' : 'results'} for “${trimmed}”`
    : '';

  return (
    <>
      <div className="flex flex-col gap-3 border-b border-line-soft px-4 pt-[18px] pb-3">
        <div className="flex items-center gap-2.5">
          <div className="min-w-0 flex-1">
            <h1 className="text-title font-bold tracking-tight-title">{props.title}</h1>
            <div className="text-small text-ink-muted">{props.subtitle}</div>
          </div>
          <Button
            variant="primary"
            unavailable
            icon={<PlusIcon size={16} />}
            title="Not available yet"
          >
            Add item
          </Button>
        </div>
        <SearchField
          id="vault-search"
          label="Search items"
          placeholder={props.searchPlaceholder}
          value={props.query}
          onChange={(event) => {
            props.onQuery(event.target.value);
          }}
          onKeyDown={(event) => {
            if (event.key === 'ArrowDown') {
              event.preventDefault();
              listRef.current?.querySelector<HTMLButtonElement>('[data-row]')?.focus();
            }
          }}
        />
        {props.chips ? (
          <div role="group" aria-label="Filter by category" className="flex flex-wrap gap-1.5">
            {props.chips.map((chip) => (
              <Chip
                key={chip.value}
                pressed={props.kindFilter === chip.value}
                count={chip.count}
                onClick={() => {
                  props.onKindFilter(chip.value);
                }}
              >
                {chip.label}
              </Chip>
            ))}
          </div>
        ) : null}
        {props.tag ? (
          <div className="flex items-center gap-2 text-small text-ink-muted">
            Tagged
            <Chip pressed onClick={props.onClearTag} aria-label={`Clear tag filter ${props.tag}`}>
              #{props.tag}
              <CloseIcon size={14} />
            </Chip>
          </div>
        ) : null}
      </div>

      <div role="status" className={cx('text-small text-ink-muted', caption && 'px-4 pt-2.5')}>
        {caption}
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto p-2">
        {props.items.length > 0 ? (
          <ul
            ref={listRef}
            id="item-list"
            aria-label={`${props.title}, ${props.items.length} items`}
            className="flex flex-col gap-0.5"
          >
            {props.items.map((item) => {
              const current = item.id === props.selectedId;
              return (
                <li key={item.id}>
                  <button
                    ref={(node) => {
                      props.rowRef(item.id, node);
                    }}
                    type="button"
                    data-row=""
                    aria-current={current ? 'true' : undefined}
                    onClick={() => {
                      props.onSelect(item.id);
                    }}
                    onKeyDown={onRowKeyDown}
                    className={cx(
                      'flex w-full cursor-pointer items-center gap-3 rounded-row p-2.5 text-left',
                      current ? 'bg-brand-soft' : 'hover:bg-hover-soft',
                    )}
                  >
                    <ItemAvatar kind={item.kind} title={item.title} />
                    <span className="flex min-w-0 flex-1 flex-col">
                      <span className="truncate text-body font-semibold">{item.title}</span>{' '}
                      <span className="truncate text-small text-ink-muted">{item.subtitle}</span>
                    </span>{' '}
                    {item.favorite ? (
                      <StarIcon
                        filled
                        size={15}
                        strokeWidth={1.6}
                        className="shrink-0 text-brand"
                        role="img"
                        aria-hidden={false}
                        aria-label="Favorite"
                      />
                    ) : null}
                  </button>
                </li>
              );
            })}
          </ul>
        ) : (
          <EmptyState {...props.empty} />
        )}
      </div>
    </>
  );
}

function EmptyState({ title, body, isSearch, action }: EmptyStateContent) {
  return (
    <div id="item-list" className="flex flex-col items-center gap-2.5 px-5 py-12 text-center">
      <div
        aria-hidden="true"
        className="flex size-[52px] items-center justify-center rounded-[14px] bg-brand-tint text-brand-text"
      >
        {isSearch ? <SearchIcon size={24} strokeWidth={1.8} /> : <VaultIcon size={24} />}
      </div>
      <h2 className="mt-1 text-title-sm font-bold">{title}</h2>
      <p className="max-w-[280px] text-body text-ink-muted">{body}</p>
      {action ? <div className="mt-1.5 flex flex-wrap justify-center gap-2">{action}</div> : null}
    </div>
  );
}
