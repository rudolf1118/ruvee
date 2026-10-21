'use client';

import { type KeyboardEvent, useEffect, useId, useRef, useState } from 'react';
import { ChevronDownIcon } from '../ui/icons';
import { cx } from '../ui/cx';
import { ALL_VAULTS, type VaultSummary } from './types';

interface VaultOption extends VaultSummary {
  count: number;
}

interface VaultSwitcherProps {
  options: VaultOption[];
  value: string;
  onChange: (vaultId: string) => void;
}

/** Vault picker: a menu button with radio items, operable by keyboard. */
export function VaultSwitcher({ options, value, onChange }: VaultSwitcherProps) {
  const [open, setOpen] = useState(false);
  const menuId = useId();
  const rootRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const current = options.find((option) => option.id === value) ?? options[0];
  const currentIndex = Math.max(
    0,
    options.findIndex((option) => option.id === value),
  );

  useEffect(() => {
    if (!open) return;
    itemRefs.current[currentIndex]?.focus();
    const onPointerDown = (event: PointerEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    document.addEventListener('pointerdown', onPointerDown);
    return () => {
      document.removeEventListener('pointerdown', onPointerDown);
    };
  }, [open, currentIndex]);

  const close = (restoreFocus: boolean) => {
    setOpen(false);
    if (restoreFocus) buttonRef.current?.focus();
  };

  const onMenuKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const items = itemRefs.current.filter((item): item is HTMLButtonElement => item !== null);
    const index = items.indexOf(document.activeElement as HTMLButtonElement);
    const focusAt = (i: number) => items[(i + items.length) % items.length]?.focus();
    if (event.key === 'ArrowDown') focusAt(index + 1);
    else if (event.key === 'ArrowUp') focusAt(index - 1);
    else if (event.key === 'Home') focusAt(0);
    else if (event.key === 'End') focusAt(items.length - 1);
    else if (event.key === 'Escape') close(true);
    else if (event.key === 'Tab') {
      close(false);
      return;
    } else return;
    event.preventDefault();
  };

  if (!current) return null;
  const initial = current.id === ALL_VAULTS ? 'All' : current.name.charAt(0).toUpperCase();

  return (
    <div ref={rootRef} className="relative mb-3">
      <button
        ref={buttonRef}
        type="button"
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => {
          setOpen((wasOpen) => !wasOpen);
        }}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
            event.preventDefault();
            setOpen(true);
          }
        }}
        className="flex w-full cursor-pointer items-center gap-2.5 rounded-row border border-line-strong bg-surface px-2.5 py-2 text-left"
      >
        <span
          aria-hidden="true"
          className="flex size-[30px] shrink-0 items-center justify-center rounded-control bg-brand-soft text-small font-bold text-brand-text"
        >
          {initial}
        </span>
        <span className="flex min-w-0 flex-1 flex-col">
          <span className="text-caption text-ink-muted">Vault</span>{' '}
          <span className="truncate text-body font-semibold">{current.name}</span>
        </span>
        <ChevronDownIcon size={16} className="text-ink-muted" />
      </button>
      {open ? (
        <div
          id={menuId}
          role="menu"
          aria-label="Choose a vault"
          tabIndex={-1}
          onKeyDown={onMenuKeyDown}
          className="absolute top-[calc(100%+6px)] right-0 left-0 z-20 flex flex-col gap-0.5 rounded-menu border border-line-menu bg-surface p-1.5 shadow-menu"
        >
          {options.map((option, index) => {
            const selected = option.id === value;
            return (
              <button
                key={option.id}
                ref={(node) => {
                  itemRefs.current[index] = node;
                }}
                type="button"
                role="menuitemradio"
                aria-checked={selected}
                tabIndex={-1}
                onClick={() => {
                  onChange(option.id);
                  close(true);
                }}
                className={cx(
                  'flex min-h-9 w-full cursor-pointer items-center gap-2.5 rounded-control-sm px-2.5 text-left text-body',
                  selected ? 'bg-brand-soft font-semibold text-brand-strong' : 'hover:bg-subtle',
                )}
              >
                <span className="flex-1">{option.name}</span>{' '}
                <span className="text-caption font-normal text-ink-muted">{option.count}</span>
              </button>
            );
          })}
        </div>
      ) : null}
    </div>
  );
}
