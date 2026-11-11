import type { ComponentType, ReactNode } from 'react';
import {
  CardIcon,
  DiceIcon,
  GridIcon,
  InfoIcon,
  KeyIcon,
  LockIcon,
  NoteIcon,
  PersonIcon,
  ShieldIcon,
  SlidersIcon,
  StarIcon,
  TrashIcon,
} from '../ui/icons';
import { Logo } from '../ui/logo';
import { SoonBadge } from '../ui/soon-badge';
import { cx } from '../ui/cx';
import { SECTION_TITLES } from './filter';
import type { Section, VaultSummary } from './types';
import { VaultSwitcher } from './vault-switcher';

type IconComponent = ComponentType<{ size?: number }>;

const navItemClass =
  'flex min-h-9 w-full items-center gap-2.5 rounded-control px-2.5 text-left text-body';

export function NavButton({
  icon: Icon,
  label,
  count,
  current,
  onSelect,
}: {
  icon: IconComponent;
  label: string;
  count?: number;
  current: boolean;
  onSelect: () => void;
}) {
  return (
    <button
      type="button"
      aria-current={current ? 'page' : undefined}
      onClick={onSelect}
      className={cx(
        navItemClass,
        'cursor-pointer',
        current
          ? 'bg-brand-soft font-semibold text-brand-strong'
          : 'font-medium text-ink-secondary hover:bg-hover',
      )}
    >
      <Icon size={18} />
      <span className="flex-1">{label}</span>
      {count === undefined ? null : (
        <>
          {' '}
          <span className="text-caption font-normal text-ink-muted">{count}</span>
        </>
      )}
    </button>
  );
}

/** Navigation entry for a feature that is not built yet. */
function UnavailableNavItem({ icon: Icon, label }: { icon: IconComponent; label: string }) {
  return (
    <button
      type="button"
      aria-disabled="true"
      title="Not available yet"
      className={cx(navItemClass, 'cursor-not-allowed font-medium text-ink-muted')}
    >
      <Icon size={18} />
      <span className="min-w-0 flex-1 truncate">
        {label} <span className="sr-only">(not available yet)</span>
      </span>
      <SoonBadge />
    </button>
  );
}

function SectionLabel({ children }: { children: ReactNode }) {
  return (
    <div className="px-2.5 pt-4 pb-1.5 text-caption font-semibold tracking-[0.02em] text-ink-muted">
      {children}
    </div>
  );
}

export interface SidebarProps {
  section: Section;
  onSection: (section: Section) => void;
  counts: Record<Section, number>;
  vaultOptions: (VaultSummary & { count: number })[];
  vaultId: string;
  onVault: (vaultId: string) => void;
  /** Rendered in the header row, e.g. the drawer's close button. */
  headerAction?: ReactNode;
  /** Locks the vault; without it "Lock now" is marked unavailable. */
  onLock?: () => void;
  /** Replaces the "Sync not set up" box with the real sync status. */
  statusPanel?: ReactNode;
  /** Extra navigation entries above Settings, e.g. devices. */
  extraNav?: ReactNode;
  /** Makes the "Security" entry available. */
  security?: { readonly current: boolean; readonly onSelect: () => void };
}

export function Sidebar({
  section,
  onSection,
  counts,
  vaultOptions,
  vaultId,
  onVault,
  headerAction,
  onLock,
  statusPanel,
  extraNav,
  security,
}: SidebarProps) {
  const nav = (target: Section, icon: IconComponent, withCount = true) => (
    <NavButton
      icon={icon}
      label={SECTION_TITLES[target]}
      {...(withCount ? { count: counts[target] } : {})}
      current={section === target}
      onSelect={() => {
        onSection(target);
      }}
    />
  );

  return (
    <nav
      aria-label="Vault navigation"
      className="flex h-full flex-col gap-0.5 overflow-y-auto px-3 pt-[18px] pb-3"
    >
      <div className="flex items-center justify-between gap-2 px-2 pb-4">
        <Logo />
        {headerAction}
      </div>

      <VaultSwitcher options={vaultOptions} value={vaultId} onChange={onVault} />

      {nav('all', GridIcon)}
      {nav('favorites', StarIcon)}

      <SectionLabel>Categories</SectionLabel>
      {nav('login', KeyIcon)}
      {nav('note', NoteIcon)}
      {nav('card', CardIcon)}
      {nav('identity', PersonIcon)}

      <div aria-hidden="true" className="mx-1.5 my-3 h-px bg-line" />
      {security ? (
        <NavButton
          icon={ShieldIcon}
          label="Security"
          current={security.current}
          onSelect={security.onSelect}
        />
      ) : (
        <UnavailableNavItem icon={ShieldIcon} label="Security" />
      )}
      <UnavailableNavItem icon={DiceIcon} label="Password generator" />
      {nav('trash', TrashIcon)}

      <div className="min-h-4 flex-1" />
      {extraNav}
      <UnavailableNavItem icon={SlidersIcon} label="Settings" />
      {onLock ? (
        <NavButton icon={LockIcon} label="Lock now" current={false} onSelect={onLock} />
      ) : (
        <UnavailableNavItem icon={LockIcon} label="Lock now" />
      )}

      {statusPanel ?? (
        <div className="mt-2 flex items-start gap-2.5 rounded-row border border-line-menu bg-surface px-3 py-2.5">
          <InfoIcon size={18} className="mt-px shrink-0 text-ink-muted" />
          <div className="flex min-w-0 flex-col gap-px">
            <span className="text-small font-semibold text-ink-secondary">Sync not set up</span>
            <span className="text-caption text-ink-muted">
              Not built yet. Preview data stays in this tab.
            </span>
          </div>
        </div>
      )}
    </nav>
  );
}
