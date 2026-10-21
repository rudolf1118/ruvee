import { CardIcon, NoteIcon, PersonIcon } from '../ui/icons';
import { cx } from '../ui/cx';
import type { ItemKind } from './types';

const KIND_ICONS = { note: NoteIcon, card: CardIcon, identity: PersonIcon } as const;
const KIND_SHORT = { note: 'NOTE', card: 'CARD', identity: 'ID' } as const;

/** Square tile beside an item: the login's initial, or the item type. */
export function ItemAvatar({
  kind,
  title,
  size = 'md',
}: {
  kind: ItemKind;
  title: string;
  size?: 'md' | 'lg';
}) {
  const box = size === 'lg' ? 'size-[52px] rounded-[13px]' : 'size-9 rounded-[9px]';
  if (kind === 'login') {
    return (
      <span
        aria-hidden="true"
        className={cx(
          box,
          'flex shrink-0 items-center justify-center border border-avatar-line bg-avatar font-bold text-ink-secondary',
          size === 'lg' ? 'text-[22px] text-ink' : 'text-body-lg',
        )}
      >
        {title.charAt(0).toUpperCase()}
      </span>
    );
  }
  const Icon = KIND_ICONS[kind];
  return (
    <span
      aria-hidden="true"
      className={cx(box, 'flex shrink-0 items-center justify-center bg-brand-tint text-brand-text')}
    >
      {size === 'lg' ? (
        <span className="text-small font-bold tracking-[0.04em]">{KIND_SHORT[kind]}</span>
      ) : (
        <Icon size={18} />
      )}
    </span>
  );
}
