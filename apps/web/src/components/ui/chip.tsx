import type { ButtonHTMLAttributes } from 'react';
import { cx } from './cx';

interface ChipProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  pressed: boolean;
  count?: number;
}

/** Toggle filter chip ("All 14", "Logins 9"). */
export function Chip({ pressed, count, className, children, ...props }: ChipProps) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      className={cx(
        'inline-flex h-[30px] shrink-0 cursor-pointer items-center gap-1.5 rounded-full border px-3 text-small',
        pressed
          ? 'border-brand-line bg-brand-soft font-semibold text-brand-strong'
          : 'border-line-strong bg-surface font-medium text-ink-secondary hover:bg-hover-soft',
        className,
      )}
      {...props}
    >
      {children}
      {count === undefined ? null : (
        <>
          {' '}
          <span className="font-medium text-ink-muted">{count}</span>
        </>
      )}
    </button>
  );
}
