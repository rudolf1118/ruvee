import type { ButtonHTMLAttributes } from 'react';
import { cx } from './cx';

/** Clickable "#tag" pill that filters the list by that tag. */
export function Tag({ className, children, ...props }: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      type="button"
      className={cx(
        'inline-flex h-7 cursor-pointer items-center gap-1 rounded-full border border-line-menu bg-canvas px-2.5 text-small text-ink-secondary',
        'hover:border-brand-line hover:bg-brand-soft hover:text-brand-strong',
        className,
      )}
      {...props}
    >
      #{children}
    </button>
  );
}
