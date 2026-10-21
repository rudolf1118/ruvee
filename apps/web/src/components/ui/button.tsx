import type { ComponentProps, MouseEvent, ReactNode } from 'react';
import { cx } from './cx';

export type ButtonVariant = 'secondary' | 'primary' | 'ghost' | 'link' | 'danger';
export type ButtonSize = 'md' | 'sm';

const base =
  'inline-flex shrink-0 items-center justify-center whitespace-nowrap border font-semibold transition-colors [&>svg]:shrink-0';

const sizes: Record<ButtonSize, { text: string; iconOnly: string }> = {
  md: { text: 'h-9 gap-2 rounded-control px-3.5 text-body', iconOnly: 'size-9 rounded-control' },
  sm: {
    text: 'h-[30px] gap-1.5 rounded-control-sm px-2.5 text-small',
    iconOnly: 'size-[30px] rounded-control-sm',
  },
};

const variants: Record<ButtonVariant, { idle: string; hover: string }> = {
  secondary: { idle: 'border-line-button bg-surface text-ink', hover: 'hover:bg-subtle' },
  primary: {
    idle: 'border-brand bg-brand text-white',
    hover: 'hover:border-brand-hover hover:bg-brand-hover',
  },
  ghost: { idle: 'border-transparent bg-transparent text-ink', hover: 'hover:bg-hover' },
  link: { idle: 'border-transparent bg-transparent text-brand-text', hover: 'hover:bg-hover' },
  danger: { idle: 'border-transparent bg-transparent text-danger', hover: 'hover:bg-hover' },
};

export interface ButtonProps extends Omit<ComponentProps<'button'>, 'disabled'> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  icon?: ReactNode;
  /** Square button showing only `icon`; requires an `aria-label`. */
  iconOnly?: boolean;
  /**
   * Marks a control for a feature that is not built yet. It stays focusable so
   * keyboard and screen reader users can discover it, but does nothing.
   */
  unavailable?: boolean;
}

export function Button({
  variant = 'secondary',
  size = 'md',
  icon,
  iconOnly = false,
  unavailable = false,
  className,
  children,
  onClick,
  type = 'button',
  ...props
}: ButtonProps) {
  const style = variants[variant];
  const handleClick = (event: MouseEvent<HTMLButtonElement>) => {
    if (unavailable) {
      event.preventDefault();
      return;
    }
    onClick?.(event);
  };
  return (
    <button
      type={type}
      aria-disabled={unavailable || undefined}
      onClick={handleClick}
      className={cx(
        base,
        iconOnly ? sizes[size].iconOnly : sizes[size].text,
        style.idle,
        unavailable ? 'cursor-not-allowed opacity-45' : cx('cursor-pointer', style.hover),
        className,
      )}
      {...props}
    >
      {icon}
      {children}
      {unavailable ? (
        <>
          {' '}
          <span className="sr-only">(not available yet)</span>
        </>
      ) : null}
    </button>
  );
}
