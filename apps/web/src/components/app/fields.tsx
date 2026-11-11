'use client';

import {
  type InputHTMLAttributes,
  type ReactNode,
  type TextareaHTMLAttributes,
  useId,
  useState,
} from 'react';
import { Button } from '../ui/button';
import { cx } from '../ui/cx';
import { AlertIcon, EyeIcon, EyeOffIcon } from '../ui/icons';

const inputClass =
  'h-10 w-full min-w-[12rem] flex-1 rounded-control border bg-surface px-3 text-body-lg placeholder:text-ink-muted focus:border-brand focus:outline-2 focus:-outline-offset-1 focus:outline-brand';

export function FieldError({ id, children }: { id: string; children: ReactNode }) {
  return (
    <p id={id} className="flex items-start gap-1.5 text-small text-danger">
      <AlertIcon size={16} className="mt-px shrink-0" />
      <span>{children}</span>
    </p>
  );
}

interface FieldProps {
  label: string;
  /** Classes for the input itself; `className` styles the wrapper. */
  inputClassName?: string;
  error?: string | undefined;
  hint?: ReactNode;
  /** Shown after the input, e.g. a Show or Generate button. */
  trailing?: ReactNode;
}

export function TextField({
  label,
  error,
  hint,
  trailing,
  className,
  inputClassName,
  ...props
}: FieldProps & InputHTMLAttributes<HTMLInputElement>) {
  const id = useId();
  const errorId = `${id}-error`;
  const hintId = `${id}-hint`;
  const describedBy = [error ? errorId : null, hint ? hintId : null].filter(Boolean).join(' ');
  return (
    <div className={cx('flex flex-col gap-1.5', className)}>
      <label htmlFor={id} className="text-small font-semibold">
        {label}
      </label>
      <div className="flex flex-wrap gap-2">
        <input
          id={id}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy || undefined}
          className={cx(inputClass, error ? 'border-danger' : 'border-line-input', inputClassName)}
          {...props}
        />
        {trailing}
      </div>
      {error ? <FieldError id={errorId}>{error}</FieldError> : null}
      {hint ? (
        <div id={hintId} className="text-small text-ink-muted">
          {hint}
        </div>
      ) : null}
    </div>
  );
}

/**
 * A password input with Show/Hide. Browser password managers and autofill are told this is a
 * new or current password through `autoComplete`; values are never stored by this component.
 */
export function PasswordField(
  props: FieldProps & InputHTMLAttributes<HTMLInputElement> & { extraTrailing?: ReactNode },
) {
  const [shown, setShown] = useState(false);
  const { extraTrailing, ...rest } = props;
  return (
    <TextField
      {...rest}
      type={shown ? 'text' : 'password'}
      spellCheck={false}
      autoCapitalize="off"
      autoCorrect="off"
      trailing={
        <>
          <Button
            onClick={() => {
              setShown(!shown);
            }}
            aria-pressed={shown}
            icon={shown ? <EyeOffIcon size={16} /> : <EyeIcon size={16} />}
            aria-label={
              shown ? `Hide ${props.label.toLowerCase()}` : `Show ${props.label.toLowerCase()}`
            }
          >
            {shown ? 'Hide' : 'Show'}
          </Button>
          {extraTrailing}
        </>
      }
    />
  );
}

export function TextArea({
  label,
  error,
  hint,
  className,
  inputClassName,
  ...props
}: FieldProps & TextareaHTMLAttributes<HTMLTextAreaElement>) {
  const id = useId();
  return (
    <div className={cx('flex flex-col gap-1.5', className)}>
      <label htmlFor={id} className="text-small font-semibold">
        {label}
      </label>
      <textarea
        id={id}
        aria-invalid={error ? true : undefined}
        className={cx(
          'min-h-24 w-full rounded-control border bg-surface px-3 py-2 text-body-lg placeholder:text-ink-muted focus:border-brand focus:outline-2 focus:-outline-offset-1 focus:outline-brand',
          error ? 'border-danger' : 'border-line-input',
          inputClassName,
        )}
        {...props}
      />
      {error ? <FieldError id={`${id}-error`}>{error}</FieldError> : null}
      {hint ? <div className="text-small text-ink-muted">{hint}</div> : null}
    </div>
  );
}

/** A form-level message: an error, or a caution notice. */
export function Notice({
  tone = 'danger',
  children,
}: {
  tone?: 'danger' | 'caution' | 'brand';
  children: ReactNode;
}) {
  return (
    <div
      role={tone === 'danger' ? 'alert' : 'note'}
      className={cx(
        'flex items-start gap-2.5 rounded-menu border px-4 py-3 text-body',
        tone === 'danger' && 'border-danger/25 bg-danger-wash text-danger-strong',
        tone === 'caution' && 'border-caution-line bg-caution-wash text-caution-strong',
        tone === 'brand' && 'border-brand-line bg-brand-wash text-ink-secondary',
      )}
    >
      <AlertIcon size={18} className="mt-px shrink-0" />
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  );
}
