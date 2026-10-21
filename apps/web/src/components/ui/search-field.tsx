import type { InputHTMLAttributes } from 'react';
import { SearchIcon } from './icons';

interface SearchFieldProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> {
  id: string;
  label: string;
}

export function SearchField({ id, label, ...props }: SearchFieldProps) {
  return (
    <div className="relative">
      <label htmlFor={id} className="sr-only">
        {label}
      </label>
      <SearchIcon size={16} className="pointer-events-none absolute top-3 left-3 text-ink-muted" />
      <input
        id={id}
        type="search"
        autoComplete="off"
        spellCheck={false}
        className="h-10 w-full rounded-control border border-line-input bg-canvas pr-3 pl-9 text-body placeholder:text-ink-muted focus:border-brand focus:outline-2 focus:-outline-offset-1 focus:outline-brand"
        {...props}
      />
    </div>
  );
}
