import type { ReactNode } from 'react';
import { openWebVault } from './open-web';

/** The Ruvee mark, as in the web app (apps/web/src/components/ui/logo.tsx). */
export function LogoMark({ size = 24 }: { size?: number }) {
  return (
    <svg className="logo-mark" width={size} height={size} viewBox="0 0 32 32" aria-hidden="true">
      <rect width="32" height="32" rx="9" />
      <circle cx="16" cy="13.5" r="5" fill="none" stroke="#fff" strokeWidth="2.6" />
      <path d="M16 18.5v6" stroke="#fff" strokeWidth="2.6" strokeLinecap="round" />
    </svg>
  );
}

function Icon({ children, size = 16 }: { children: ReactNode; size?: number | undefined }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {children}
    </svg>
  );
}

export const LockIcon = ({ size }: { size?: number | undefined }) => (
  <Icon size={size}>
    <rect x="4.5" y="10.5" width="15" height="10" rx="2.5" />
    <path d="M8 10.5V7.5a4 4 0 0 1 8 0v3" />
  </Icon>
);
export const ExternalIcon = () => (
  <Icon size={14}>
    <path d="M14 4h6v6" />
    <path d="M20 4l-9 9" />
    <path d="M18 14v4a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h4" />
  </Icon>
);
export const CopyIcon = () => (
  <Icon>
    <rect x="8.5" y="8.5" width="12" height="12" rx="2.5" />
    <path d="M15.5 8.5V6a2.5 2.5 0 0 0-2.5-2.5H6A2.5 2.5 0 0 0 3.5 6v7A2.5 2.5 0 0 0 6 15.5h2.5" />
  </Icon>
);
export const SettingsIcon = () => (
  <Icon>
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
  </Icon>
);
export const KeyIcon = () => (
  <Icon size={22}>
    <circle cx="8" cy="15" r="4" />
    <path d="M10.8 12.2L20 3M16 7l3 3M14 9l2 2" />
  </Icon>
);
export const GlobeIcon = () => (
  <Icon size={22}>
    <circle cx="12" cy="12" r="9" />
    <path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" />
  </Icon>
);
export const AlertIcon = () => (
  <Icon size={22}>
    <circle cx="12" cy="12" r="9" />
    <path d="M12 7.5v5.5M12 16.5h.01" />
  </Icon>
);

/** "Open Ruvee": the paired server's web vault (open-web.ts). Hidden without a server. */
export function OpenRuvee({
  server,
  label = 'Open Ruvee',
}: {
  server: string | null;
  label?: string;
}) {
  if (server === null) return null;
  return (
    <button
      type="button"
      className="btn btn-secondary btn-sm"
      title={`Open the Ruvee web vault at ${server}`}
      onClick={() => void openWebVault(server)}
    >
      {label}
      <ExternalIcon />
    </button>
  );
}

export type LockState = 'locked' | 'unlocked' | null;

/** The popup's and the settings page's header: the mark, the lock state, Open Ruvee. */
export function Header({
  server,
  lock,
  title,
}: {
  server: string | null;
  lock: LockState;
  title?: string;
}) {
  return (
    <header className="bar">
      <span className="brand">
        <LogoMark />
        <span className="wordmark">ruvee</span>
        {title ? <span className="bar-title">{title}</span> : null}
      </span>
      <span className="bar-end">
        {lock === null ? null : (
          <span className={`lock-state ${lock}`}>
            <span className="dot" aria-hidden="true" />
            {lock === 'locked' ? 'Locked' : 'Unlocked'}
          </span>
        )}
        <OpenRuvee server={server} />
      </span>
    </header>
  );
}

/** The development build's notice; the popup shows it at the bottom, where it costs no room. */
export function DevTag() {
  return (
    <span className="tag" title="Development build, not reviewed. Use synthetic data only.">
      Development build
    </span>
  );
}

/** One state with one next action: empty, locked, error, not fillable. */
export function StateCard({
  icon,
  title,
  tone = 'neutral',
  children,
  action,
}: {
  icon: ReactNode;
  title: ReactNode;
  tone?: 'neutral' | 'danger';
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className={`state-card ${tone}`}>
      <span className="state-icon">{icon}</span>
      <p className="state-title">{title}</p>
      {children}
      {action}
    </div>
  );
}
