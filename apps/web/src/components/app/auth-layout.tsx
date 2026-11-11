import type { ReactNode } from 'react';
import { Logo } from '../ui/logo';

/** The centred card of the design's Locked and Set up screens. */
export function AuthCard({
  title,
  children,
  aside,
  badge,
  wide = false,
}: {
  title: string;
  children: ReactNode;
  aside?: ReactNode;
  badge?: ReactNode;
  wide?: boolean;
}) {
  return (
    <main className="flex min-h-dvh flex-col">
      <header className="flex h-14 items-center px-4 md:px-6">
        <Logo />
      </header>
      <div className="flex flex-1 items-start justify-center px-4 pt-6 pb-12 md:items-center md:pt-0">
        <div
          className={
            wide ? 'flex w-full max-w-[920px] flex-col gap-4 md:flex-row' : 'w-full max-w-[440px]'
          }
        >
          <section className="flex min-w-0 flex-1 flex-col gap-4 rounded-card border border-line bg-surface p-6 shadow-card md:p-8">
            {badge ? <div className="flex justify-end">{badge}</div> : null}
            <h1 className="text-heading leading-tight font-bold tracking-tight-title">{title}</h1>
            {children}
          </section>
          {aside ? (
            <aside className="rounded-card border border-brand-line bg-brand-wash p-6 md:w-[300px]">
              {aside}
            </aside>
          ) : null}
        </div>
      </div>
    </main>
  );
}

/** Ruvee's recovery wording (account-recovery.md §8), shown on setup and unlock screens. */
export function RecoveryWarning() {
  return (
    <p className="text-small text-ink-muted">
      Ruvee can&apos;t see, reset or recover your master password, and nobody can recover your data
      for you. If you forget your password or lose all your devices, your Recovery Kit is the only
      way back in. Without your password and an enrolled device, or your Recovery Kit, your data is
      permanently lost.
    </p>
  );
}

export function DevelopmentNotice() {
  return (
    <p className="rounded-menu border border-dashed border-brand-line bg-brand-wash px-3.5 py-3 text-small text-ink-secondary">
      Development build, not reviewed. Use synthetic data only and never type a real password.
    </p>
  );
}
