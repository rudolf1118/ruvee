'use client';

import Link from 'next/link';
import { type SubmitEvent, useEffect, useRef, useState } from 'react';
import type { DevicePhase, UnlockedVault } from '@ruvee/vault';
import { VaultClientError, type VaultClient } from '@/vault/client';
import { Button } from '../ui/button';
import { LockIcon } from '../ui/icons';
import { AuthCard, DevelopmentNotice, RecoveryWarning } from './auth-layout';
import { Notice, PasswordField, TextField } from './fields';
import { messageFor } from './messages';

/** The design preview is a development-only route (`page.dev.tsx`). */
const showPreviewLink = process.env.NODE_ENV !== 'production';

export function WelcomeScreen({
  onCreate,
  onLogin,
  onRecover,
  onOpenExport,
  onReopen,
}: {
  onCreate: () => void;
  onLogin: () => void;
  onRecover: () => void;
  onOpenExport: () => void;
  /** A restored server waiting for its owner (backup-restore.md §3.13), Recovery Kit path. */
  onReopen: () => void;
}) {
  return (
    <AuthCard title="Keep every password in one calm, safe place.">
      <p className="text-body-lg text-ink-muted">
        Ruvee stores your logins and notes in a vault that is encrypted on your devices before
        anything reaches the server.
      </p>
      <DevelopmentNotice />
      <div className="flex flex-wrap gap-3">
        <Button variant="primary" onClick={onCreate}>
          Create an account
        </Button>
        <Button variant="ghost" onClick={onLogin}>
          I already have an account
        </Button>
      </div>
      <Button variant="link" className="-ml-2 self-start" onClick={onRecover}>
        Lost your password or devices? Use your Recovery Kit
      </Button>
      <Button variant="link" className="-ml-2 self-start" onClick={onOpenExport}>
        Open an encrypted export
      </Button>
      <Button variant="link" className="-ml-2 self-start" onClick={onReopen}>
        Reopen a restored server with your Recovery Kit
      </Button>
      {showPreviewLink ? (
        <Link
          href="/preview"
          className="self-start text-small font-semibold text-brand-text underline"
        >
          Open the interface preview
        </Link>
      ) : null}
    </AuthCard>
  );
}

function useSubmit() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = async (task: () => Promise<void>) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      await task();
    } catch (e) {
      setError(
        e instanceof VaultClientError
          ? messageFor(e.code, e.retryAfterSeconds)
          : messageFor('internal'),
      );
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, run };
}

/** Logging in on a device that is not set up yet: it becomes a pending device (D-04). */
export function LoginScreen({
  client,
  onBack,
  onPhase,
}: {
  client: VaultClient;
  onBack: () => void;
  onPhase: (phase: DevicePhase) => void;
}) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { busy, error, run } = useSubmit();
  const submit = (event: SubmitEvent) => {
    event.preventDefault();
    void run(async () => {
      const phase = await client.call('login', { username, password });
      setPassword('');
      onPhase(phase);
    });
  };
  return (
    <AuthCard title="Log in on this device">
      <p className="text-body text-ink-muted">
        Logging in proves who you are to the server. To open your vault here, you will then add this
        device from one that is already set up: your password alone can&apos;t unlock a new device.
      </p>
      <form className="flex flex-col gap-4" onSubmit={submit}>
        <TextField
          label="Username"
          value={username}
          onChange={(e) => {
            setUsername(e.target.value);
          }}
          autoComplete="username"
          required
        />
        <PasswordField
          label="Master password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
          }}
          autoComplete="current-password"
          required
        />
        {error ? <Notice>{error}</Notice> : null}
        <div className="flex justify-between gap-2">
          <Button variant="ghost" onClick={onBack}>
            Back
          </Button>
          <Button variant="primary" type="submit" aria-disabled={busy || undefined}>
            {busy ? 'Logging in…' : 'Log in'}
          </Button>
        </div>
      </form>
    </AuthCard>
  );
}

/** The design's Locked screen. Unlocking needs only this device's data and works offline. */
export function LockScreen({
  client,
  username,
  notice,
  onUnlocked,
  onRecover,
}: {
  client: VaultClient;
  username: string;
  notice?: string | null;
  onUnlocked: (vault: UnlockedVault) => void;
  onRecover: () => void;
}) {
  const [password, setPassword] = useState('');
  // Set after `previous_password_required`: the password and SK both changed elsewhere.
  const [previous, setPrevious] = useState<string | null>(null);
  const { busy, error, run } = useSubmit();
  const formRef = useRef<HTMLFormElement>(null);
  useEffect(() => {
    // The unlock screen has one task, so its field takes focus when it appears.
    formRef.current?.querySelector<HTMLInputElement>('input[type="password"]')?.focus();
  }, []);
  const submit = (event: SubmitEvent) => {
    event.preventDefault();
    void run(async () => {
      let vault;
      try {
        vault = await client.call('unlock', {
          password,
          ...(previous === null ? {} : { previousPassword: previous }),
        });
      } catch (e) {
        if (e instanceof VaultClientError && e.code === 'previous_password_required')
          setPrevious('');
        throw e;
      }
      setPassword('');
      setPrevious(null);
      onUnlocked(vault);
    });
  };
  return (
    <AuthCard
      title="Your vault is locked"
      badge={
        <span className="inline-flex items-center gap-1.5 rounded-full bg-subtle px-2.5 py-1 text-small font-semibold text-ink-secondary">
          <LockIcon size={14} /> Locked
        </span>
      }
    >
      <p className="text-body text-ink-muted">
        Enter the master password for <strong className="text-ink">{username}</strong> to open your
        vault on this device.
      </p>
      {notice ? <Notice tone="caution">{notice}</Notice> : null}
      <form ref={formRef} className="flex flex-col gap-4" onSubmit={submit}>
        {/* Lets password managers associate the field with the account. */}
        <input
          type="text"
          name="username"
          autoComplete="username"
          value={username}
          readOnly
          hidden
        />
        <PasswordField
          label="Master password"
          value={password}
          onChange={(e) => {
            setPassword(e.target.value);
          }}
          autoComplete="current-password"
          error={error ?? undefined}
        />
        {previous === null ? null : (
          <PasswordField
            label="Previous master password"
            value={previous}
            onChange={(e) => {
              setPrevious(e.target.value);
            }}
            autoComplete="off"
            hint="The one this device used before the change. Needed once."
          />
        )}
        <Button
          variant="primary"
          type="submit"
          aria-disabled={busy || undefined}
          className="w-full"
        >
          {busy ? 'Unlocking…' : 'Unlock'}
        </Button>
      </form>
      <RecoveryWarning />
      <Button variant="link" className="-ml-2 self-start" onClick={onRecover}>
        Forgot your master password? Use your Recovery Kit
      </Button>
    </AuthCard>
  );
}
