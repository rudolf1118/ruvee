'use client';

import { type SubmitEvent, useEffect, useRef, useState } from 'react';
import type { PairingCode, PairingHostStatus, UnlockedVault } from '@/vault/protocol';
import { VaultClientError, type VaultClient } from '@/vault/client';
import { Button } from '../ui/button';
import { ChevronLeftIcon } from '../ui/icons';
import { AuthCard } from './auth-layout';
import { Notice, PasswordField, TextField } from './fields';
import { messageFor } from './messages';

const POLL_MS = 2000;

function errorText(e: unknown): string {
  return e instanceof VaultClientError
    ? messageFor(e.code, e.retryAfterSeconds)
    : messageFor('internal');
}

function useCountdown(deadlineMs: number | null): string {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (deadlineMs === null) return;
    const timer = setInterval(() => {
      setNow(Date.now());
    }, 1000);
    return () => {
      clearInterval(timer);
    };
  }, [deadlineMs]);
  if (deadlineMs === null) return '';
  const left = Math.max(0, Math.round((deadlineMs - now) / 1000));
  return `${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`;
}

export const PLATFORM_NAMES: Record<string, string> = {
  web: 'web browser',
  extension: 'browser extension',
  ios: 'iPhone or iPad',
  android: 'Android device',
};

/**
 * Device A: shows the code (device-enrollment §3.2 steps 2 and 3), waits for a request whose MAC
 * the worker verified, and asks the user to approve it (step 7). The code is never copied or sent.
 */
export function AddDevicePanel({ client, onClose }: { client: VaultClient; onClose: () => void }) {
  const [code, setCode] = useState<PairingCode | null>(null);
  const [status, setStatus] = useState<PairingHostStatus>({ state: 'waiting' });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const countdown = useCountdown(code?.expiresAtMs ?? null);
  const codeRef = useRef<PairingCode | null>(null);

  useEffect(() => {
    let cancelled = false;
    client.call('pairingStart').then(
      (started) => {
        if (cancelled) {
          void client.call('pairingCancel', { pairingId: started.pairingId });
          return;
        }
        codeRef.current = started;
        setCode(started);
      },
      (e: unknown) => {
        setError(errorText(e));
      },
    );
    return () => {
      cancelled = true;
      const open = codeRef.current;
      if (open)
        void client.call('pairingCancel', { pairingId: open.pairingId }).catch(() => undefined);
    };
  }, [client]);

  useEffect(() => {
    if (!code || status.state !== 'waiting') return;
    const timer = setInterval(() => {
      void client
        .call('pairingStatus', { pairingId: code.pairingId })
        .then(setStatus, (e: unknown) => {
          setError(errorText(e));
        });
    }, POLL_MS);
    return () => {
      clearInterval(timer);
    };
  }, [client, code, status.state]);

  const approve = () => {
    if (!code || busy) return;
    setBusy(true);
    client.call('pairingApprove', { pairingId: code.pairingId }).then(
      () => {
        codeRef.current = null;
        setStatus({ state: 'approved' });
        setBusy(false);
      },
      (e: unknown) => {
        setError(errorText(e));
        setBusy(false);
      },
    );
  };

  return (
    <div className="mx-auto flex max-w-[640px] flex-col gap-4">
      <Button
        variant="link"
        className="-ml-2 self-start"
        icon={<ChevronLeftIcon size={18} />}
        onClick={onClose}
      >
        Back to items
      </Button>
      <section className="flex flex-col gap-4 rounded-card border border-line bg-surface p-6 shadow-card">
        <h2 className="text-heading leading-tight font-bold tracking-tight-title">Add a device</h2>
        {error ? <Notice>{error}</Notice> : null}
        {status.state === 'approved' ? (
          <>
            <Notice tone="brand">
              The new device was added. It finishes setting up on its own screen.
            </Notice>
            <Button variant="primary" className="self-start" onClick={onClose}>
              Done
            </Button>
          </>
        ) : status.state === 'failed' ? (
          <Notice>{messageFor('pairing_failed')}</Notice>
        ) : status.state === 'expired' ? (
          <Notice tone="caution">{messageFor('pairing_expired')}</Notice>
        ) : status.state === 'request' ? (
          <>
            <p className="text-body-lg">
              Approve a new <strong>{PLATFORM_NAMES[status.platform] ?? status.platform}</strong>{' '}
              that asked to join at {new Date(status.requestedAtMs).toLocaleTimeString()}?
            </p>
            <p className="text-small text-ink-muted">
              Approve only if you just typed this code on that device yourself. Approving gives it a
              copy of the keys to your vault.
            </p>
            <div className="flex gap-2">
              <Button variant="primary" onClick={approve} aria-disabled={busy || undefined}>
                {busy ? 'Approving…' : 'Approve'}
              </Button>
              <Button onClick={onClose}>Cancel</Button>
            </div>
          </>
        ) : (
          <>
            <p className="text-body text-ink-muted">
              On the new device, log in and type this code. It works once and expires in{' '}
              <span aria-live="off">{countdown || '10:00'}</span>. Never type it anywhere else.
            </p>
            <output
              data-testid="pairing-code"
              className="rounded-menu border border-line bg-canvas p-4 font-mono text-title tracking-wide break-words select-all"
            >
              {code?.code ?? 'Creating a code…'}
            </output>
            <p className="text-small text-ink-muted" aria-live="polite">
              Waiting for the new device…
            </p>
          </>
        )}
      </section>
    </div>
  );
}

/** Device B: logged in but pending. Joins with the code and waits for approval (steps 4 to 10). */
export function JoinWithCode({
  client,
  username,
  onEnrolled,
}: {
  client: VaultClient;
  username: string;
  onEnrolled: (vault: UnlockedVault) => void;
}) {
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [needsPassword, setNeedsPassword] = useState(false);
  const [waiting, setWaiting] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void client.call('pairingNeedsPassword').then(setNeedsPassword, () => undefined);
  }, [client]);

  useEffect(() => {
    if (!waiting) return;
    const timer = setInterval(() => {
      client.call('pairingWait').then(
        (status) => {
          if (status.state === 'enrolled') {
            clearInterval(timer);
            onEnrolled(status.vault);
          }
        },
        (e: unknown) => {
          clearInterval(timer);
          setWaiting(false);
          if (e instanceof VaultClientError && e.code === 'password_required')
            setNeedsPassword(true);
          setError(errorText(e));
        },
      );
    }, POLL_MS);
    return () => {
      clearInterval(timer);
    };
  }, [client, waiting, onEnrolled]);

  const submit = (event: SubmitEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    client
      .call('pairingJoin', { code, ...(needsPassword ? { password } : {}) })
      .then(
        () => {
          setPassword('');
          setWaiting(true);
        },
        (e: unknown) => {
          if (e instanceof VaultClientError && e.code === 'password_required')
            setNeedsPassword(true);
          setError(errorText(e));
        },
      )
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <AuthCard title="Add this device">
      <p className="text-body text-ink-muted">
        You are logged in as <strong className="text-ink">{username}</strong>, but this device
        can&apos;t open your vault yet: your password alone is not enough. On a device that is
        already set up, choose <strong>Add a device</strong> and type the code it shows here.
      </p>
      {waiting ? (
        <Notice tone="brand">Waiting for approval on your other device…</Notice>
      ) : (
        <form className="flex flex-col gap-4" onSubmit={submit}>
          <TextField
            label="Pairing code"
            value={code}
            onChange={(e) => {
              setCode(e.target.value);
            }}
            autoComplete="off"
            spellCheck={false}
            placeholder="PC1-…"
            inputClassName="font-mono"
          />
          {needsPassword ? (
            <PasswordField
              label="Master password"
              value={password}
              onChange={(e) => {
                setPassword(e.target.value);
              }}
              autoComplete="current-password"
            />
          ) : null}
          {error ? <Notice>{error}</Notice> : null}
          <Button
            variant="primary"
            type="submit"
            aria-disabled={busy || undefined}
            className="self-start"
          >
            {busy ? 'Sending…' : 'Add this device'}
          </Button>
        </form>
      )}
    </AuthCard>
  );
}
