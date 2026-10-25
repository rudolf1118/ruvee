'use client';

import { useCallback, useEffect, useState } from 'react';
import type { ActivityEvent } from '@/vault/protocol';
import { VaultClientError, type VaultClient } from '@/vault/client';
import { Button } from '../ui/button';
import { ChevronLeftIcon } from '../ui/icons';
import { Notice } from './fields';
import { messageFor } from './messages';

/** Events that may mean someone else is acting on the account. */
const WATCH = new Set([
  'login_failed',
  'refresh_reuse',
  'recovery_started',
  'recovery_failed',
  'pairing_mac_failed',
  'integrity_warning_reported',
]);

function describe(e: ActivityEvent): string {
  switch (e.type) {
    case 'login_succeeded':
      return e.details.newDevice === true ? 'Signed in on a new device' : 'Signed in';
    case 'login_failed':
      return 'Failed sign-in attempt';
    case 'session_revoked':
      return 'A session was signed out';
    case 'refresh_reuse':
      return 'A reused sign-in token was refused, and its session ended';
    case 'password_changed':
      return 'Master password changed';
    case 'recovery_started':
      return 'The Recovery Kit was used to start a recovery';
    case 'recovery_failed':
      return 'Failed Recovery Kit attempt';
    case 'recovery_completed':
      return 'Recovery completed';
    case 'recovery_key_rotated':
      return 'New Recovery Kit made';
    case 'secret_key_rotated':
      return 'Secret Key replaced';
    case 'device_pairing_requested':
      return 'A device asked to be added';
    case 'device_enrolled':
      return 'A device was added';
    case 'device_revoked':
      return e.details.reason === 'lost' ? 'A device was removed as lost' : 'A device was removed';
    case 'pairing_mac_failed':
      return 'A pairing request failed its check and was cancelled';
    case 'vault_reset':
      return 'The vault was reset';
    case 'bootstrap_used':
      return 'Account created';
    case 'bootstrap_failed':
      return 'Failed setup attempt';
    case 'integrity_warning_reported':
      return "A device found data that didn't pass Ruvee's checks";
    default:
      return e.type;
  }
}

function errorText(e: unknown): string {
  return e instanceof VaultClientError
    ? messageFor(e.code, e.retryAfterSeconds)
    : messageFor('internal');
}

/** P2-15: what happened on the account, from the server's security events (INV-12). */
export function ActivityPanel({ client, onClose }: { client: VaultClient; onClose: () => void }) {
  const [events, setEvents] = useState<readonly ActivityEvent[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(
    (from?: string) => {
      client
        .call('activity', from === undefined ? {} : { cursor: from })
        .then(
          (page) => {
            setError(null);
            setEvents((prev) =>
              from === undefined ? page.events : [...(prev ?? []), ...page.events],
            );
            setCursor(page.nextCursor);
          },
          (e: unknown) => {
            setError(errorText(e));
          },
        )
        .finally(() => {
          setBusy(false);
        });
    },
    [client],
  );

  useEffect(() => {
    load();
  }, [load]);

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
        <h2 className="text-heading leading-tight font-bold tracking-tight-title">Activity</h2>
        <p className="text-body text-ink-muted">
          Sign-ins, device changes and key changes on your account, newest first. Ruvee keeps them
          for a year. If you see something you didn&apos;t do, change your master password and
          review your devices.
        </p>
        {error ? (
          <Notice>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span>{error}</span>
              <Button
                size="sm"
                onClick={() => {
                  load();
                }}
              >
                Try again
              </Button>
            </div>
          </Notice>
        ) : null}
        {events === null && !error ? (
          <p className="text-body text-ink-muted" aria-busy="true">
            Loading activity…
          </p>
        ) : null}
        {events?.length === 0 ? <p className="text-body text-ink-muted">No activity yet.</p> : null}
        {events && events.length > 0 ? (
          <ol className="flex flex-col divide-y divide-line rounded-menu border border-line">
            {events.map((e) => (
              <li key={e.id} className="flex flex-col gap-0.5 px-4 py-3">
                <span
                  className={
                    WATCH.has(e.type)
                      ? 'text-body font-semibold text-caution-strong'
                      : 'text-body font-semibold'
                  }
                >
                  {describe(e)}
                </span>
                <span className="text-small text-ink-muted">
                  <time dateTime={new Date(e.atMs).toISOString()}>
                    {new Date(e.atMs).toLocaleString()}
                  </time>
                  {e.device === 'this_device' ? ' · this device' : ''}
                  {e.ip ? ` · ${e.ip}` : ''}
                </span>
              </li>
            ))}
          </ol>
        ) : null}
        {cursor ? (
          <Button
            className="self-start"
            aria-disabled={busy || undefined}
            onClick={() => {
              if (busy) return;
              setBusy(true);
              load(cursor);
            }}
          >
            {busy ? 'Loading…' : 'Show older'}
          </Button>
        ) : null}
      </section>
    </div>
  );
}
