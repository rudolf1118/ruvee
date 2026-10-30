'use client';

import type { LocalStateView, SyncStatus } from '@ruvee/vault';
import { type SubmitEvent, useCallback, useEffect, useState } from 'react';
import { VaultClientError, type VaultClient } from '@/vault/client';
import { Button } from '../ui/button';
import { download } from './export';
import { Notice, PasswordField, TextField } from './fields';
import { messageFor } from './messages';

/** Sync states in which this device may hold more than the server (backup-restore.md §3.12). */
const RESTORE_REASONS = new Set(['server_behind', 'history_rewritten', 'keyset_rollback']);

export function needsRestoreHelp(status: SyncStatus, sessionProblem: string | undefined): boolean {
  return (
    status.state === 'maintenance' ||
    status.state === 'reopening' ||
    sessionProblem === 'device_unknown' ||
    (status.state === 'integrity_error' && RESTORE_REASONS.has(status.integrity ?? ''))
  );
}

/** The restore-specific explanation; the server's restore claim only picks the wording. */
export function restoreExplanation(status: SyncStatus, sessionProblem?: string): string {
  if (status.state === 'maintenance')
    return 'The server is being restored by its owner and is not available yet. This device keeps its local copy, read-only, and changes nothing until the server opens again.';
  if (status.state === 'reopening')
    return 'The server was restored from a backup and waits for its owner to reopen it, with a code from the server and the master password from the time of the backup. Until then this device keeps its local copy, read-only.';
  const restored = status.serverRestoredAtMs !== undefined;
  const why = restored
    ? 'The server reports that it was restored from a backup, which can be older than this device.'
    : 'This can happen when the server was restored from an older backup.';
  if (sessionProblem === 'device_unknown')
    return `${why} The server doesn't know this device, so it won't sync. Its local copy is kept and nothing is erased.`;
  if (status.integrity === 'keyset_rollback')
    return `${why} The server has older account keys than this device, so nothing from it was applied. Your local copy is unchanged and read-only.`;
  return `${why} This device holds newer changes than the server, so nothing from it was applied. Your local copy is unchanged and read-only.`;
}

export function errorText(e: unknown): string {
  return e instanceof VaultClientError
    ? messageFor(e.code, e.retryAfterSeconds)
    : messageFor('internal');
}

export const plural = (n: number, one: string, many: string) =>
  `${String(n)} ${n === 1 ? one : many}`;

/**
 * An offline export of this device's verified copy (backup-restore.md §3.12): the form, and what
 * the file holds and leaves out. Shared by the restore help and the move to a new account.
 */
export function LocalExportForm({
  client,
  local,
  onSaved,
}: {
  client: VaultClient;
  local: LocalStateView | null;
  onSaved: () => void;
}) {
  const [recoveryKey, setRecoveryKey] = useState('');
  const [password, setPassword] = useState('');
  const [acknowledged, setAcknowledged] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);

  const notIncluded = local ? local.pending + local.conflicts : 0;

  const exportLocal = (event: SubmitEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    setSaved(null);
    client
      .call('exportLocal', { password, recoveryKey, acknowledgeNotIncluded: acknowledged })
      .then(
        (file) => {
          download(file.fileName, file.text);
          setPassword('');
          setRecoveryKey('');
          setSaved(
            `Saved as ${file.fileName}: the ${plural(file.snapshot.items, 'item', 'items')} this device last verified, as of ${new Date(file.snapshot.asOfMs).toLocaleString()}.` +
              (file.notIncluded.pending + file.notIncluded.conflicts > 0
                ? ` Not in the file: ${plural(file.notIncluded.pending, 'change', 'changes')} waiting to sync and ${plural(file.notIncluded.conflicts, 'conflict', 'conflicts')}. They stay on this device.`
                : ''),
          );
          onSaved();
        },
        (e: unknown) => {
          setError(errorText(e));
        },
      )
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <>
      {saved ? <Notice tone="brand">{saved}</Notice> : null}
      <form className="flex flex-col gap-4" onSubmit={exportLocal}>
        <TextField
          label="Recovery Key for this export"
          value={recoveryKey}
          autoComplete="off"
          spellCheck={false}
          placeholder="RK1-…"
          inputClassName="font-mono"
          onChange={(e) => {
            setRecoveryKey(e.target.value);
          }}
        />
        <PasswordField
          label="Master password on this device"
          value={password}
          autoComplete="current-password"
          onChange={(e) => {
            setPassword(e.target.value);
          }}
        />
        {notIncluded > 0 ? (
          <label className="flex items-start gap-2.5 rounded-menu border border-line bg-canvas px-3.5 py-3 text-body">
            <input
              type="checkbox"
              className="mt-1 size-4 accent-brand"
              checked={acknowledged}
              onChange={(e) => {
                setAcknowledged(e.target.checked);
              }}
            />
            <span>
              I understand that {plural(notIncluded, 'change', 'changes')} on this device will not
              be in the file.
            </span>
          </label>
        ) : null}
        {error ? <Notice>{error}</Notice> : null}
        <Button
          variant="primary"
          type="submit"
          className="self-end"
          aria-disabled={busy || undefined}
        >
          Download verified copy
        </Button>
      </form>
    </>
  );
}

/**
 * Security → after a server restore: an offline export of this device's verified copy, then,
 * only if the user asks for it, erasing this device to start over (backup-restore.md §3.12).
 */
export function RestoreHelpSection({
  client,
  status,
  sessionProblem,
  onErased,
}: {
  client: VaultClient;
  status: SyncStatus;
  sessionProblem?: string;
  onErased: () => void;
}) {
  const [local, setLocal] = useState<LocalStateView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmText, setConfirmText] = useState('');
  const [withoutExport, setWithoutExport] = useState(false);

  const refresh = useCallback(() => {
    void client.call('localState').then(setLocal, () => {
      setLocal(null);
    });
  }, [client]);
  useEffect(refresh, [refresh, status]);

  const startOver = () => {
    if (busy || !local || confirmText !== 'erase this device') return;
    setBusy(true);
    setError(null);
    client
      .call('startOver', {
        confirm: 'erase-this-device',
        pendingSeen: local.pending,
        conflictsSeen: local.conflicts,
        ...(withoutExport ? { withoutExport: true } : {}),
      })
      .then(onErased, (e: unknown) => {
        setError(errorText(e));
        refresh();
      })
      .finally(() => {
        setBusy(false);
      });
  };

  return (
    <section className="flex flex-col gap-4" aria-labelledby="restore-help-heading">
      <h3 id="restore-help-heading" className="text-title font-bold">
        After a server restore
      </h3>
      <Notice tone="caution">{restoreExplanation(status, sessionProblem)}</Notice>
      {local ? (
        <p className="text-body text-ink-muted">
          On this device: {plural(local.snapshot.items, 'item', 'items')} in the last verified copy
          {local.snapshot.asOfMs
            ? ` (as of ${new Date(local.snapshot.asOfMs).toLocaleString()})`
            : ''}
          , {plural(local.pending, 'change', 'changes')} waiting to sync,{' '}
          {plural(local.conflicts, 'conflict', 'conflicts')}.
        </p>
      ) : null}

      <h4 className="text-body font-semibold">1. Keep an encrypted copy</h4>
      <p className="text-body text-ink-muted">
        This works without the server. The file holds the last copy of your vault that this device
        verified, in the usual encrypted export format; only the Recovery Kit you type here opens
        it. Changes waiting to sync and unresolved conflicts were never verified, so they are not in
        the file: they stay on this device until you erase it.
      </p>
      <LocalExportForm client={client} local={local} onSaved={refresh} />

      <h4 className="text-body font-semibold">2. Start over on this device (optional)</h4>
      <p className="text-body text-ink-muted">
        Ruvee never erases this device by itself. Erasing it deletes its local copy, including any
        changes not in an export, so that it can log in to the server again as a new device. Do this
        only after you have the copy you need.
      </p>
      {local && !local.exported ? (
        <label className="flex items-start gap-2.5 rounded-menu border border-line bg-canvas px-3.5 py-3 text-body">
          <input
            type="checkbox"
            className="mt-1 size-4 accent-brand"
            checked={withoutExport}
            onChange={(e) => {
              setWithoutExport(e.target.checked);
            }}
          />
          <span>Erase without an export of this device&apos;s current state.</span>
        </label>
      ) : null}
      <TextField
        label='Type "erase this device" to confirm'
        value={confirmText}
        autoComplete="off"
        spellCheck={false}
        onChange={(e) => {
          setConfirmText(e.target.value);
        }}
      />
      {error ? <Notice>{error}</Notice> : null}
      <Button
        className="self-end"
        aria-disabled={busy || confirmText !== 'erase this device' || undefined}
        onClick={startOver}
      >
        Erase this device
      </Button>
    </section>
  );
}
