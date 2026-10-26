import type { SyncStatus } from '@ruvee/vault';
import { Button } from '../ui/button';
import { cx } from '../ui/cx';
import { AlertIcon, CloudIcon, RefreshIcon } from '../ui/icons';
import { restoreExplanation } from './restore-help';
import { relativeTime } from './view-model';

function describe(status: SyncStatus): {
  title: string;
  detail: string;
  tone: 'ok' | 'muted' | 'warn';
} {
  const last = status.lastSyncedAtMs
    ? `Checked ${relativeTime(status.lastSyncedAtMs)}`
    : 'Not checked yet';
  const waiting =
    status.pendingCount === 1
      ? '1 change waiting to sync'
      : `${status.pendingCount} changes waiting to sync`;
  switch (status.state) {
    case 'synced':
      return { title: 'Synced', detail: `${last}. Encrypted on this device.`, tone: 'ok' };
    case 'syncing':
      return { title: 'Syncing…', detail: last, tone: 'muted' };
    case 'pending':
      return { title: 'Sync pending', detail: waiting, tone: 'muted' };
    case 'offline':
      return {
        title: 'Offline',
        detail:
          status.pendingCount > 0 ? `${waiting}. Your local copy works.` : 'Your local copy works.',
        tone: 'muted',
      };
    case 'session_expired':
      return { title: 'Signed out', detail: 'Lock and unlock to sign in again.', tone: 'warn' };
    case 'integrity_error':
      return {
        title: 'Sync paused',
        detail:
          status.serverRestoredAtMs !== undefined
            ? restoreExplanation(status)
            : "The server's copy didn't pass Ruvee's checks, so nothing from it was applied. Your local copy is unchanged and read-only.",
        tone: 'warn',
      };
    case 'maintenance':
      return { title: 'Server unavailable', detail: restoreExplanation(status), tone: 'warn' };
    case 'reopening':
      return { title: 'Waiting to be reopened', detail: restoreExplanation(status), tone: 'warn' };
  }
}

/** The sidebar status box. "Synced" is shown only after the server state was verified. */
export function SyncPanel({ status, onSync }: { status: SyncStatus; onSync: () => void }) {
  const d = describe(status);
  const Icon = d.tone === 'warn' ? AlertIcon : CloudIcon;
  return (
    <div
      role="status"
      aria-live="polite"
      className={cx(
        'mt-2 flex items-start gap-2.5 rounded-row border px-3 py-2.5',
        d.tone === 'warn' ? 'border-caution-line bg-caution-wash' : 'border-line-menu bg-surface',
      )}
    >
      <Icon
        size={18}
        className={cx(
          'mt-px shrink-0',
          d.tone === 'ok'
            ? 'text-brand'
            : d.tone === 'warn'
              ? 'text-caution-strong'
              : 'text-ink-muted',
        )}
      />
      <div className="flex min-w-0 flex-1 flex-col gap-px">
        <span className="text-small font-semibold text-ink-secondary">{d.title}</span>
        <span className="text-caption text-ink-muted">{d.detail}</span>
        {status.lastChange && !status.lastChange.byThisDevice ? (
          <span className="text-caption text-ink-muted">
            Last change {relativeTime(status.lastChange.atMs)} on another device
          </span>
        ) : null}
      </div>
      {status.state === 'integrity_error' || status.state === 'syncing' ? null : (
        <Button
          variant="ghost"
          size="sm"
          iconOnly
          aria-label="Sync now"
          icon={<RefreshIcon size={16} />}
          onClick={onSync}
        />
      )}
    </div>
  );
}
