'use client';

import type { MigrationReport, SyncStatus } from '@ruvee/vault';
import { useCallback, useEffect, useState } from 'react';
import type { VaultClient } from '@/vault/client';
import { Notice } from './fields';
import { LocalExportForm, plural } from './restore-help';

const CHANGE_WORDS = { created: 'new', edited: 'edited', deleted: 'deleted' } as const;

/**
 * Security → move to a new account (docs/security/device-proof.md §9,
 * docs/guides/legacy-account-migration.md). An account from before device keys can never get a
 * trusted account verification key, so its data moves by export and import. This device's copy
 * is only read: nothing here erases or changes it, and every change no export can hold is named.
 */
export function MigrationSection({ client, status }: { client: VaultClient; status: SyncStatus }) {
  const [report, setReport] = useState<MigrationReport | null>(null);

  const refresh = useCallback(() => {
    void client.call('migrationReport').then(setReport, () => {
      setReport(null);
    });
  }, [client]);
  useEffect(refresh, [refresh, status]);

  const local = report
    ? {
        snapshot: report.snapshot,
        pending: report.changes.length,
        conflicts: report.conflicts.length,
        exported: report.exported,
      }
    : null;
  const leftBehind = report ? report.changes.length + report.conflicts.length : 0;

  return (
    <section className="flex flex-col gap-4" aria-labelledby="migration-heading">
      <h3 id="migration-heading" className="text-title font-bold">
        Move to a new account
      </h3>
      <Notice tone="caution">
        This account was created before device keys. The server can&apos;t verify a new device key
        for it, so this device won&apos;t sync and can&apos;t be enrolled again. Your local copy
        stays here, unchanged, and keeps working offline. To keep using Ruvee, move your items to a
        new account on a new installation; the steps are in the migration guide.
      </Notice>
      {report ? (
        <p className="text-body text-ink-muted">
          On this device: {plural(report.snapshot.items, 'item', 'items')} in the last verified copy
          {report.snapshot.asOfMs
            ? ` (as of ${new Date(report.snapshot.asOfMs).toLocaleString()})`
            : ''}
          , {plural(report.changes.length, 'change', 'changes')} waiting to sync,{' '}
          {plural(report.conflicts.length, 'conflict', 'conflicts')}.
        </p>
      ) : null}

      <h4 className="text-body font-semibold">1. Download the verified copy</h4>
      <p className="text-body text-ink-muted">
        This works without the server. Import the file into the new account; only the Recovery Kit
        you type here opens it.
      </p>
      <LocalExportForm client={client} local={local} onSaved={refresh} />

      <h4 className="text-body font-semibold">2. Copy what the file can&apos;t hold</h4>
      {leftBehind === 0 ? (
        <p className="text-body text-ink-muted">
          Nothing: this device has no changes waiting to sync and no conflicts.
        </p>
      ) : (
        <>
          <Notice tone="caution">
            The move is not complete until you have copied each item below into the new account by
            hand. Open it here, then add or change it there. The file has its last verified version,
            or nothing for a new one.
          </Notice>
          <ul className="flex flex-col gap-1.5 text-body" aria-label="Not in the export">
            {report?.changes.map((c) => (
              <li key={`change-${c.id}`}>
                {c.title} <span className="text-ink-muted">({CHANGE_WORDS[c.change]})</span>
              </li>
            ))}
            {report?.conflicts.map((c) => (
              <li key={`conflict-${c.id}`}>
                {c.title}{' '}
                <span className="text-ink-muted">
                  (conflict{c.localDeleted ? ': deleted on this device' : ''})
                </span>
              </li>
            ))}
          </ul>
        </>
      )}

      <h4 className="text-body font-semibold">3. Keep this browser until you have checked</h4>
      <p className="text-body text-ink-muted">
        Leave this browser&apos;s copy in place until the new account opens on its own device, shows
        every item, and its Recovery Kit works. Ruvee never erases it by itself.
      </p>
    </section>
  );
}
