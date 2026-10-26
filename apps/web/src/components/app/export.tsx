'use client';

import type { ExportView, ItemDetail } from '@ruvee/vault';
import { type SubmitEvent, useState } from 'react';
import { VaultClientError, type VaultClient } from '@/vault/client';
import { Button } from '../ui/button';
import { AuthCard } from './auth-layout';
import { Notice, PasswordField, TextField } from './fields';
import { messageFor } from './messages';

function errorText(e: unknown): string {
  return e instanceof VaultClientError
    ? messageFor(e.code, e.retryAfterSeconds)
    : messageFor('internal');
}

/** Hands ciphertext to the browser as a file. Nothing is uploaded (backup-restore.md §4.7). */
function download(fileName: string, text: string) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/vnd.ruvee.export+json' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = fileName;
  link.click();
  setTimeout(() => {
    URL.revokeObjectURL(url);
  }, 0);
}

/** Security → encrypted export (backup-restore.md §4, D-13 option A). */
export function ExportSection({ client }: { client: VaultClient }) {
  const [recoveryKey, setRecoveryKey] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);

  const submit = (event: SubmitEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    setDone(null);
    client
      .call('exportVault', { password, recoveryKey })
      .then(
        (file) => {
          download(file.fileName, file.text);
          setPassword('');
          setRecoveryKey('');
          setDone(file.fileName);
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
    <section className="flex flex-col gap-4" aria-labelledby="export-heading">
      <h3 id="export-heading" className="text-title font-bold">
        Encrypted export
      </h3>
      <p className="text-body text-ink-muted">
        A file with your vault as it is now, still encrypted, that opens without this server or any
        of your devices. Only the Recovery Kit you type here opens it: if you lose that kit, the
        file can never be opened. The file is made on this device and is never uploaded.
      </p>
      {done ? (
        <Notice tone="brand">
          Saved as {done}. Anyone who has this file and the Recovery Kit you typed can read your
          vault as it is today, so don&apos;t keep the two together.
        </Notice>
      ) : null}
      <form className="flex flex-col gap-4" onSubmit={submit}>
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
          label="Master password"
          value={password}
          autoComplete="current-password"
          onChange={(e) => {
            setPassword(e.target.value);
          }}
        />
        {error ? <Notice>{error}</Notice> : null}
        <Button
          variant="primary"
          type="submit"
          className="self-end"
          aria-disabled={busy || undefined}
        >
          {busy ? 'Making the file…' : 'Download encrypted export'}
        </Button>
      </form>
    </section>
  );
}

/**
 * Opening an export with no account (backup-restore.md §4.4): everything is checked before
 * anything is shown, and the contents stay in the worker's memory until closed.
 */
export function ExportViewer({ client, onClose }: { client: VaultClient; onClose: () => void }) {
  const [text, setText] = useState<string | null>(null);
  const [fileName, setFileName] = useState('');
  const [recoveryKey, setRecoveryKey] = useState('');
  const [view, setView] = useState<ExportView | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const close = () => {
    void client.call('exportClose').finally(onClose);
  };

  const submit = (event: SubmitEvent) => {
    event.preventDefault();
    if (busy || text === null) return;
    setBusy(true);
    setError(null);
    client
      .call('exportOpen', { text, recoveryKey })
      .then(
        (opened) => {
          setRecoveryKey('');
          setView(opened);
        },
        (e: unknown) => {
          setError(
            e instanceof VaultClientError && e.code === 'kit_mismatch'
              ? "This Recovery Key doesn't open this export. Use the kit that was typed when it was made."
              : errorText(e),
          );
        },
      )
      .finally(() => {
        setBusy(false);
      });
  };

  if (view)
    return (
      <AuthCard title="Encrypted export">
        <Notice tone="caution">
          This is your vault as of {new Date(view.asOfMs).toLocaleString()}, last changed by the
          device with ID {view.authorDeviceId.slice(0, 8)}. Ruvee can&apos;t tell whether a newer
          copy exists. Nothing here is saved on this device.
        </Notice>
        {view.items.length === 0 ? <p className="text-body text-ink-muted">No items.</p> : null}
        <ul className="flex flex-col divide-y divide-line rounded-menu border border-line">
          {view.items.map((item) => (
            <ExportedItem key={item.id} client={client} item={item} />
          ))}
        </ul>
        <Button variant="primary" className="self-start" onClick={close}>
          Close
        </Button>
      </AuthCard>
    );

  return (
    <AuthCard title="Open an encrypted export">
      <p className="text-body text-ink-muted">
        Choose an export file and type the Recovery Key it was made with. It opens on this device
        only, without an account, and is not uploaded.
      </p>
      <form className="flex flex-col gap-4" onSubmit={submit}>
        <label className="flex flex-col gap-1.5 text-small font-semibold">
          Export file
          <input
            type="file"
            accept=".ruvee,application/vnd.ruvee.export+json"
            className="text-body font-normal"
            onChange={(e) => {
              const file = e.target.files?.[0];
              setError(null);
              setText(null);
              setFileName(file?.name ?? '');
              if (file)
                file.text().then(setText, () => {
                  setError(messageFor('invalid_export'));
                });
            }}
          />
        </label>
        <TextField
          label="Recovery Key"
          value={recoveryKey}
          autoComplete="off"
          spellCheck={false}
          placeholder="RK1-…"
          inputClassName="font-mono"
          onChange={(e) => {
            setRecoveryKey(e.target.value);
          }}
        />
        {error ? <Notice>{error}</Notice> : null}
        <div className="flex justify-between gap-2">
          <Button variant="ghost" onClick={close}>
            Back
          </Button>
          <Button
            variant="primary"
            type="submit"
            aria-disabled={busy || text === null || undefined}
          >
            {busy ? 'Checking…' : fileName ? `Open ${fileName}` : 'Open'}
          </Button>
        </div>
      </form>
    </AuthCard>
  );
}

function ExportedItem({ client, item }: { client: VaultClient; item: ItemDetail }) {
  const [shown, setShown] = useState<string | null>(null);
  return (
    <li className="flex flex-col gap-1 px-4 py-3" aria-label={item.title}>
      <span className="text-body font-semibold">{item.title}</span>
      {item.username ? <span className="text-small">{item.username}</span> : null}
      {item.urls.length > 0 ? (
        <span className="text-small text-ink-muted">{item.urls.join(', ')}</span>
      ) : null}
      {item.noteText ? (
        <span className="text-small whitespace-pre-wrap">{item.noteText}</span>
      ) : null}
      {item.hasPassword ? (
        <div className="flex items-center gap-2">
          <span className="font-mono text-small">{shown ?? '••••••••'}</span>
          <Button
            size="sm"
            variant="ghost"
            onClick={() => {
              if (shown !== null) {
                setShown(null);
                return;
              }
              void client.call('exportSecret', { id: item.id }).then(setShown);
            }}
          >
            {shown === null ? 'Reveal' : 'Hide'}
          </Button>
        </div>
      ) : null}
    </li>
  );
}
