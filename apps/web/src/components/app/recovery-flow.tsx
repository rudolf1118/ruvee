'use client';

import { type SubmitEvent, useState } from 'react';
import { checkMasterPassword, MASTER_PASSWORD_MIN_CHARACTERS } from '@ruvee/vault';
import type { RecoveryKitView, UnlockedVault } from '@ruvee/vault';
import { VaultClientError, type VaultClient } from '@/vault/client';
import { Button } from '../ui/button';
import { AuthCard, DevelopmentNotice, RecoveryWarning } from './auth-layout';
import { Notice, PasswordField, TextField } from './fields';
import { messageFor } from './messages';
import { RecoveryKitPanel } from './recovery-kit';

type Step = 'kit' | 'password' | 'new-kit' | 'verify';

/**
 * Recovery with the Recovery Kit (account-recovery.md §3): the kit proves possession of the
 * Recovery Key, the user sets a master password, and a new Recovery Kit replaces the used one.
 * Used for a forgotten password and for a device that has none of the account's keys.
 *
 * The same steps reopen a restored server (backup-restore.md §3.13): `reopen-kit` adds the
 * reopening code to the kit step (a browser with no data); `reopen-password` asks, on this
 * unlocked device, for the code and the master password as of the backup. Both end with a new
 * password and a new kit. The code lives only in this component's state.
 */
export type RecoveryMode = 'recovery' | 'reopen-kit' | 'reopen-password';

export function RecoveryFlow({
  client,
  initialUsername,
  mode = 'recovery',
  onCancel,
  onDone,
}: {
  client: VaultClient;
  initialUsername?: string;
  mode?: RecoveryMode;
  onCancel: () => void;
  onDone: (vault: UnlockedVault) => void;
}) {
  const reopening = mode !== 'recovery';
  const [reopenCode, setReopenCode] = useState('');
  const [oldPassword, setOldPassword] = useState('');
  const [step, setStep] = useState<Step>('kit');
  const [username, setUsername] = useState(initialUsername ?? '');
  const [recoveryKey, setRecoveryKey] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [newKit, setNewKit] = useState<RecoveryKitView | null>(null);
  const [typedKey, setTypedKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // This browser holds another account's vault (review R6): erased only if the user says so.
  const [otherVault, setOtherVault] = useState(false);
  const [replaceConfirmed, setReplaceConfirmed] = useState(false);
  const check = checkMasterPassword(password);

  const run = (task: () => Promise<void>) => (event: SubmitEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    task()
      .catch((e: unknown) => {
        if (e instanceof VaultClientError && e.code === 'local_data_other_account') {
          setOtherVault(true);
          return;
        }
        setError(
          e instanceof VaultClientError
            ? messageFor(e.code, e.retryAfterSeconds)
            : messageFor('internal'),
        );
      })
      .finally(() => {
        setBusy(false);
      });
  };

  const codeField = (
    <TextField
      label="Reopening code"
      value={reopenCode}
      autoComplete="off"
      spellCheck={false}
      placeholder="RC1-…"
      inputClassName="font-mono"
      hint="Printed by the server's owner with ruvee-admin on the server. Never sent anywhere else."
      onChange={(e) => {
        setReopenCode(e.target.value.trim());
      }}
    />
  );

  if (step === 'kit' && mode === 'reopen-password')
    return (
      <AuthCard title="Reopen the restored server">
        <p className="text-body text-ink-muted">
          The server was restored from a backup and waits for you. Enter the code from the server
          and the master password you used <strong>at the time of the backup</strong>. This device
          keeps all its items. Afterwards you choose a new master password and get a new Recovery
          Kit, and the old ones stop working.
        </p>
        <form
          className="flex flex-col gap-4"
          onSubmit={run(async () => {
            await client.call('reopenBegin', { reopenCode, password: oldPassword });
            setReopenCode('');
            setOldPassword('');
            setStep('password');
          })}
        >
          {codeField}
          <PasswordField
            label="Master password at the time of the backup"
            value={oldPassword}
            autoComplete="current-password"
            onChange={(e) => {
              setOldPassword(e.target.value);
            }}
          />
          {error ? <Notice>{error}</Notice> : null}
          <div className="flex justify-between gap-2">
            <Button variant="ghost" onClick={onCancel}>
              Back
            </Button>
            <Button variant="primary" type="submit" aria-disabled={busy || undefined}>
              {busy ? 'Checking…' : 'Continue'}
            </Button>
          </div>
        </form>
      </AuthCard>
    );

  if (step === 'kit')
    return (
      <AuthCard title={reopening ? 'Reopen the restored server' : 'Use your Recovery Kit'}>
        <p className="text-body text-ink-muted">
          {reopening
            ? 'The server was restored from a backup and waits for you. Enter the code from the server, and the Recovery Kit you had at the time of the backup. Afterwards you choose a new master password and get a new kit, and the old ones stop working.'
            : 'Your Recovery Kit lets you set a new master password and open your vault on this device. Afterwards you get a new kit, and the one you use now stops working.'}
        </p>
        <form
          className="flex flex-col gap-4"
          onSubmit={run(async () => {
            await client.call(
              'recoveryBegin',
              reopening
                ? { username, recoveryKey, reopenCode }
                : {
                    username,
                    recoveryKey,
                    ...(otherVault && replaceConfirmed ? { replaceLocalData: true } : {}),
                  },
            );
            setRecoveryKey('');
            setReopenCode('');
            setStep('password');
          })}
        >
          {reopening ? codeField : null}
          <TextField
            label="Username"
            value={username}
            autoComplete="username"
            onChange={(e) => {
              setUsername(e.target.value);
            }}
          />
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
          <p className="text-small text-ink-muted">
            Other devices on your account are told that the Recovery Kit was used, and they have to
            log in again with the new password.
          </p>
          {otherVault ? (
            <>
              <Notice tone="caution">{messageFor('local_data_other_account')}</Notice>
              <label className="flex items-start gap-2.5 rounded-menu border border-line bg-canvas px-3.5 py-3 text-body">
                <input
                  type="checkbox"
                  className="mt-1 size-4 accent-brand"
                  checked={replaceConfirmed}
                  onChange={(e) => {
                    setReplaceConfirmed(e.target.checked);
                  }}
                />
                <span>
                  Erase the other vault from this browser, including any changes it has not
                  uploaded, and recover my account here.
                </span>
              </label>
            </>
          ) : null}
          {error ? <Notice>{error}</Notice> : null}
          <div className="flex justify-between gap-2">
            <Button variant="ghost" onClick={onCancel}>
              Back
            </Button>
            <Button variant="primary" type="submit" aria-disabled={busy || undefined}>
              {busy ? 'Checking…' : 'Continue'}
            </Button>
          </div>
        </form>
      </AuthCard>
    );

  if (step === 'password')
    return (
      <AuthCard title="Set your master password">
        <p className="text-body text-ink-muted">
          {reopening
            ? 'Choose a new master password. The one from the time of the backup stops working when you finish.'
            : 'Your Recovery Key opened your vault. Choose the master password you will use from now on; it can be the old one.'}
        </p>
        <form
          className="flex flex-col gap-4"
          noValidate
          onSubmit={run(async () => {
            if (!check.ok) throw new VaultClientError('invalid_password');
            if (password !== confirm) {
              setError("The passwords don't match.");
              return;
            }
            const kit = await client.call('recoverySetPassword', { password });
            setPassword('');
            setConfirm('');
            setNewKit(kit);
            setStep('new-kit');
          })}
        >
          <PasswordField
            label="New master password"
            value={password}
            autoComplete="new-password"
            hint={`At least ${MASTER_PASSWORD_MIN_CHARACTERS} characters (${check.characters} so far).`}
            onChange={(e) => {
              setPassword(e.target.value);
            }}
          />
          <PasswordField
            label="Type it again"
            value={confirm}
            autoComplete="new-password"
            onChange={(e) => {
              setConfirm(e.target.value);
            }}
          />
          <DevelopmentNotice />
          {error ? <Notice>{error}</Notice> : null}
          <Button
            variant="primary"
            type="submit"
            className="self-end"
            aria-disabled={busy || undefined}
          >
            {busy ? 'Creating keys…' : 'Continue'}
          </Button>
        </form>
      </AuthCard>
    );

  if (step === 'new-kit' && newKit)
    return (
      <AuthCard title="Save your new Recovery Kit">
        <Notice tone="caution">
          Your old Recovery Kit stops working when you finish. Destroy it and keep only this one.
        </Notice>
        <RecoveryWarning />
        <RecoveryKitPanel
          kit={newKit}
          onSaved={() => {
            setStep('verify');
          }}
        />
      </AuthCard>
    );

  return (
    <AuthCard title="Check your new Recovery Kit">
      <p className="text-body text-ink-muted">
        Type the new Recovery Key. Recovery finishes only when it matches.
      </p>
      <form
        className="flex flex-col gap-4"
        onSubmit={run(async () => {
          await client.call('recoveryVerifyKit', { recoveryKey: typedKey });
          const vault = await client.call('recoveryFinish');
          setNewKit(null);
          onDone(vault);
        })}
      >
        <TextField
          label="Recovery Key"
          value={typedKey}
          autoComplete="off"
          spellCheck={false}
          placeholder="RK1-…"
          inputClassName="font-mono"
          onChange={(e) => {
            setTypedKey(e.target.value);
          }}
        />
        {error ? <Notice>{error}</Notice> : null}
        <div className="flex justify-between gap-2">
          <Button
            variant="ghost"
            onClick={() => {
              setStep('new-kit');
            }}
          >
            Show the kit again
          </Button>
          <Button variant="primary" type="submit" aria-disabled={busy || undefined}>
            {busy ? 'Finishing…' : reopening ? 'Finish and reopen' : 'Finish recovery'}
          </Button>
        </div>
      </form>
    </AuthCard>
  );
}
