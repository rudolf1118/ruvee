'use client';

import { type SubmitEvent, useState } from 'react';
import {
  checkMasterPassword,
  MASTER_PASSWORD_MIN_CHARACTERS,
  type Strength,
} from '@/vault/password-policy';
import type { RecoveryKitView, UnlockedVault } from '@/vault/protocol';
import { VaultClientError, type VaultClient } from '@/vault/client';
import { Button } from '../ui/button';
import { cx } from '../ui/cx';
import { CheckIcon } from '../ui/icons';
import { AuthCard, DevelopmentNotice, RecoveryWarning } from './auth-layout';
import { Notice, PasswordField, TextField } from './fields';
import { messageFor } from './messages';

type Step = 'account' | 'password' | 'kit' | 'verify';

const STEPS: readonly { id: Step; label: string }[] = [
  { id: 'account', label: 'Account' },
  { id: 'password', label: 'Master password' },
  { id: 'kit', label: 'Recovery Kit' },
];

function Steps({ current }: { current: Step }) {
  const index = STEPS.findIndex((s) => s.id === (current === 'verify' ? 'kit' : current));
  return (
    <ol aria-label="Setup steps" className="flex flex-wrap gap-2 text-small">
      {STEPS.map((step, i) => (
        <li
          key={step.id}
          aria-current={i === index ? 'step' : undefined}
          className={cx(
            'flex items-center gap-1.5 rounded-full px-2.5 py-1',
            i === index ? 'bg-brand-soft font-semibold text-brand-strong' : 'text-ink-muted',
          )}
        >
          <span
            aria-hidden="true"
            className={cx(
              'flex size-5 items-center justify-center rounded-full text-caption',
              i < index ? 'bg-brand text-white' : i === index ? 'bg-brand text-white' : 'bg-subtle',
            )}
          >
            {i < index ? <CheckIcon size={12} /> : i + 1}
          </span>
          {step.label}
        </li>
      ))}
    </ol>
  );
}

const STRENGTH_TEXT: Record<Strength, string> = {
  too_short: 'Too short',
  weak: 'Weak: add more words',
  fair: 'Fair',
  strong: 'Strong',
};

export function SetupFlow({
  client,
  onCancel,
  onDone,
}: {
  client: VaultClient;
  onCancel: () => void;
  onDone: (vault: UnlockedVault) => void;
}) {
  const [step, setStep] = useState<Step>('account');
  const [token, setToken] = useState('');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [understood, setUnderstood] = useState(false);
  const [kit, setKit] = useState<RecoveryKitView | null>(null);
  const [typedKey, setTypedKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [touched, setTouched] = useState(false);

  const check = checkMasterPassword(password);
  const mismatch = confirm !== '' && confirm !== password;

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

  const submitPassword = (event: SubmitEvent) => {
    event.preventDefault();
    setTouched(true);
    if (!check.ok || confirm !== password || !understood) return;
    void run(async () => {
      const view = await client.call('setupBegin', { bootstrapToken: token, username, password });
      setKit(view);
      // The typed password is no longer needed in the page once the worker has it.
      setPassword('');
      setConfirm('');
      setStep('kit');
    });
  };

  if (step === 'account')
    return (
      <AuthCard title="Create your account" badge={<Steps current={step} />}>
        <p className="text-body text-ink-muted">
          This server holds one account. To create it, you need the setup token from the server
          owner&apos;s terminal (
          <code className="font-mono text-small">ruvee-admin bootstrap-token</code>).
        </p>
        <form
          className="flex flex-col gap-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (token.trim() && username.trim()) setStep('password');
          }}
        >
          <TextField
            label="Setup token"
            value={token}
            onChange={(e) => {
              setToken(e.target.value);
            }}
            autoComplete="off"
            spellCheck={false}
            inputClassName="font-mono"
            required
          />
          <TextField
            label="Username"
            value={username}
            onChange={(e) => {
              setUsername(e.target.value);
            }}
            autoComplete="username"
            hint="Letters, digits, dots, dashes or underscores. Not case-sensitive."
            required
          />
          <div className="flex justify-between gap-2">
            <Button variant="ghost" onClick={onCancel}>
              Back
            </Button>
            <Button variant="primary" type="submit">
              Continue
            </Button>
          </div>
        </form>
      </AuthCard>
    );

  if (step === 'password')
    return (
      <AuthCard
        title="Create your master password"
        wide
        badge={<Steps current={step} />}
        aside={
          <div className="flex flex-col gap-3 text-body text-ink-secondary">
            <h2 className="text-body-lg font-bold text-ink">Why this password matters</h2>
            <p>
              Your master password, together with a secret key kept on your enrolled devices,
              unlocks your vault. It never leaves this device in a form the server can use.
            </p>
            <p>
              <strong>No one can reset it for you.</strong> Next you&apos;ll get a Recovery Kit:
              keep it safe, because it is the only way back in if you forget this password.
            </p>
          </div>
        }
      >
        <p className="text-body text-ink-muted">
          This is the one password you&apos;ll need to remember.
        </p>
        <form className="flex flex-col gap-4" onSubmit={submitPassword} noValidate>
          <PasswordField
            label="Master password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
            }}
            autoComplete="new-password"
            error={touched && !check.ok ? messageFor('invalid_password') : undefined}
            hint={
              <span aria-live="polite">
                At least {MASTER_PASSWORD_MIN_CHARACTERS} characters ({check.characters} so far)
                {password ? ` · ${STRENGTH_TEXT[check.strength]}` : ''}. Tip: four or more random
                words are long and easy to remember.
              </span>
            }
          />
          <PasswordField
            label="Type it again"
            value={confirm}
            onChange={(e) => {
              setConfirm(e.target.value);
            }}
            autoComplete="new-password"
            error={
              (touched || mismatch) && confirm !== password
                ? "The passwords don't match."
                : undefined
            }
          />
          <label className="flex items-start gap-2.5 rounded-menu border border-line bg-canvas px-3.5 py-3 text-body">
            <input
              type="checkbox"
              className="mt-1 size-4 accent-brand"
              checked={understood}
              onChange={(e) => {
                setUnderstood(e.target.checked);
              }}
            />
            <span>
              I understand that Ruvee can&apos;t recover my master password, and that without it and
              an enrolled device, or my Recovery Kit, my data is permanently lost.
            </span>
          </label>
          {touched && !understood ? (
            <Notice tone="caution">Confirm that you understand to continue.</Notice>
          ) : null}
          <DevelopmentNotice />
          {error ? <Notice>{error}</Notice> : null}
          <div className="flex justify-between gap-2">
            <Button
              variant="ghost"
              onClick={() => {
                setStep('account');
              }}
            >
              Back
            </Button>
            <Button variant="primary" type="submit" aria-disabled={busy || undefined}>
              {busy ? 'Creating keys…' : 'Continue'}
            </Button>
          </div>
        </form>
      </AuthCard>
    );

  if (step === 'kit' && kit)
    return (
      <AuthCard title="Save your Recovery Kit" badge={<Steps current={step} />}>
        <RecoveryWarning />
        <div className="flex flex-col gap-3 rounded-menu border border-line bg-canvas p-4">
          <div className="text-label font-semibold text-ink-muted">Recovery Key</div>
          <div data-testid="recovery-key" className="font-mono text-body-lg break-words select-all">
            {kit.recoveryKey}
          </div>
          <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-small">
            <dt className="text-ink-muted">Username</dt>
            <dd>{kit.username}</dd>
            <dt className="text-ink-muted">Server</dt>
            <dd className="break-all">{kit.serverOrigin}</dd>
            <dt className="text-ink-muted">Created</dt>
            <dd>{new Date(kit.createdAtMs).toLocaleString()}</dd>
            <dt className="text-ink-muted">Kit id</dt>
            <dd className="font-mono">{kit.recoveryKeyIdShort}</dd>
          </dl>
        </div>
        <p className="text-small text-ink-muted">
          Write it down or print this page, and keep it somewhere safe, like where you keep your
          passport. Ruvee never stores it and can&apos;t show it again.
        </p>
        <div className="flex flex-wrap justify-between gap-2">
          <Button
            onClick={() => {
              window.print();
            }}
          >
            Print
          </Button>
          <Button
            variant="primary"
            onClick={() => {
              setStep('verify');
            }}
          >
            I&apos;ve saved it
          </Button>
        </div>
      </AuthCard>
    );

  return (
    <AuthCard title="Check your Recovery Kit" badge={<Steps current={step} />}>
      <p className="text-body text-ink-muted">
        Type the Recovery Key from your kit. Setup finishes only when it matches, so you know your
        copy works.
      </p>
      <form
        className="flex flex-col gap-4"
        onSubmit={(event) => {
          event.preventDefault();
          void run(async () => {
            await client.call('setupVerifyKit', { recoveryKey: typedKey });
            const vault = await client.call('setupFinish');
            setKit(null);
            onDone(vault);
          });
        }}
      >
        <TextField
          label="Recovery Key"
          value={typedKey}
          onChange={(e) => {
            setTypedKey(e.target.value);
          }}
          autoComplete="off"
          spellCheck={false}
          placeholder="RK1-…"
          inputClassName="font-mono"
        />
        {error ? <Notice>{error}</Notice> : null}
        <div className="flex justify-between gap-2">
          <Button
            variant="ghost"
            onClick={() => {
              setStep('kit');
            }}
          >
            Show the kit again
          </Button>
          <Button variant="primary" type="submit" aria-disabled={busy || undefined}>
            {busy ? 'Finishing…' : 'Finish setup'}
          </Button>
        </div>
      </form>
    </AuthCard>
  );
}
