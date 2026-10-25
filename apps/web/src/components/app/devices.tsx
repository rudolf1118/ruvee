'use client';

import { type ReactNode, type SubmitEvent, useCallback, useEffect, useState } from 'react';
import { checkMasterPassword, MASTER_PASSWORD_MIN_CHARACTERS } from '@/vault/password-policy';
import type { DeviceView } from '@/vault/protocol';
import { VaultClientError, type VaultClient } from '@/vault/client';
import { Button } from '../ui/button';
import { ChevronLeftIcon, PlusIcon } from '../ui/icons';
import { DevelopmentNotice } from './auth-layout';
import { Notice, PasswordField } from './fields';
import { messageFor } from './messages';
import { PLATFORM_NAMES } from './pairing';
import { relativeTime } from './view-model';

function errorText(e: unknown): string {
  return e instanceof VaultClientError
    ? messageFor(e.code, e.retryAfterSeconds)
    : messageFor('internal');
}

function Panel({
  title,
  onClose,
  children,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
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
        <h2 className="text-heading leading-tight font-bold tracking-tight-title">{title}</h2>
        {children}
      </section>
    </div>
  );
}

const STATUS_TEXT: Record<DeviceView['status'], string> = {
  active: 'Active',
  pending: 'Logged in, not added yet',
  revoked: 'Removed',
};

const ENROLLED_TEXT: Record<NonNullable<DeviceView['enrolledVia']>, string> = {
  bootstrap: 'created the account',
  pairing: 'added with a pairing code',
  recovery: 'added with the Recovery Kit',
};

function deviceName(d: DeviceView): string {
  const name = PLATFORM_NAMES[d.platform] ?? d.platform;
  return name.charAt(0).toUpperCase() + name.slice(1);
}

/**
 * The account's devices and their sessions (device-enrollment §6). Removing a device needs the
 * master password again (step-up, INV-14), and the screen says what removal cannot do.
 */
export function DevicesPanel({
  client,
  onClose,
  onAddDevice,
  onChangePassword,
}: {
  client: VaultClient;
  onClose: () => void;
  onAddDevice: () => void;
  onChangePassword: () => void;
}) {
  const [devices, setDevices] = useState<readonly DeviceView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<DeviceView | null>(null);
  const [revokedLost, setRevokedLost] = useState<{ secretKeyRotated: boolean } | null>(null);

  const load = useCallback(() => {
    client.call('devices').then(
      (next) => {
        setError(null);
        setDevices(next);
      },
      (e: unknown) => {
        setError(errorText(e));
      },
    );
  }, [client]);

  useEffect(load, [load]);

  if (revoking)
    return (
      <Panel title="Remove a device" onClose={onClose}>
        <RevokeForm
          client={client}
          device={revoking}
          onCancel={() => {
            setRevoking(null);
          }}
          onDone={(reason, result) => {
            setRevoking(null);
            setRevokedLost(reason === 'lost' ? result : null);
            load();
          }}
        />
      </Panel>
    );

  return (
    <Panel title="Devices" onClose={onClose}>
      <p className="text-body text-ink-muted">
        Every device that can open your vault holds its own copy of your keys. Add a device with a
        pairing code; remove one you no longer use or have lost.
      </p>
      <Button
        variant="primary"
        className="self-start"
        icon={<PlusIcon size={16} />}
        onClick={onAddDevice}
      >
        Add a device
      </Button>
      {revokedLost ? (
        <Notice tone="caution">
          <div className="flex flex-col gap-2">
            <span>
              {revokedLost.secretKeyRotated
                ? 'The device was removed and your Secret Key was replaced, so a copy of the server data no longer works with the old one. '
                : "The device was removed, but your Secret Key couldn't be replaced. Replace it under Security. "}
              Because the device may be in someone else&apos;s hands, also change your master
              password now, then the important passwords stored in your vault.
            </span>
            <Button size="sm" className="self-start" onClick={onChangePassword}>
              Open Security
            </Button>
          </div>
        </Notice>
      ) : null}
      {error ? (
        <Notice>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span>{error}</span>
            <Button size="sm" onClick={load}>
              Try again
            </Button>
          </div>
        </Notice>
      ) : null}
      {devices === null && !error ? (
        <p className="text-body text-ink-muted" aria-busy="true">
          Loading devices…
        </p>
      ) : null}
      {devices ? (
        <ul className="flex flex-col divide-y divide-line rounded-menu border border-line">
          {devices.map((d) => (
            <li key={d.id} className="flex flex-col gap-2 p-4" aria-label={deviceName(d)}>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-col">
                  <span className="text-body-lg font-semibold">
                    {deviceName(d)}
                    {d.current ? (
                      <span className="ml-2 rounded-control-sm bg-brand-wash px-1.5 py-0.5 text-small font-medium text-ink-secondary">
                        This device
                      </span>
                    ) : null}
                  </span>
                  <span className="text-small text-ink-muted">
                    {STATUS_TEXT[d.status]}
                    {d.enrolledVia ? `, ${ENROLLED_TEXT[d.enrolledVia]}` : ''}
                    {d.status === 'revoked' && d.revokedAtMs !== null
                      ? ` ${relativeTime(d.revokedAtMs)}`
                      : d.lastSeenAtMs !== null
                        ? ` · last seen ${relativeTime(d.lastSeenAtMs)}`
                        : ''}
                    {` · ID ${d.id.slice(0, 8)}`}
                  </span>
                </div>
                {!d.current && d.status !== 'revoked' ? (
                  <Button
                    variant="danger"
                    size="sm"
                    aria-label={`Remove ${deviceName(d)} ${d.id.slice(0, 8)}`}
                    onClick={() => {
                      setRevokedLost(null);
                      setRevoking(d);
                    }}
                  >
                    Remove
                  </Button>
                ) : null}
              </div>
              {d.sessions.length > 0 ? (
                <ul className="flex flex-col gap-1 text-small text-ink-muted">
                  {d.sessions.map((s) => (
                    <li key={s.id} className="flex flex-wrap items-center justify-between gap-2">
                      <span>
                        {s.current ? 'This session' : 'Signed in'} since{' '}
                        {relativeTime(s.createdAtMs)}, last used {relativeTime(s.lastUsedAtMs)}
                      </span>
                      {s.current ? null : (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => {
                            client
                              .call('endSession', { sessionId: s.id })
                              .then(load, (e: unknown) => {
                                setError(errorText(e));
                              });
                          }}
                        >
                          Sign out
                        </Button>
                      )}
                    </li>
                  ))}
                </ul>
              ) : null}
            </li>
          ))}
        </ul>
      ) : null}
    </Panel>
  );
}

function RevokeForm({
  client,
  device,
  onCancel,
  onDone,
}: {
  client: VaultClient;
  device: DeviceView;
  onCancel: () => void;
  onDone: (reason: 'retired' | 'lost', result: { secretKeyRotated: boolean }) => void;
}) {
  const [reason, setReason] = useState<'retired' | 'lost'>('retired');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = (event: SubmitEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    client
      .call('revokeDevice', { deviceId: device.id, reason, password })
      .then(
        (result) => {
          setPassword('');
          onDone(reason, result);
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
    <form className="flex flex-col gap-4" onSubmit={submit}>
      <p className="text-body">
        Remove <strong>{deviceName(device)}</strong> (ID {device.id.slice(0, 8)}),{' '}
        {device.lastSeenAtMs === null
          ? 'which has not been seen yet'
          : `last seen ${relativeTime(device.lastSeenAtMs)}`}
        ?
      </p>
      <fieldset className="flex flex-col gap-2">
        <legend className="mb-1 text-small font-semibold">Why are you removing it?</legend>
        <label className="flex items-start gap-2 text-body">
          <input
            type="radio"
            name="reason"
            className="mt-1"
            checked={reason === 'retired'}
            onChange={() => {
              setReason('retired');
            }}
          />
          <span>I no longer use it, and it is still in my hands</span>
        </label>
        <label className="flex items-start gap-2 text-body">
          <input
            type="radio"
            name="reason"
            className="mt-1"
            checked={reason === 'lost'}
            onChange={() => {
              setReason('lost');
            }}
          />
          <span>It was lost or stolen, or someone else may have used it</span>
        </label>
      </fieldset>
      <Notice tone="caution">
        <div className="flex flex-col gap-1.5">
          <span>
            The device is signed out at once and can no longer sync. When it next connects, Ruvee
            erases its local copy, and changes on it that never synced are lost.
          </span>
          <span>Removing a device does not erase it:</span>
          <ul className="ml-4 list-disc">
            <li>An offline device keeps opening its copy with the password it knows.</li>
            <li>
              A compromised device can ignore the erase. It holds a copy of your keys and every item
              it downloaded, and anything already seen or copied stays exposed.
            </li>
          </ul>
          {reason === 'lost' ? (
            <span>
              Ruvee also replaces your Secret Key, which the lost device holds. Afterwards, change
              your master password and the important passwords stored in your vault.
            </span>
          ) : null}
        </div>
      </Notice>
      <PasswordField
        label="Master password"
        value={password}
        autoComplete="current-password"
        hint="Removing a device needs your master password again."
        onChange={(e) => {
          setPassword(e.target.value);
        }}
      />
      {error ? <Notice>{error}</Notice> : null}
      <div className="flex justify-between gap-2">
        <Button variant="ghost" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="primary" type="submit" aria-disabled={busy || undefined}>
          {busy ? 'Removing…' : 'Remove device'}
        </Button>
      </div>
    </form>
  );
}

/** Master password change (authentication.md §9) and Secret Key replacement (D-24). */
export function SecurityPanel({ client, onClose }: { client: VaultClient; onClose: () => void }) {
  return (
    <Panel title="Security" onClose={onClose}>
      <ChangePasswordSection client={client} onClose={onClose} />
      <hr className="border-line" />
      <SecretKeySection client={client} />
    </Panel>
  );
}

function SecretKeySection({ client }: { client: VaultClient }) {
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  const submit = (event: SubmitEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    client
      .call('rotateSecretKey', { password })
      .then(
        () => {
          setPassword('');
          setDone(true);
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
    <section className="flex flex-col gap-4" aria-labelledby="secret-key-heading">
      <h3 id="secret-key-heading" className="text-title font-bold">
        Secret Key
      </h3>
      {done ? (
        <Notice tone="brand">
          Your Secret Key was replaced. Your other devices switch to the new one the next time they
          unlock while online.
        </Notice>
      ) : (
        <form className="flex flex-col gap-4" onSubmit={submit}>
          <p className="text-body text-ink-muted">
            Every device you added holds your Secret Key. Replace it if you lost a device or think
            one was used by someone else: a later copy of the server&apos;s data then can&apos;t be
            combined with the old key to guess your password. It doesn&apos;t help against a device
            that already opened your vault, and it doesn&apos;t change your master password or
            Recovery Kit.
          </p>
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
            {busy ? 'Replacing…' : 'Replace Secret Key'}
          </Button>
        </form>
      )}
    </section>
  );
}

/** authentication.md §9: a new master password for the same keys; other sessions end. */
function ChangePasswordSection({ client, onClose }: { client: VaultClient; onClose: () => void }) {
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [confirm, setConfirm] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);
  const check = checkMasterPassword(next);

  const submit = (event: SubmitEvent) => {
    event.preventDefault();
    if (busy) return;
    setError(null);
    if (!check.ok) {
      setError(messageFor('invalid_password'));
      return;
    }
    if (next !== confirm) {
      setError("The new passwords don't match.");
      return;
    }
    setBusy(true);
    client
      .call('changePassword', { currentPassword: current, newPassword: next })
      .then(
        () => {
          setCurrent('');
          setNext('');
          setConfirm('');
          setDone(true);
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
    <section className="flex flex-col gap-4" aria-labelledby="password-heading">
      <h3 id="password-heading" className="text-title font-bold">
        Change master password
      </h3>
      {done ? (
        <>
          <Notice tone="brand">
            Your master password was changed. Use the new one from now on, on every device.
          </Notice>
          <Button variant="primary" className="self-start" onClick={onClose}>
            Done
          </Button>
        </>
      ) : (
        <form className="flex flex-col gap-4" noValidate onSubmit={submit}>
          <p className="text-body text-ink-muted">
            Your other devices are signed out and ask for the new password when they next connect. A
            device that stays offline keeps opening its copy with the old password until then.
            Copies of your vault made earlier can still be opened with the old password, so changing
            it doesn&apos;t protect against a device or backup that is already lost.
          </p>
          <PasswordField
            label="Current master password"
            value={current}
            autoComplete="current-password"
            onChange={(e) => {
              setCurrent(e.target.value);
            }}
          />
          <PasswordField
            label="New master password"
            value={next}
            autoComplete="new-password"
            hint={`At least ${MASTER_PASSWORD_MIN_CHARACTERS} characters (${check.characters} so far).`}
            onChange={(e) => {
              setNext(e.target.value);
            }}
          />
          <PasswordField
            label="Type the new password again"
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
            {busy ? 'Changing…' : 'Change password'}
          </Button>
        </form>
      )}
    </section>
  );
}
