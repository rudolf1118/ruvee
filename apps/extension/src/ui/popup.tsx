import type { DevicePhase, PairingJoinStatus, SyncStatus } from '@ruvee/vault';
import { type SubmitEvent, useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import type {
  Candidate,
  Candidates,
  FillOutcome,
  PairingView,
  PendingSave,
  SavePendingResult,
  Status,
} from '../messages';
import {
  call,
  CallError,
  messageFor,
  PAIRING_RESTART_CODES,
  pairingMessageFor,
  stepMessageFor,
} from './client';
import { storedServerOrigin } from './open-web';
import {
  AlertIcon,
  CopyIcon,
  DevTag,
  GlobeIcon,
  Header,
  KeyIcon,
  LockIcon,
  type LockState,
  OpenRuvee,
  SettingsIcon,
  StateCard,
} from './parts';

const PAIRING_POLL_MS = 2000;

/**
 * The tab the popup acts on. In the test build only, `?tab=` names it, because a popup opened
 * as a page is itself the active tab (extension-design.md §6).
 */
async function targetTab(): Promise<number | null> {
  if (__RUVEE_TEST__) {
    const fromQuery = Number(new URLSearchParams(location.search).get('tab'));
    if (Number.isInteger(fromQuery) && fromQuery > 0) return fromQuery;
  }
  const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  return tab?.id ?? null;
}

interface Screen {
  readonly name: 'loading' | 'stale' | 'no-server' | 'login' | 'pending' | 'locked' | 'unlocked';
}

function Popup() {
  const [screen, setScreen] = useState<Screen>({ name: 'loading' });
  const [error, setError] = useState<string | null>(null);
  // The paired server, for "Open Ruvee"; null hides the button.
  const [server, setServer] = useState<string | null>(null);

  const refresh = useCallback(() => {
    const next = (status: Status): Promise<Screen> => {
      setServer(status.serverOrigin);
      // A worker from another build (files replaced without a reload) does not know this
      // popup's messages; nothing else is sent to it.
      if (status.build !== __RUVEE_BUILD__) return Promise.resolve({ name: 'stale' });
      if (!status.serverOrigin) return Promise.resolve({ name: 'no-server' });
      if (status.unlocked) return Promise.resolve({ name: 'unlocked' });
      return call<DevicePhase>({ kind: 'vault', method: 'phase' }).then((phase) => ({
        name: phase.phase === 'new' ? 'login' : phase.phase === 'pending' ? 'pending' : 'locked',
      }));
    };
    call<Status>({ kind: 'status' })
      .then(next)
      .then(setScreen, (e: unknown) => {
        setError(stepMessageFor('status', e));
        // The worker did not answer; the address stored at pairing still opens the web vault.
        void storedServerOrigin().then(setServer);
      });
  }, []);

  useEffect(refresh, [refresh]);

  const lock: LockState =
    screen.name === 'unlocked' ? 'unlocked' : screen.name === 'locked' ? 'locked' : null;

  return (
    <main className="popup">
      <Header server={server} lock={lock} />
      <div className="content">
        {error ? (
          <StateCard
            tone="danger"
            icon={<AlertIcon />}
            title="Ruvee could not start"
            action={
              <button
                type="button"
                className="btn btn-primary btn-block"
                onClick={() => {
                  setError(null);
                  refresh();
                }}
              >
                Try again
              </button>
            }
          >
            <p role="alert" className="state-body">
              {error}
            </p>
          </StateCard>
        ) : null}
        {screen.name === 'loading' && !error ? (
          <p aria-busy="true" className="muted center">
            Loading…
          </p>
        ) : null}
        {screen.name === 'stale' ? (
          <StateCard
            tone="danger"
            icon={<AlertIcon />}
            title="Finish the update"
            action={
              <button
                type="button"
                className="btn btn-primary btn-block"
                onClick={() => {
                  chrome.runtime.reload();
                }}
              >
                Reload Ruvee
              </button>
            }
          >
            <p role="alert" className="state-body">
              Ruvee was updated, but the browser is still running the previous version. Reload it to
              finish the update (or press Reload on its card in chrome://extensions). The vault
              locks; unlock it again afterwards.
            </p>
          </StateCard>
        ) : null}
        {screen.name === 'no-server' ? (
          <StateCard
            icon={<GlobeIcon />}
            title="Connect your Ruvee server"
            action={
              <button
                type="button"
                className="btn btn-primary btn-block"
                onClick={() => void chrome.runtime.openOptionsPage()}
              >
                Open settings
              </button>
            }
          >
            <p className="state-body">Choose your Ruvee server first.</p>
          </StateCard>
        ) : null}
        {screen.name === 'login' ? <Login onDone={refresh} /> : null}
        {screen.name === 'pending' ? (
          <Pair
            onDone={refresh}
            onRestart={() => {
              setScreen({ name: 'login' });
            }}
          />
        ) : null}
        {screen.name === 'locked' ? <Unlock onDone={refresh} /> : null}
        {screen.name === 'unlocked' ? <Fill onLocked={refresh} server={server} /> : null}
      </div>
      <footer className="foot">
        <DevTag />
        <button
          type="button"
          className="btn btn-ghost btn-icon"
          aria-label="Settings"
          title="Settings"
          onClick={() => void chrome.runtime.openOptionsPage()}
        >
          <SettingsIcon />
        </button>
      </footer>
    </main>
  );
}

function useSubmit() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const run = (task: () => Promise<void>) => (event: SubmitEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    task()
      .catch((e: unknown) => {
        setError(messageFor(e));
      })
      .finally(() => {
        setBusy(false);
      });
  };
  return { busy, error, run };
}

function Login({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const { busy, error, run } = useSubmit();
  return (
    <form
      onSubmit={run(async () => {
        await call({ kind: 'vault', method: 'login', params: { username, password } });
        setPassword('');
        onDone();
      })}
    >
      <div className="form-head">
        <p className="state-title">Log in to Ruvee</p>
        <p className="muted">
          Log in with your Ruvee account. Then add this browser from a device that is already set
          up.
        </p>
      </div>
      <label>
        Username
        <input
          value={username}
          autoComplete="username"
          onChange={(e) => {
            setUsername(e.target.value);
          }}
        />
      </label>
      <label>
        Master password
        <input
          type="password"
          value={password}
          autoComplete="current-password"
          onChange={(e) => {
            setPassword(e.target.value);
          }}
        />
      </label>
      {error ? (
        <p role="alert" className="notice error">
          {error}
        </p>
      ) : null}
      <button type="submit" className="btn btn-primary btn-block" aria-disabled={busy || undefined}>
        {busy ? 'Logging in…' : 'Log in'}
      </button>
    </form>
  );
}

/**
 * device-enrollment §3: this browser is device B and joins with the code shown on device A. The
 * worker owns the join and finishes it even while the popup is closed (it closes as soon as the
 * user switches to the device that approves); this screen only reads where the join stands.
 */
function Pair({ onDone, onRestart }: { onDone: () => void; onRestart: () => void }) {
  const [view, setView] = useState<PairingView | null>(null);
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [needsPassword, setNeedsPassword] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<CallError | null>(null);

  const read = useCallback(
    () =>
      call<PairingView>({ kind: 'pairing' }).then(
        (next) => {
          if (next.state === 'enrolled') onDone();
          else setView(next);
        },
        (e: unknown) => {
          setFailure(e instanceof CallError ? e : new CallError('internal'));
        },
      ),
    [onDone],
  );

  useEffect(() => {
    void read();
    void call<boolean>({ kind: 'vault', method: 'pairingNeedsPassword' }).then(
      setNeedsPassword,
      () => undefined,
    );
  }, [read]);

  const joined = view?.state === 'joined';
  useEffect(() => {
    if (!joined) return;
    const timer = setInterval(() => void read(), PAIRING_POLL_MS);
    return () => {
      clearInterval(timer);
    };
  }, [joined, read]);

  const send = (task: () => Promise<void>) => (event: SubmitEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setFailure(null);
    void task()
      .catch((e: unknown) => {
        const error = e instanceof CallError ? e : new CallError('internal');
        if (error.code === 'password_required') setNeedsPassword(true);
        setFailure(error);
      })
      .then(read)
      .finally(() => {
        setBusy(false);
      });
  };

  if (!view) return <p aria-busy="true">Loading…</p>;
  // What stopped the last join, or this screen's own call; either may need a new login.
  const problem = failure ?? (view.problem === null ? null : new CallError(view.problem));
  const alert = problem ? (
    <p role="alert" className="notice error">
      {pairingMessageFor(problem)}
    </p>
  ) : null;
  const restart =
    problem && PAIRING_RESTART_CODES.has(problem.code) ? (
      <button type="button" className="btn btn-secondary btn-block" onClick={onRestart}>
        Log in again
      </button>
    ) : null;

  if (view.state === 'joined')
    return (
      <section className="stack">
        <p role="status" className="state-title">
          Waiting for approval on your other device…
        </p>
        <p className="muted">You can close this window; Ruvee finishes adding this browser.</p>
        {view.needsPassword ? (
          <form
            onSubmit={send(async () => {
              const status = await call<PairingJoinStatus>({
                kind: 'vault',
                method: 'pairingWait',
                params: { password },
              });
              setPassword('');
              if (status.state === 'enrolled') onDone();
            })}
          >
            <label>
              Master password
              <input
                type="password"
                value={password}
                autoComplete="current-password"
                onChange={(e) => {
                  setPassword(e.target.value);
                }}
              />
              <span className="hint">Needed once more to finish adding this browser.</span>
            </label>
            {alert}
            <button
              type="submit"
              className="btn btn-primary btn-block"
              aria-disabled={busy || undefined}
            >
              {busy ? 'Finishing…' : 'Finish adding this browser'}
            </button>
          </form>
        ) : (
          alert
        )}
        {restart}
      </section>
    );

  return (
    <form
      onSubmit={send(async () => {
        await call({
          kind: 'vault',
          method: 'pairingJoin',
          params: { code, ...(needsPassword ? { password } : {}) },
        });
        setPassword('');
      })}
    >
      <div className="form-head">
        <p className="state-title">Add this browser</p>
        <p className="muted">
          On a device that is already set up, open <strong>Devices</strong>, choose{' '}
          <strong>Add a device</strong>, and type the code it shows here.
        </p>
      </div>
      <label>
        Pairing code
        <input
          value={code}
          autoComplete="off"
          spellCheck={false}
          placeholder="PC1-…"
          className="mono"
          onChange={(e) => {
            setCode(e.target.value);
          }}
        />
      </label>
      {needsPassword ? (
        <label>
          Master password
          <input
            type="password"
            value={password}
            onChange={(e) => {
              setPassword(e.target.value);
            }}
          />
        </label>
      ) : null}
      {alert}
      <button type="submit" className="btn btn-primary btn-block" aria-disabled={busy || undefined}>
        {busy ? 'Sending…' : 'Add this browser'}
      </button>
      {restart}
    </form>
  );
}

function Unlock({ onDone }: { onDone: () => void }) {
  const [password, setPassword] = useState('');
  // Set after `previous_password_required`: the password and SK both changed elsewhere.
  const [previous, setPrevious] = useState<string | null>(null);
  const field = useRef<HTMLInputElement>(null);
  useEffect(() => {
    // The locked popup has one task, so its field takes focus, as on the web lock screen.
    field.current?.focus();
  }, []);
  const { busy, error, run } = useSubmit();
  return (
    <form
      onSubmit={run(async () => {
        try {
          await call({
            kind: 'vault',
            method: 'unlock',
            params: { password, ...(previous === null ? {} : { previousPassword: previous }) },
          });
        } catch (e) {
          if (e instanceof CallError && e.code === 'previous_password_required') setPrevious('');
          throw e;
        }
        setPassword('');
        setPrevious(null);
        onDone();
      })}
    >
      <div className="locked-head">
        <span className="state-icon">
          <LockIcon size={22} />
        </span>
        <p className="state-title">Your vault is locked.</p>
        <p className="muted">Enter your master password to fill logins on this page.</p>
      </div>
      <label>
        Master password
        <input
          type="password"
          value={password}
          autoComplete="current-password"
          ref={field}
          onChange={(e) => {
            setPassword(e.target.value);
          }}
        />
      </label>
      {previous === null ? null : (
        <label>
          Previous master password
          <input
            type="password"
            value={previous}
            autoComplete="off"
            onChange={(e) => {
              setPrevious(e.target.value);
            }}
          />
          <span className="hint">The one this browser used before the change. Needed once.</span>
        </label>
      )}
      {error ? (
        <p role="alert" className="notice error">
          {error}
        </p>
      ) : null}
      <button type="submit" className="btn btn-primary btn-block" aria-disabled={busy || undefined}>
        {busy ? 'Unlocking…' : 'Unlock'}
      </button>
    </form>
  );
}

/**
 * backup-restore.md §3.12. This browser keeps its copy and is never erased by itself; the
 * verified-copy export and "start over" are in the web app. The server's restore claim only
 * picks the wording.
 */
function restoreNotice(status: SyncStatus): string | null {
  if (status.state === 'maintenance')
    return 'Your Ruvee server is being restored by its owner. Logins here can still be filled; nothing changes until the server opens again.';
  if (status.state === 'reopening')
    return 'Your Ruvee server was restored and waits to be reopened in the web app, with the code from the server. Logins here can still be filled.';
  if (
    status.state === 'integrity_error' &&
    ['server_behind', 'history_rewritten', 'keyset_rollback'].includes(status.integrity ?? '')
  )
    return `${status.serverRestoredAtMs !== undefined ? 'Your server reports that it was restored from a backup.' : 'Your server may have been restored from an older backup.'} This browser has newer data, so sync is paused and its copy is kept, read-only. See Security in the Ruvee web app.`;
  return null;
}

const FILL_TEXT: Record<FillOutcome, string> = {
  filled: 'Filled. Check the page before you submit it.',
  origin_changed: 'The page changed before Ruvee could fill it. Nothing was filled.',
  no_password_field: 'No visible password field on this page.',
  not_allowed: "This login isn't saved for this page, so Ruvee won't fill it.",
  gone: 'This login is no longer in your vault (deleted or moved to Trash on another device). Nothing was filled.',
};

/** extension-design.md §4: logins saved for exactly this page's origin, filled on request. */
function Fill({ onLocked, server }: { onLocked: () => void; server: string | null }) {
  const [tabId, setTabId] = useState<number | null>(null);
  const [found, setFound] = useState<Candidates | null>(null);
  const [pending, setPending] = useState<PendingSave | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const failed = useCallback(
    (step: string) => (e: unknown) => {
      if (
        e instanceof CallError &&
        ['locked', 'session_expired', 'device_revoked'].includes(e.code)
      )
        onLocked();
      else setError(stepMessageFor(step, e));
    },
    [onLocked],
  );

  /** The logins for the tab, as the worker holds them now. */
  const list = useCallback(
    async (tab: number | null): Promise<void> => {
      if (tab === null) {
        setFound({ origin: null, items: [] });
        return;
      }
      await call<Candidates>({ kind: 'candidates', tabId: tab }).then(
        setFound,
        failed('candidates'),
      );
    },
    [failed],
  );

  useEffect(() => {
    void (async () => {
      const tab = await targetTab().catch(() => null);
      setTabId(tab);
      // The local list first, so the popup is usable at once and while offline.
      await list(tab);
      // A save offer waiting for this tab (phase B). Its own call: a failure here or in the
      // sync below does not hide the list, and the error names the call.
      if (tab !== null)
        await call<PendingSave | null>({ kind: 'pendingSave', tabId: tab }).then(
          setPending,
          failed('pendingSave'),
        );
      // A sync on every open: it brings other devices' changes, and it is how a revoked
      // browser or an ended session is noticed (the worker then locks or wipes itself). The
      // list is read again afterwards: what other devices deleted must not stay offered.
      await call<SyncStatus>({ kind: 'vault', method: 'sync' }).then(async (synced) => {
        if (synced.state === 'session_expired') {
          onLocked();
          return;
        }
        // Only a notice of its own: a fill the user started meanwhile keeps its result shown.
        const notice = restoreNotice(synced);
        if (notice !== null) setNotice(notice);
        await list(tab);
      }, failed('sync'));
    })();
  }, [onLocked, list, failed]);

  const answerSave = (save: boolean) => {
    if (tabId === null) return;
    setNotice(null);
    setError(null);
    const request = save
      ? call<SavePendingResult>({ kind: 'savePending', tabId })
      : call<true>({ kind: 'dismissPending', tabId }).then(() => 'dismissed' as const);
    request
      .then(async (result) => {
        setPending(null);
        if (result === 'saved') {
          setNotice('Saved to your vault.');
          setFound(await call<Candidates>({ kind: 'candidates', tabId }));
        } else if (result === 'gone')
          setNotice('That sign-in is no longer waiting. Nothing was saved.');
      })
      .catch((e: unknown) => {
        setError(messageFor(e));
      });
  };

  const fill = (item: Candidate) => {
    if (tabId === null) return;
    setNotice(null);
    call<FillOutcome>({ kind: 'fill', tabId, itemId: item.id }).then((outcome) => {
      setNotice(FILL_TEXT[outcome]);
      if (outcome === 'gone') void list(tabId);
    }, failed('fill'));
  };

  // The username only: it is already on screen. The password never reaches the popup.
  const copyUsername = (item: Candidate) => {
    setNotice(null);
    navigator.clipboard.writeText(item.username).then(
      () => {
        setNotice('Username copied.');
      },
      () => {
        setError('The browser did not allow copying. Select the username and copy it instead.');
      },
    );
  };

  return (
    <section className="stack">
      {pending ? (
        // extension-inline-autofill.md §5.2: the only place a save is offered (never in the page).
        <div className="save-offer" role="group" aria-labelledby="save-offer-title">
          <span className="save-icon" aria-hidden="true">
            <KeyIcon />
          </span>
          <div className="save-body">
            <p id="save-offer-title" className="save-title">
              Save this login for <strong>{pending.origin}</strong>?
            </p>
            <p className="muted">
              {pending.username === '' ? 'No username' : `Username: ${pending.username}`}. The
              password stays hidden.
            </p>
            <div className="actions">
              <button
                type="button"
                className="btn btn-primary btn-sm"
                onClick={() => {
                  answerSave(true);
                }}
              >
                Save login
              </button>
              <button
                type="button"
                className="btn btn-secondary btn-sm"
                onClick={() => {
                  answerSave(false);
                }}
              >
                Not now
              </button>
            </div>
          </div>
        </div>
      ) : null}
      {found?.origin ? (
        <p className="site">
          Logins for <strong>{found.origin}</strong>
        </p>
      ) : found ? null : (
        <p aria-busy="true" className="muted center">
          Looking for logins…
        </p>
      )}
      {error ? (
        <p role="alert" className="notice error">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p role="status" className="notice ok">
          {notice}
        </p>
      ) : null}
      {found && !found.origin ? (
        <StateCard icon={<GlobeIcon />} title="Nothing to fill here">
          <p className="state-body">
            Ruvee fills only HTTPS pages (and loopback addresses during development).
          </p>
        </StateCard>
      ) : null}
      {found?.origin && found.items.length === 0 ? (
        <StateCard
          icon={<KeyIcon />}
          title="No logins for this site"
          action={<OpenRuvee server={server} label="Add one in Ruvee" />}
        >
          <p className="state-body">No login is saved for exactly this address.</p>
        </StateCard>
      ) : null}
      <ul className="logins">
        {found?.items.map((item) => (
          <li key={item.id}>
            <span className="avatar" aria-hidden="true">
              {(item.title.trim().charAt(0) || '?').toUpperCase()}
            </span>
            <span className="login-text">
              <strong>{item.title}</strong>
              <span className="muted">{item.username === '' ? 'No username' : item.username}</span>
            </span>
            <span className="row-actions">
              {item.username === '' ? null : (
                <button
                  type="button"
                  className="btn btn-ghost btn-icon"
                  aria-label={`Copy username for ${item.title}`}
                  title="Copy username"
                  onClick={() => {
                    copyUsername(item);
                  }}
                >
                  <CopyIcon />
                </button>
              )}
              <button
                type="button"
                className="btn btn-primary btn-sm"
                aria-label={`Fill ${item.title}`}
                onClick={() => {
                  fill(item);
                }}
              >
                Fill
              </button>
            </span>
          </li>
        ))}
      </ul>
      <div className="actions spread">
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => {
            void call({ kind: 'lock' }).then(onLocked);
          }}
        >
          <LockIcon size={14} />
          Lock
        </button>
        <button
          type="button"
          className="btn btn-ghost btn-sm"
          onClick={() => {
            void call({ kind: 'vault', method: 'logout' }).finally(onLocked);
          }}
        >
          Log out
        </button>
      </div>
    </section>
  );
}

const root = document.getElementById('root');
if (root) createRoot(root).render(<Popup />);
