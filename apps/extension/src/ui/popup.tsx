import type { DevicePhase, PairingJoinStatus, SyncStatus } from '@ruvee/vault';
import { type SubmitEvent, useCallback, useEffect, useRef, useState } from 'react';
import { createRoot } from 'react-dom/client';
import type {
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

  const refresh = useCallback(() => {
    const next = (status: Status): Promise<Screen> => {
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
      });
  }, []);

  useEffect(refresh, [refresh]);

  return (
    <main>
      <header>
        <strong>Ruvee</strong>
        <span className="badge">Development build</span>
      </header>
      {error ? (
        <p role="alert" className="error">
          {error}
        </p>
      ) : null}
      {screen.name === 'loading' ? <p aria-busy="true">Loading…</p> : null}
      {screen.name === 'stale' ? (
        <section>
          <p role="alert" className="error">
            Ruvee was updated, but the browser is still running the previous version. Reload it to
            finish the update (or press Reload on its card in chrome://extensions). The vault locks;
            unlock it again afterwards.
          </p>
          <button
            type="button"
            className="primary"
            onClick={() => {
              chrome.runtime.reload();
            }}
          >
            Reload Ruvee
          </button>
        </section>
      ) : null}
      {screen.name === 'no-server' ? (
        <section>
          <p>Choose your Ruvee server first.</p>
          <button
            type="button"
            className="primary"
            onClick={() => void chrome.runtime.openOptionsPage()}
          >
            Open settings
          </button>
        </section>
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
      {screen.name === 'unlocked' ? <Fill onLocked={refresh} /> : null}
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
      <p>
        Log in with your Ruvee account. Then add this browser from a device that is already set up.
      </p>
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
        <p role="alert" className="error">
          {error}
        </p>
      ) : null}
      <button type="submit" className="primary" aria-disabled={busy || undefined}>
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
    <p role="alert" className="error">
      {pairingMessageFor(problem)}
    </p>
  ) : null;
  const restart =
    problem && PAIRING_RESTART_CODES.has(problem.code) ? (
      <button type="button" onClick={onRestart}>
        Log in again
      </button>
    ) : null;

  if (view.state === 'joined')
    return (
      <section>
        <p role="status">Waiting for approval on your other device…</p>
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
              <span className="muted">Needed once more to finish adding this browser.</span>
            </label>
            {alert}
            <button type="submit" className="primary" aria-disabled={busy || undefined}>
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
      <p>
        On a device that is already set up, open <strong>Devices</strong>, choose{' '}
        <strong>Add a device</strong>, and type the code it shows here.
      </p>
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
      <button type="submit" className="primary" aria-disabled={busy || undefined}>
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
      <p>Your vault is locked.</p>
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
          <span className="muted">The one this browser used before the change. Needed once.</span>
        </label>
      )}
      {error ? (
        <p role="alert" className="error">
          {error}
        </p>
      ) : null}
      <button type="submit" className="primary" aria-disabled={busy || undefined}>
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
};

/** extension-design.md §4: logins saved for exactly this page's origin, filled on request. */
function Fill({ onLocked }: { onLocked: () => void }) {
  const [tabId, setTabId] = useState<number | null>(null);
  const [found, setFound] = useState<Candidates | null>(null);
  const [pending, setPending] = useState<PendingSave | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    void (async () => {
      // Each call on its own: one that fails does not hide what the others found (a save
      // offer must not vanish because a sync failed), and the error names the call.
      const failed = (step: string) => (e: unknown) => {
        if (
          e instanceof CallError &&
          ['locked', 'session_expired', 'device_revoked'].includes(e.code)
        )
          onLocked();
        else setError(stepMessageFor(step, e));
      };
      const tab = await targetTab().catch(() => null);
      setTabId(tab);
      if (tab === null) setFound({ origin: null, items: [] });
      else {
        await call<Candidates>({ kind: 'candidates', tabId: tab }).then(setFound, (e: unknown) => {
          setFound({ origin: null, items: [] });
          failed('candidates')(e);
        });
        await call<PendingSave | null>({ kind: 'pendingSave', tabId: tab }).then(
          setPending,
          failed('pendingSave'),
        );
      }
      // A sync on every open: it brings other devices' changes, and it is how a revoked
      // browser or an ended session is noticed (the worker then locks or wipes itself).
      await call<SyncStatus>({ kind: 'vault', method: 'sync' }).then((synced) => {
        if (synced.state === 'session_expired') onLocked();
        else setNotice(restoreNotice(synced));
      }, failed('sync'));
    })();
  }, [onLocked]);

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

  return (
    <section>
      {pending ? (
        // extension-inline-autofill.md §5.2: the only place a save is offered (never in the page).
        <div className="save-offer" role="group" aria-labelledby="save-offer-title">
          <p id="save-offer-title">
            Save this login for <strong>{pending.origin}</strong>?
          </p>
          <p className="muted">
            {pending.username === '' ? 'No username' : `Username: ${pending.username}`}. The
            password stays hidden.
          </p>
          <button
            type="button"
            className="primary"
            onClick={() => {
              answerSave(true);
            }}
          >
            Save login
          </button>
          <button
            type="button"
            onClick={() => {
              answerSave(false);
            }}
          >
            Not now
          </button>
        </div>
      ) : null}
      {found?.origin ? (
        <p className="origin">
          Logins for <strong>{found.origin}</strong>
        </p>
      ) : found ? (
        <p>Ruvee fills only HTTPS pages (and loopback addresses during development).</p>
      ) : (
        <p aria-busy="true">Looking for logins…</p>
      )}
      {error ? (
        <p role="alert" className="error">
          {error}
        </p>
      ) : null}
      {notice ? <p role="status">{notice}</p> : null}
      {found?.origin && found.items.length === 0 ? (
        <p>No login is saved for exactly this address.</p>
      ) : null}
      <ul>
        {found?.items.map((item) => (
          <li key={item.id}>
            <span>
              <strong>{item.title}</strong>
              <span className="muted">{item.username}</span>
            </span>
            <button
              type="button"
              aria-label={`Fill ${item.title}`}
              onClick={() => {
                if (tabId === null) return;
                setNotice(null);
                call<FillOutcome>({ kind: 'fill', tabId, itemId: item.id }).then(
                  (outcome) => {
                    setNotice(FILL_TEXT[outcome]);
                  },
                  (e: unknown) => {
                    setError(messageFor(e));
                  },
                );
              }}
            >
              Fill
            </button>
          </li>
        ))}
      </ul>
      <button
        type="button"
        onClick={() => {
          void call({ kind: 'lock' }).then(onLocked);
        }}
      >
        Lock
      </button>
      <button
        type="button"
        onClick={() => {
          void call({ kind: 'vault', method: 'logout' }).finally(onLocked);
        }}
      >
        Log out
      </button>
    </section>
  );
}

const root = document.getElementById('root');
if (root) createRoot(root).render(<Popup />);
