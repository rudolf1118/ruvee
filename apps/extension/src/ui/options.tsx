import { type SubmitEvent, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { INLINE_ORIGINS } from '../inline/gate';
import type {
  InlineSettings,
  OfferLogEntry,
  SetInlineResult,
  SetServerResult,
  Status,
} from '../messages';
import { fillableOrigin } from '../origin';
import { call, messageFor } from './client';

const RESULT_TEXT: Record<Exclude<SetServerResult, 'saved'>, string> = {
  not_an_origin:
    'Use the address of your Ruvee server only, like https://vault.example. Plain http works only for 127.0.0.1 and localhost.',
  device_exists:
    'This browser is already set up with another server. Remove it from that account first.',
  no_permission: 'Ruvee needs permission to reach that server. Allow it when the browser asks.',
};

/**
 * The server address (extension-design.md §2). The extension asks for host permission for that
 * one origin, and for nothing else.
 */
function Options() {
  const [current, setCurrent] = useState<string | null>(null);
  const [text, setText] = useState('');
  const [message, setMessage] = useState<{ tone: 'error' | 'ok'; text: string } | null>(null);
  const [stale, setStale] = useState(false);

  useEffect(() => {
    call<Status>({ kind: 'status' }).then(
      (status) => {
        // Files replaced without a reload: the old worker does not know these pages' messages.
        if (status.build !== __RUVEE_BUILD__) setStale(true);
        setCurrent(status.serverOrigin);
        setText(status.serverOrigin ?? '');
      },
      (e: unknown) => {
        setMessage({ tone: 'error', text: messageFor(e) });
      },
    );
  }, []);

  const submit = (event: SubmitEvent) => {
    event.preventDefault();
    setMessage(null);
    const typed = text.trim().replace(/\/+$/, '');
    const origin = fillableOrigin(typed);
    // The origin alone: a path would be dropped silently, and the worker refuses it too.
    if (!origin || origin !== typed) {
      setMessage({ tone: 'error', text: RESULT_TEXT.not_an_origin });
      return;
    }
    // Asked here, in the click, because the browser shows its prompt only for a user gesture.
    chrome.permissions
      .request({ origins: [`${origin}/*`] })
      .then(() => call<SetServerResult>({ kind: 'setServer', origin }))
      .then(
        (result) => {
          if (result === 'saved') {
            setCurrent(origin);
            setMessage({ tone: 'ok', text: 'Saved. Open Ruvee from the toolbar to log in.' });
          } else setMessage({ tone: 'error', text: RESULT_TEXT[result] });
        },
        (e: unknown) => {
          setMessage({ tone: 'error', text: messageFor(e) });
        },
      );
  };

  return (
    <main className="options">
      <h1>Ruvee settings</h1>
      {stale ? (
        <p role="alert" className="error">
          Ruvee was updated, but the browser is still running the previous version.{' '}
          <button
            type="button"
            onClick={() => {
              chrome.runtime.reload();
            }}
          >
            Reload Ruvee
          </button>
        </p>
      ) : null}
      <p className="badge">Development build, not reviewed. Use synthetic data only.</p>
      <form onSubmit={submit}>
        <label>
          Server address
          <input
            value={text}
            placeholder="https://vault.example"
            spellCheck={false}
            onChange={(e) => {
              setText(e.target.value);
            }}
          />
        </label>
        {current ? <p className="muted">Current server: {current}</p> : null}
        {message ? (
          <p role={message.tone === 'error' ? 'alert' : 'status'} className={message.tone}>
            {message.text}
          </p>
        ) : null}
        <button type="submit" className="primary">
          Save
        </button>
      </form>
      <Inline />
    </main>
  );
}

/**
 * Inline fill (extension-inline-autofill.md, phase A). Off by default. Turning it on asks the
 * browser for permission to run on every HTTPS page, so the icon can appear in login fields;
 * turning it off gives that permission back.
 */
function Inline() {
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [autoOpen, setAutoOpen] = useState(false);
  const [log, setLog] = useState<OfferLogEntry[]>([]);
  const [message, setMessage] = useState<{ tone: 'error' | 'ok'; text: string } | null>(null);

  useEffect(() => {
    call<InlineSettings>({ kind: 'inlineSettings' }).then(
      (settings) => {
        setEnabled(settings.enabled);
        setAutoOpen(settings.autoOpenSave);
        void call<OfferLogEntry[]>({ kind: 'offerLog' }).then(setLog, () => undefined);
      },
      (e: unknown) => {
        setMessage({ tone: 'error', text: messageFor(e) });
      },
    );
  }, []);

  const turnOn = () => {
    setMessage(null);
    // Asked here, in the click: the browser shows its prompt only for a user gesture.
    chrome.permissions
      .request({ origins: [...INLINE_ORIGINS] })
      .then(() => call<SetInlineResult>({ kind: 'setInline', enabled: true }))
      .then(
        (result) => {
          if (result === 'saved') {
            setEnabled(true);
            setMessage({
              tone: 'ok',
              text: 'On. Reload a login page to see the Ruvee icon in its fields.',
            });
          } else
            setMessage({
              tone: 'error',
              text: 'Ruvee needs permission to run on websites to show the icon. Allow it when the browser asks.',
            });
        },
        (e: unknown) => {
          setMessage({ tone: 'error', text: messageFor(e) });
        },
      );
  };

  const turnOff = () => {
    setMessage(null);
    call<SetInlineResult>({ kind: 'setInline', enabled: false })
      .then(async () => {
        setEnabled(false);
        // The test build's host permission is part of its manifest and cannot be given back.
        if (!__RUVEE_TEST__) await chrome.permissions.remove({ origins: [...INLINE_ORIGINS] });
        // Giving back access to every site must not have taken the server's with it.
        const status = await call<Status>({ kind: 'status' });
        const server = status.serverOrigin;
        const serverKept =
          server === null || (await chrome.permissions.contains({ origins: [`${server}/*`] }));
        setMessage(
          serverKept
            ? { tone: 'ok', text: 'Off. Ruvee no longer runs on websites.' }
            : {
                tone: 'error',
                text: 'Off. The browser also removed access to your Ruvee server: save the server address again above.',
              },
        );
      })
      .catch((e: unknown) => {
        setMessage({ tone: 'error', text: messageFor(e) });
      });
  };

  return (
    <section aria-labelledby="inline-heading">
      <h2 id="inline-heading">Fill from login fields</h2>
      <p>
        Shows the Ruvee icon in login fields. Clicking it opens Ruvee, where you choose what to
        fill, as from the toolbar. Ruvee never fills by itself and never asks for your master
        password inside a web page.
      </p>
      <p className="muted">
        This needs permission to run on every HTTPS website. Websites can then tell that Ruvee is
        installed, but not whether it is unlocked or has a login for them.
      </p>
      {enabled === null ? null : (
        <p>
          Status: <strong>{enabled ? 'on' : 'off'}</strong>
        </p>
      )}
      {message ? (
        <p role={message.tone === 'error' ? 'alert' : 'status'} className={message.tone}>
          {message.text}
        </p>
      ) : null}
      {enabled === false ? (
        <button type="button" className="primary" onClick={turnOn}>
          Turn on
        </button>
      ) : null}
      {enabled === true ? (
        <button type="button" onClick={turnOff}>
          Turn off
        </button>
      ) : null}
      {enabled === true ? (
        <label className="check">
          <input
            type="checkbox"
            checked={autoOpen}
            onChange={(event) => {
              const next = event.target.checked;
              setMessage(null);
              call<true>({ kind: 'setAutoOpenSave', enabled: next }).then(
                () => {
                  setAutoOpen(next);
                },
                (e: unknown) => {
                  setMessage({ tone: 'error', text: messageFor(e) });
                },
              );
            }}
          />
          Open Ruvee by itself to offer saving a login
          <span className="muted">
            {' '}
            After you sign in on a site, Ruvee opens its own window to ask whether to save the
            login. Off: only a + on the Ruvee button shows the offer. When the window opens, the
            site may notice that its page lost focus, and so that Ruvee is unlocked and has no login
            with that username.
          </span>
        </label>
      ) : null}
      {enabled === true ? (
        // Development build: what became of the last sign-ins, so a hand check can tell why a
        // popup did or did not open (extension-inline-autofill.md §8.3).
        <div className="offer-log">
          <h3>Recent sign-ins (development build)</h3>
          {log.length === 0 ? (
            <p className="muted">None since the browser started.</p>
          ) : (
            <ul>
              {log.map((entry) => (
                <li key={`${String(entry.atMs)}-${entry.origin}`}>
                  <span className="muted">{new Date(entry.atMs).toLocaleTimeString()}</span>{' '}
                  {entry.origin}: {entry.result}
                </li>
              ))}
            </ul>
          )}
          <button
            type="button"
            onClick={() => {
              void call<OfferLogEntry[]>({ kind: 'offerLog' }).then(setLog, () => undefined);
            }}
          >
            Refresh
          </button>
        </div>
      ) : null}
    </section>
  );
}

const root = document.getElementById('root');
if (root) createRoot(root).render(<Options />);
