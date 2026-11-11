import { type SubmitEvent, useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import type { SetServerResult, Status } from '../messages';
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

  useEffect(() => {
    call<Status>({ kind: 'status' }).then(
      (status) => {
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
    </main>
  );
}

const root = document.getElementById('root');
if (root) createRoot(root).render(<Options />);
