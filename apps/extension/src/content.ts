import { captureFrom, type Capture, submitControl } from './inline/capture';
import { inlineFields } from './inline/detect';

/**
 * The inline content script (extension-inline-autofill.md §2 option I1, §5.1). Registered only
 * after the user turns inline fill on, in the top frame of pages the extension may fill. It draws
 * the same icon on every login field whatever the vault holds; it never asks the worker anything
 * and receives nothing back but an empty reply. A trusted click on the icon asks the worker to
 * open the toolbar popup, where the user chooses, exactly as with manual fill.
 *
 * Phase B: when the user signs in (their own click on a submit control, or Enter in a field), the
 * script sends what the form holds to the worker, which may offer to save it from the toolbar
 * (§5.2). The page typed those values itself; nothing comes back.
 */

const TAG = 'ruvee-inline-icon';
const SIZE = 20;
const INSET = 6;
/** Narrower fields get no icon: it would cover what the user types. */
const MIN_FIELD_WIDTH = 80;
const MIN_FIELD_HEIGHT = 16;
/** One request a second at most, however often the icon is clicked. */
const OPEN_INTERVAL_MS = 1000;

// The brand mark (docs/brand/favicon.svg), inline: there are no web-accessible resources.
const MARKUP = `<style>
:host { all: initial; }
button { all: initial; display: block; width: ${String(SIZE)}px; height: ${String(SIZE)}px; cursor: pointer; }
svg { display: block; width: 100%; height: 100%; }
</style><button type="button" tabindex="-1" title="Fill with Ruvee" aria-label="Fill with Ruvee"><svg viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="8" fill="#6d4aff"/><circle cx="16" cy="13.2" r="4.8" fill="none" stroke="#fff" stroke-width="3.2"/><path d="M16 18.4v6.4" stroke="#fff" stroke-width="3.2" stroke-linecap="round"/></svg></button>`;

const icons = new Map<HTMLInputElement, HTMLElement>();
let lastOpen = 0;

function setStyle(el: HTMLElement, styles: Record<string, string>): void {
  // Inline and `!important`: page style sheets cannot move or resize the icon by accident.
  for (const [name, value] of Object.entries(styles))
    el.style.setProperty(name, value, 'important');
}

function makeIcon(): HTMLElement {
  const host = document.createElement(TAG);
  // Closed: the page cannot reach the button. It can still hide, cover or restyle the host,
  // which is why the icon only opens the popup and never fills by itself (E-10).
  const root = host.attachShadow({ mode: 'closed' });
  root.innerHTML = MARKUP;
  const button = root.querySelector('button');
  setStyle(host, {
    all: 'initial',
    position: 'fixed',
    'z-index': '2147483647',
    width: `${String(SIZE)}px`,
    height: `${String(SIZE)}px`,
    display: 'none',
  });
  // Keep the focus in the field the user is in.
  button?.addEventListener('mousedown', (event) => {
    event.preventDefault();
  });
  button?.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
    // Only the user's own click: a page's `click()` or dispatched event does nothing.
    if (!event.isTrusted) return;
    const now = Date.now();
    if (now - lastOpen < OPEN_INTERVAL_MS) return;
    lastOpen = now;
    chrome.runtime.sendMessage({ kind: 'inlineOpen' }).catch(() => undefined);
  });
  return host;
}

/** Enter in a field also makes the browser click the submit button: one capture, not two. */
const CAPTURE_REPEAT_MS = 2000;
let lastCapture: { at: number; capture: Capture } | undefined;

function sendCapture(from: Element): void {
  const capture = captureFrom(from);
  if (!capture) return;
  const now = Date.now();
  if (
    lastCapture &&
    now - lastCapture.at < CAPTURE_REPEAT_MS &&
    lastCapture.capture.username === capture.username &&
    lastCapture.capture.password === capture.password
  )
    return;
  lastCapture = { at: now, capture };
  chrome.runtime
    .sendMessage({ kind: 'inlineCapture', username: capture.username, password: capture.password })
    .catch(() => undefined);
}

function onClick(event: MouseEvent): void {
  // Only the user's own gesture: `requestSubmit()` and `button.click()` are the page's.
  if (!event.isTrusted) return;
  const control = submitControl(event.target);
  if (control) sendCapture(control);
}

function onKeydown(event: KeyboardEvent): void {
  if (!event.isTrusted || event.key !== 'Enter' || event.isComposing) return;
  if (event.target instanceof HTMLInputElement) sendCapture(event.target);
}

function place(field: HTMLInputElement, host: HTMLElement): void {
  const box = field.getBoundingClientRect();
  const shown =
    field.isConnected &&
    box.width >= MIN_FIELD_WIDTH &&
    box.height >= MIN_FIELD_HEIGHT &&
    box.bottom > 0 &&
    box.right > 0 &&
    box.top < window.innerHeight &&
    box.left < window.innerWidth &&
    field.checkVisibility({ opacityProperty: true, visibilityProperty: true });
  if (!shown) {
    setStyle(host, { display: 'none' });
    return;
  }
  setStyle(host, {
    display: 'block',
    left: `${String(Math.round(box.right - SIZE - INSET))}px`,
    top: `${String(Math.round(box.top + (box.height - SIZE) / 2))}px`,
  });
}

function placeAll(): void {
  for (const [field, host] of icons) place(field, host);
}

function scan(): void {
  const fields = new Set(inlineFields(document));
  for (const [field, host] of icons)
    if (!fields.has(field)) {
      host.remove();
      icons.delete(field);
    }
  for (const field of fields) {
    let host = icons.get(field);
    if (!host) {
      host = makeIcon();
      icons.set(field, host);
    }
    // A page that removed the icon gets it back on its next change.
    if (!host.isConnected) document.documentElement.append(host);
  }
  placeAll();
}

let scanQueued = false;
function queueScan(): void {
  if (scanQueued) return;
  scanQueued = true;
  setTimeout(() => {
    scanQueued = false;
    scan();
  }, 150);
}

let placeQueued = false;
function queuePlace(): void {
  if (placeQueued) return;
  placeQueued = true;
  requestAnimationFrame(() => {
    placeQueued = false;
    placeAll();
  });
}

// Only in the top frame (the fill reaches only the top frame), and only once per document. The
// marker lives in the isolated world's global scope, which the page cannot see or set.
const started = globalThis as { ruveeInlineStarted?: boolean };
if (window.top === window && !started.ruveeInlineStarted) {
  started.ruveeInlineStarted = true;
  const ours = (node: Node) => node.nodeName.toLowerCase() === TAG;
  new MutationObserver((records) => {
    // Our own icons moving or being placed are not a reason to scan again.
    const onlyOurs = records.every((r) =>
      r.type === 'attributes'
        ? ours(r.target)
        : [...r.addedNodes, ...r.removedNodes].every((n) => ours(n)),
    );
    if (!onlyOurs) queueScan();
  }).observe(document.documentElement, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ['type', 'disabled', 'readonly', 'style', 'class', 'hidden'],
  });
  window.addEventListener('scroll', queuePlace, { capture: true, passive: true });
  window.addEventListener('resize', queuePlace, { passive: true });
  // Capture phase on the window, before the page's own handlers can navigate away.
  window.addEventListener('click', onClick, { capture: true });
  window.addEventListener('keydown', onKeydown, { capture: true });
  // Animations and layout changes that fire no event.
  setInterval(() => {
    if (icons.size > 0) placeAll();
  }, 1000);
  scan();
}
