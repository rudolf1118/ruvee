/**
 * One tab per browser profile runs the vault (follow-up review F-2). Each engine keeps its own
 * copy of pending edits and writes it whole to IndexedDB, so two tabs would overwrite each
 * other's unsynced changes. The tab that runs the vault holds a Web Lock for as long as the page
 * lives; another tab can ask it, over a BroadcastChannel, to finish what it is doing and let go.
 */
const LOCK = 'ruvee-vault';
const CHANNEL = 'ruvee-vault-tabs';
const TAKE_OVER = 'take-over';

export function tabLockSupported(): boolean {
  return (
    typeof navigator !== 'undefined' &&
    'locks' in navigator &&
    typeof BroadcastChannel !== 'undefined'
  );
}

/** Called when another tab asks for the vault; the lock is released once it resolves. */
let handOver: () => Promise<void> = () => Promise.resolve();
/** Per page, not per component: a remount must not release and lose the lock. */
let held: Promise<boolean> | undefined;

export function onHandOver(callback: () => Promise<void>): void {
  handOver = callback;
}

/**
 * Takes the lock for this page. With `wait` false it resolves false at once when another tab
 * holds it; with `wait` true it resolves when the other tab has let go.
 */
export function takeTabLock(wait: boolean): Promise<boolean> {
  if (held) return held.then((ok) => (ok || !wait ? ok : request(true)));
  return request(wait);
}

function request(wait: boolean): Promise<boolean> {
  const attempt = new Promise<boolean>((resolve) => {
    void navigator.locks.request(LOCK, wait ? {} : { ifAvailable: true }, (lock) => {
      if (!lock) {
        resolve(false);
        return undefined;
      }
      resolve(true);
      return new Promise<void>((release) => {
        const channel = new BroadcastChannel(CHANNEL);
        channel.onmessage = (event: MessageEvent) => {
          if (event.data !== TAKE_OVER) return;
          channel.close();
          held = undefined;
          void handOver().finally(release);
        };
      });
    });
  });
  held = attempt;
  return attempt;
}

/** Asks the tab that holds the vault to let go; pair it with `takeTabLock(true)`. */
export function askOtherTab(): void {
  const channel = new BroadcastChannel(CHANNEL);
  channel.postMessage(TAKE_OVER);
  channel.close();
}
