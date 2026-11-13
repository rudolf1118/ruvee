import { fillableOrigin } from '../origin';

/**
 * "Open Ruvee": the paired server's web vault, in a tab. A tab already showing that origin is
 * brought to the front instead of opening another. No permission beyond what pairing granted:
 * creating and focusing tabs needs none, and the query by URL sees tabs of the server's origin
 * because the extension holds host permission for it (and only it, outside inline fill). Without
 * that permission the query finds nothing and a new tab opens.
 */
export async function openWebVault(server: string | null): Promise<void> {
  // Only the origin stored at pairing, and only one Ruvee would talk to.
  const origin = fillableOrigin(server ?? undefined);
  if (origin === null || origin !== server) return;
  const open = await chrome.tabs.query({ url: `${origin}/*` }).catch(() => []);
  const tab = open.find((t) => t.id !== undefined && fillableOrigin(t.url) === origin);
  if (tab?.id === undefined) {
    await chrome.tabs.create({ url: `${origin}/` });
    return;
  }
  await chrome.tabs.update(tab.id, { active: true });
  if (tab.windowId !== undefined) await chrome.windows.update(tab.windowId, { focused: true });
}

/** The server origin as stored at pairing; read directly when the worker could not answer. */
export async function storedServerOrigin(): Promise<string | null> {
  const stored = await chrome.storage.local.get('serverOrigin').catch(() => ({}));
  const value = (stored as Record<string, unknown>).serverOrigin;
  return typeof value === 'string' ? value : null;
}
