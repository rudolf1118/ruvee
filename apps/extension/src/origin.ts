/**
 * Origin rules for manual fill (extension-design.md §4). A login is offered only when its stored
 * URL has exactly the tab's origin: same scheme, host and port. No subdomain or registrable-domain
 * matching, and no plain HTTP except on loopback.
 */

const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

/** The origin of a page that may be filled, or null when the page is not fillable at all. */
export function fillableOrigin(url: string | undefined): string | null {
  if (url === undefined) return null;
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return null;
  }
  // Credentials in the URL make the displayed host easy to misread; refuse such pages.
  if (parsed.username !== '' || parsed.password !== '') return null;
  if (parsed.protocol === 'https:') return parsed.origin;
  if (parsed.protocol === 'http:' && LOOPBACK_HOSTS.has(parsed.hostname)) return parsed.origin;
  return null;
}

/**
 * The origin of a stored login URL. A bare host such as `mail.example` means `https://`. A
 * trailing dot is a different host to the browser, so it is kept and simply never matches.
 */
export function storedOrigin(url: string): string | null {
  const text = /^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`;
  return fillableOrigin(text);
}

export function originMatches(stored: string, tabUrl: string | undefined): boolean {
  const tab = fillableOrigin(tabUrl);
  const item = storedOrigin(stored);
  return tab !== null && item !== null && tab === item;
}
