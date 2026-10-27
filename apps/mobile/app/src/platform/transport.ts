import type { TokenPair } from '@ruvee/contracts';
import { ApiError, NetworkError, refreshTokens, type Transport } from '@ruvee/vault';
import { secureStore } from './secure-store';

/**
 * The mobile API transport: a token platform like the extension (authentication.md §5).
 *
 * - Access token (10 minutes): in memory only. After a process restart the first request
 *   refreshes it.
 * - Refresh token (rotating): in the Keystore-backed secure store, so a restart does not force a
 *   new OPAQUE login. It decrypts nothing (INV-06).
 * - `credentials: 'omit'`: no cookie ever goes with a bearer request.
 *
 * Caching: see `installOriginHeader` for why `cache: 'no-store'` is dropped on this server's
 * requests.
 *
 * `Origin`: the API's CSRF check (authentication.md §6) requires `Origin` on the unauthenticated
 * writes a token client makes (`login/*`, `refresh`), and accepts only the configured public
 * origin or a listed extension origin. A native app has no browser origin, so it sends the
 * server's own origin, which the user configured; it carries no ambient credential, so this
 * grants nothing a non-browser client could not already do. Recorded for review as SC-3
 * (docs/mobile/shared-change-requests.md).
 */
const REFRESH_TOKEN = 'refresh-token';

export interface MobileTransport extends Transport {
  /** Drops both tokens: after logout, revocation, or a refresh the server refused. */
  clear(): Promise<void>;
  hasRefreshToken(): Promise<boolean>;
}

let installedOrigin: string | undefined;

/** Adds `Origin` to requests for this server's API, and to no other request. */
function installOriginHeader(origin: string): void {
  installedOrigin = origin;
  const g = globalThis as { fetch: typeof fetch; __ruveeFetch?: typeof fetch };
  if (g.__ruveeFetch) return;
  const base = g.fetch;
  g.__ruveeFetch = base;
  g.fetch = (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    if (installedOrigin === undefined || !url.startsWith(`${installedOrigin}/api/`))
      return base(input, init);
    const headers = new Headers(init?.headers);
    if (!headers.has('Origin')) headers.set('Origin', installedOrigin);
    // React Native's fetch (whatwg-fetch) implements `cache: 'no-store'` by appending `_=<time>`
    // to the URL, which the API's strict query schemas refuse. Every API response is already
    // `Cache-Control: no-store`, which React Native's OkHttp client honours, so the option is
    // dropped for this server only.
    const { cache: _noStore, ...rest } = init ?? {};
    return base(input, { ...rest, headers });
  };
}

export function mobileTransport(origin: string): MobileTransport {
  installOriginHeader(origin);
  const base: Transport = { baseUrl: `${origin}/api/v1`, credentials: 'omit' };
  let accessToken: string | undefined;
  let refreshing: Promise<boolean> | undefined;

  const save = async (tokens: TokenPair) => {
    accessToken = tokens.accessToken;
    await secureStore.setText(REFRESH_TOKEN, tokens.refreshToken);
  };
  const clear = async () => {
    accessToken = undefined;
    await secureStore.remove(REFRESH_TOKEN);
  };
  // One refresh at a time: a rotated refresh token presented twice ends the whole session family.
  const refresh = () => {
    refreshing ??= (async () => {
      try {
        const current = await secureStore.getText(REFRESH_TOKEN);
        if (!current) return false;
        try {
          await save(await refreshTokens(base, current));
          return true;
        } catch (error) {
          // Only the server's refusal ends the session. Without a network the refresh token is
          // kept: it is still valid, and losing it would turn going offline into a logout.
          if (error instanceof ApiError) await clear();
          return false;
        }
      } finally {
        refreshing = undefined;
      }
    })();
    return refreshing;
  };

  return {
    ...base,
    async authorization() {
      if (accessToken === undefined && (await secureStore.getText(REFRESH_TOKEN)) !== undefined) {
        const refreshed = await refresh();
        // A session exists but could not be resumed (no network): the request must not go out
        // unauthenticated, where a 401 would read as "session ended". It fails as offline.
        if (!refreshed && (await secureStore.getText(REFRESH_TOKEN)) !== undefined)
          throw new NetworkError('offline');
      }
      return accessToken === undefined ? undefined : `Bearer ${accessToken}`;
    },
    refresh,
    onTokens: save,
    clear,
    async hasRefreshToken() {
      return (await secureStore.getText(REFRESH_TOKEN)) !== undefined;
    },
  };
}
