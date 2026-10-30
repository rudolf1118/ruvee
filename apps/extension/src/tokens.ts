import type { TokenPair } from '@ruvee/contracts';

/**
 * Token storage (authentication.md §5): the access token in `chrome.storage.session` (memory
 * only), the refresh token in the extension origin's IndexedDB, which content scripts cannot
 * read. Neither decrypts anything (INV-06).
 */

const DB = 'ruvee-extension';
const STORE = 'tokens';
const ACCESS_KEY = 'accessToken';

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => {
      req.result.createObjectStore(STORE);
    };
    req.onsuccess = () => {
      resolve(req.result);
    };
    req.onerror = () => {
      reject(new Error('token store unavailable'));
    };
  });
}

async function tx<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>) {
  const db = await open();
  try {
    return await new Promise<T>((resolve, reject) => {
      const req = run(db.transaction(STORE, mode).objectStore(STORE));
      req.onsuccess = () => {
        resolve(req.result);
      };
      req.onerror = () => {
        reject(new Error('token store failed'));
      };
    });
  } finally {
    db.close();
  }
}

export async function saveTokens(tokens: TokenPair): Promise<void> {
  await chrome.storage.session.set({ [ACCESS_KEY]: tokens.accessToken });
  await tx('readwrite', (s) => s.put(tokens.refreshToken, 'refresh'));
}

export async function accessToken(): Promise<string | undefined> {
  const stored = await chrome.storage.session.get(ACCESS_KEY);
  const value = stored[ACCESS_KEY];
  return typeof value === 'string' ? value : undefined;
}

export async function refreshToken(): Promise<string | undefined> {
  const value = await tx<unknown>('readonly', (s) => s.get('refresh'));
  return typeof value === 'string' ? value : undefined;
}

export async function clearTokens(): Promise<void> {
  await chrome.storage.session.remove(ACCESS_KEY);
  await tx('readwrite', (s) => s.delete('refresh'));
}
