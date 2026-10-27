import type {
  ItemDraft,
  ItemSummary,
  SyncStatus,
  UnlockedVault,
  VaultErrorCode,
  VaultEvent,
} from '@ruvee/vault';
import { useCallback, useEffect, useRef, useState } from 'react';
import { AppState, type AppStateStatus } from 'react-native';
import { nativeOpaqueClient } from '../crypto/opaque-client';
import { MobileDeviceStore } from '../storage/device-store';
import { startVault, VaultCallError, type VaultRuntime } from './runtime';

/**
 * The app's state machine around the shared engine.
 *
 * Lock policy (sync-protocol.md §Memory and lock, D-10, docs/mobile/storage-policy.md):
 * - the app leaving the foreground locks at once (`background`); a brief `inactive` (a system
 *   dialog, the app switcher) only covers the screen;
 * - 15 minutes without a touch locks;
 * - a lock button locks;
 * - the session ending locks; revocation erases the local copy (the engine wipes the store) and
 *   forgets the tokens;
 * - a process that dies takes every key with it: keys live only in this process's memory, so a
 *   restart always starts locked.
 */

export type Screen =
  | { readonly name: 'boot' }
  | { readonly name: 'fatal'; readonly message: string }
  | { readonly name: 'server' }
  | { readonly name: 'signin' }
  | { readonly name: 'pair'; readonly username: string }
  | { readonly name: 'locked'; readonly username: string; readonly reason?: LockReason }
  | { readonly name: 'vault' }
  | { readonly name: 'revoked' };

export type LockReason = 'manual' | 'background' | 'idle' | 'session_expired' | 'logout';

const IDLE_LOCK_MS = 15 * 60_000;
const SYNC_INTERVAL_MS = 60_000;
const SERVER_SETTING = 'serverOrigin';

export class UiError extends Error {
  constructor(
    readonly code: VaultErrorCode,
    readonly retryAfterSeconds?: number,
  ) {
    super(code);
  }
}

function toUiError(error: unknown): UiError {
  if (error instanceof VaultCallError)
    return new UiError(error.payload.code, error.payload.retryAfterSeconds);
  return new UiError('internal');
}

export function useVaultApp() {
  const [screen, setScreen] = useState<Screen>({ name: 'boot' });
  const [items, setItems] = useState<readonly ItemSummary[]>([]);
  const [sync, setSync] = useState<SyncStatus | null>(null);
  const [notice, setNotice] = useState<UnlockedVault['sessionProblem'] | null>(null);
  const [covered, setCovered] = useState(false);
  const [origin, setOrigin] = useState<string | null>(null);
  const store = useRef<MobileDeviceStore | null>(null);
  const runtime = useRef<VaultRuntime | null>(null);
  const screenRef = useRef(screen);
  screenRef.current = screen;
  const lastTouch = useRef(Date.now());

  const clearVaultView = () => {
    setItems([]);
    setSync(null);
    setNotice(null);
  };

  /** True from the moment a vault view is shown until the next lock; events before it are stale. */
  const open = useRef(false);
  const onEvent = useCallback((event: VaultEvent) => {
    if (!open.current) return;
    if (event.event === 'items') setItems(event.items);
    else if (event.event === 'sync') setSync(event.status);
    else if (event.event === 'ended') {
      const current = runtime.current;
      open.current = false;
      runtime.current?.lock();
      clearVaultView();
      if (event.reason === 'device_revoked') {
        void current?.forgetTokens().catch(() => undefined);
        setScreen({ name: 'revoked' });
      } else
        setScreen((s) => ({
          name: 'locked',
          username: 'username' in s ? s.username : '',
          reason: 'session_expired',
        }));
    }
  }, []);

  const route = useCallback(async () => {
    const r = runtime.current;
    if (!r) {
      setScreen({ name: 'server' });
      return;
    }
    const phase = await r.call('phase');
    if (phase.phase === 'new') setScreen({ name: 'signin' });
    else if (phase.phase === 'pending') setScreen({ name: 'pair', username: phase.username });
    else setScreen({ name: 'locked', username: phase.username });
  }, []);

  const connect = useCallback(
    async (serverOrigin: string) => {
      const s = store.current;
      if (!s) return;
      runtime.current?.close();
      runtime.current = await startVault({
        origin: serverOrigin,
        store: s,
        opaque: nativeOpaqueClient(),
        onEvent,
      });
      setOrigin(serverOrigin);
    },
    [onEvent],
  );

  // ---- Boot ----
  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const s = await MobileDeviceStore.open();
        if (cancelled) return;
        store.current = s;
        const saved = await s.setting(SERVER_SETTING);
        if (saved) await connect(saved);
        await route();
      } catch (e) {
        // A crypto self-test failure lands here too: the vault never opens on primitives that
        // disagree with the web (src/crypto/ruvee-crypto.ts).
        setScreen({ name: 'fatal', message: e instanceof Error ? e.name : 'startup failed' });
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [connect, route]);

  const lock = useCallback((reason: LockReason) => {
    const r = runtime.current;
    if (!r) return;
    open.current = false;
    r.lock();
    clearVaultView();
    setScreen((s) =>
      s.name === 'vault' || s.name === 'locked'
        ? {
            name: 'locked',
            username: s.name === 'locked' ? s.username : lockedUser.current,
            reason,
          }
        : s.name === 'pair'
          ? { name: 'pair', username: s.username }
          : s,
    );
  }, []);
  const lockedUser = useRef('');

  // ---- Lifecycle: background locks, inactive covers, idle locks, foreground syncs ----
  useEffect(() => {
    const sub = AppState.addEventListener('change', (state: AppStateStatus) => {
      setCovered(state !== 'active');
      if (
        state === 'background' &&
        (screenRef.current.name === 'vault' || screenRef.current.name === 'pair')
      )
        lock('background');
    });
    const timer = setInterval(() => {
      if (screenRef.current.name === 'vault' && Date.now() - lastTouch.current >= IDLE_LOCK_MS)
        lock('idle');
    }, 15_000);
    return () => {
      sub.remove();
      clearInterval(timer);
    };
  }, [lock]);

  useEffect(() => {
    if (screen.name !== 'vault') return;
    const timer = setInterval(() => {
      if (AppState.currentState === 'active')
        void runtime.current?.call('sync').then(setSync, () => undefined);
    }, SYNC_INTERVAL_MS);
    return () => {
      clearInterval(timer);
    };
  }, [screen.name]);

  const opened = (vault: UnlockedVault) => {
    open.current = true;
    lockedUser.current = vault.username;
    setItems(vault.items);
    setSync(vault.sync);
    setNotice(vault.sessionProblem ?? null);
    lastTouch.current = Date.now();
    setScreen({ name: 'vault' });
  };

  const call = useCallback(async <T>(run: (r: VaultRuntime) => Promise<T>): Promise<T> => {
    const r = runtime.current;
    if (!r) throw new UiError('internal');
    try {
      return await run(r);
    } catch (e) {
      throw toUiError(e);
    }
  }, []);

  return {
    screen,
    items,
    sync,
    notice,
    covered,
    origin,
    touched: () => {
      lastTouch.current = Date.now();
    },
    async setServer(serverOrigin: string) {
      await store.current?.putSetting(SERVER_SETTING, serverOrigin);
      await connect(serverOrigin);
      await route();
    },
    async changeServer() {
      // Only before this device holds an account: an enrolled device stays with its server.
      const phase = await call((r) => r.call('phase'));
      if (phase.phase !== 'new') return;
      await store.current?.putSetting(SERVER_SETTING, null);
      runtime.current?.close();
      runtime.current = null;
      setOrigin(null);
      setScreen({ name: 'server' });
    },
    async signIn(username: string, password: string) {
      const phase = await call((r) => r.call('login', { username, password }));
      if (phase.phase === 'enrolled') setScreen({ name: 'locked', username: phase.username });
      else if (phase.phase === 'pending') setScreen({ name: 'pair', username: phase.username });
    },
    needsPairingPassword: () => call((r) => r.call('pairingNeedsPassword')),
    async joinPairing(code: string, password?: string) {
      await call((r) => r.call('pairingJoin', password ? { code, password } : { code }));
    },
    /** One poll; true once this device is enrolled and the vault is open. */
    async pairingStep(): Promise<boolean> {
      const status = await call((r) => r.call('pairingWait'));
      if (status.state !== 'enrolled') return false;
      opened(status.vault);
      return true;
    },
    async unlock(password: string, previousPassword?: string) {
      const vault = await call((r) =>
        r.call('unlock', previousPassword ? { password, previousPassword } : { password }),
      );
      opened(vault);
    },
    lock: () => {
      lock('manual');
    },
    async logout() {
      await call((r) => r.call('logout'));
      await runtime.current?.forgetTokens();
      lock('logout');
    },
    async syncNow() {
      setSync(await call((r) => r.call('sync')));
    },
    detail: (id: string) => call((r) => r.call('detail', { id })),
    secret: (id: string) => call((r) => r.call('secret', { id })),
    conflict: (id: string) => call((r) => r.call('conflict', { id })),
    async resolveConflict(id: string, choice: 'mine' | 'theirs' | 'both') {
      await call((r) => r.call('resolveConflict', { id, choice }));
      setItems(await call((r) => r.call('items')));
    },
    async save(draft: ItemDraft) {
      const summary = await call((r) => r.call('save', { draft }));
      setItems(await call((r) => r.call('items')));
      return summary;
    },
    async startAgain() {
      setScreen({ name: 'signin' });
    },
  };
}

export type VaultApp = ReturnType<typeof useVaultApp>;
