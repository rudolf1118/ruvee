'use client';

import '@/vault/zod-config';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type {
  DevicePhase,
  ItemDetail,
  ItemSummary,
  SyncStatus,
  UnlockedVault,
} from '@/vault/protocol';
import { VaultClient } from '@/vault/client';
import { DevicesIcon, LogoutIcon } from '../ui/icons';
import { NavButton } from '../vault/sidebar';
import { VaultShell } from '../vault/vault-shell';
import { AuthCard } from './auth-layout';
import { clearClipboard } from './clipboard';
import { LockScreen, LoginScreen, WelcomeScreen } from './entry-screens';
import { ItemEditor } from './item-editor';
import { LiveItemDetail } from './live-item-detail';
import { AddDevicePanel } from './pairing';
import { PendingDeviceScreen } from './pending-device';
import { SetupFlow } from './setup-flow';
import { SyncPanel } from './sync-panel';
import { PERSONAL_VAULT, toView } from './view-model';

/** D-10, approved for development: lock after 15 minutes without interaction. */
export const AUTO_LOCK_MS = 15 * 60_000;
/** While unlocked and visible, pull changes this often when there is no push channel yet. */
const POLL_MS = 60_000;

type Screen =
  | { name: 'starting' }
  | { name: 'unsupported' }
  | { name: 'welcome' }
  | { name: 'setup' }
  | { name: 'login' }
  | { name: 'pending'; username: string }
  | { name: 'locked'; username: string; notice?: string }
  | { name: 'unlocked'; vault: UnlockedVault };

function supported(): boolean {
  return (
    typeof Worker !== 'undefined' &&
    typeof indexedDB !== 'undefined' &&
    typeof WebAssembly !== 'undefined' &&
    typeof globalThis.crypto.getRandomValues === 'function'
  );
}

function screenFor(phase: DevicePhase): Screen {
  if (phase.phase === 'new') return { name: 'welcome' };
  if (phase.phase === 'pending') return { name: 'pending', username: phase.username };
  return { name: 'locked', username: phase.username };
}

export function VaultApp() {
  const [screen, setScreen] = useState<Screen>(() =>
    typeof window === 'undefined' || supported() ? { name: 'starting' } : { name: 'unsupported' },
  );
  const clientRef = useRef<VaultClient | null>(null);
  const [client, setClient] = useState<VaultClient | null>(null);

  const freshClient = useCallback(() => {
    clientRef.current?.terminate();
    const next = new VaultClient();
    clientRef.current = next;
    setClient(next);
    return next;
  }, []);

  useEffect(() => {
    if (!supported()) return;
    const c = new VaultClient();
    clientRef.current = c;
    void c.call('phase').then(
      (phase) => {
        setClient(c);
        setScreen(screenFor(phase));
      },
      () => {
        setScreen({ name: 'unsupported' });
      },
    );
    return () => {
      clientRef.current?.terminate();
    };
  }, []);

  /** INV-15: drop every key and plaintext, then show the unlock screen with a new worker. */
  const lock = useCallback(
    async (username: string, notice?: string) => {
      await clearClipboard();
      await clientRef.current?.lock();
      const c = freshClient();
      const phase = await c.call('phase').catch(() => ({ phase: 'new' }) as const);
      setScreen(
        phase.phase === 'enrolled'
          ? { name: 'locked', username, ...(notice ? { notice } : {}) }
          : screenFor(phase),
      );
    },
    [freshClient],
  );

  if (screen.name === 'starting' || (!client && screen.name !== 'unsupported'))
    return <main className="min-h-dvh" aria-busy="true" />;

  switch (screen.name) {
    case 'unsupported':
      return (
        <AuthCard title="This browser can't run Ruvee">
          <p className="text-body text-ink-muted">
            Ruvee needs Web Workers, IndexedDB and WebAssembly. Private browsing modes sometimes
            disable them. Try a current version of Chrome, Firefox or Safari in a normal window.
          </p>
        </AuthCard>
      );
    default:
      break;
  }
  if (!client) return null;
  switch (screen.name) {
    case 'welcome':
      return (
        <WelcomeScreen
          onCreate={() => {
            setScreen({ name: 'setup' });
          }}
          onLogin={() => {
            setScreen({ name: 'login' });
          }}
        />
      );
    case 'setup':
      return (
        <SetupFlow
          client={client}
          onCancel={() => {
            setScreen({ name: 'welcome' });
          }}
          onDone={(vault) => {
            setScreen({ name: 'unlocked', vault });
          }}
        />
      );
    case 'login':
      return (
        <LoginScreen
          client={client}
          onBack={() => {
            setScreen({ name: 'welcome' });
          }}
          onPhase={(phase) => {
            setScreen(screenFor(phase));
          }}
        />
      );
    case 'pending':
      return (
        <PendingDeviceScreen
          client={client}
          username={screen.username}
          onEnrolled={(vault) => {
            setScreen({ name: 'unlocked', vault });
          }}
        />
      );
    case 'locked':
      return (
        <LockScreen
          client={client}
          username={screen.username}
          notice={screen.notice ?? null}
          onUnlocked={(vault) => {
            setScreen({ name: 'unlocked', vault });
          }}
        />
      );
    case 'unlocked':
      return (
        <UnlockedApp
          key={screen.vault.deviceId}
          client={client}
          vault={screen.vault}
          onLock={(notice) => {
            void lock(screen.vault.username, notice);
          }}
        />
      );
    default:
      return null;
  }
}

function UnlockedApp({
  client,
  vault,
  onLock,
}: {
  client: VaultClient;
  vault: UnlockedVault;
  onLock: (notice?: string) => void;
}) {
  const [items, setItems] = useState<readonly ItemSummary[]>(vault.items);
  const [status, setStatus] = useState<SyncStatus>(vault.sync);
  const [editing, setEditing] = useState<{ existing: ItemDetail | null } | null>(null);
  const [addingDevice, setAddingDevice] = useState(false);
  const [selectId, setSelectId] = useState<string | null>(null);
  const [version, setVersion] = useState(0);
  const lastActivity = useRef(0);
  const onLockRef = useRef(onLock);
  useEffect(() => {
    onLockRef.current = onLock;
  }, [onLock]);

  useEffect(
    () =>
      client.subscribe((event) => {
        if (event.event === 'items') {
          setItems(event.items);
          setVersion((v) => v + 1);
        } else if (event.event === 'sync') setStatus(event.status);
        else
          onLockRef.current(
            event.reason === 'device_revoked'
              ? 'This device was removed from your account, and its local copy was erased.'
              : 'Your session ended. Unlock to sign in again.',
          );
      }),
    [client],
  );

  const refresh = useCallback(() => {
    void client.call('items').then((next) => {
      setItems(next);
      setVersion((v) => v + 1);
    });
  }, [client]);

  const syncNow = useCallback(() => {
    void client.call('sync').then(setStatus, () => undefined);
  }, [client]);

  // Auto-lock on inactivity (D-10), and polling while visible (sync-protocol §9 fallback).
  useEffect(() => {
    const touch = () => {
      lastActivity.current = Date.now();
    };
    touch();
    const events = ['pointerdown', 'keydown', 'wheel', 'touchstart'] as const;
    for (const e of events) window.addEventListener(e, touch, { passive: true });
    const timer = setInterval(() => {
      if (Date.now() - lastActivity.current >= AUTO_LOCK_MS) onLockRef.current();
    }, 5_000);
    const poll = setInterval(() => {
      if (document.visibilityState === 'visible') syncNow();
    }, POLL_MS);
    const onFocus = () => {
      syncNow();
    };
    window.addEventListener('focus', onFocus);
    return () => {
      for (const e of events) window.removeEventListener(e, touch);
      clearInterval(timer);
      clearInterval(poll);
      window.removeEventListener('focus', onFocus);
    };
  }, [syncNow]);

  const views = useMemo(() => items.map(toView), [items]);
  const byId = useMemo(() => new Map(items.map((i) => [i.id, i])), [items]);
  const readOnly = status.state === 'integrity_error';

  return (
    <VaultShell
      items={views}
      vaults={[PERSONAL_VAULT]}
      live={{
        onAddItem: () => {
          if (readOnly) return;
          setAddingDevice(false);
          setEditing({ existing: null });
        },
        onLock: () => {
          onLock();
        },
        statusPanel: <SyncPanel status={status} onSync={syncNow} />,
        extraNav: (
          <>
            <NavButton
              icon={DevicesIcon}
              label="Add a device"
              current={addingDevice}
              onSelect={() => {
                setEditing(null);
                setAddingDevice(true);
              }}
            />
            <NavButton
              icon={LogoutIcon}
              label="Log out"
              current={false}
              onSelect={() => {
                void client.call('logout').finally(() => {
                  onLock('You logged out. Unlock to sign in again.');
                });
              }}
            />
          </>
        ),
        rowBadge: (item) => {
          const summary = byId.get(item.id);
          if (summary?.conflict) return 'Changed on two devices';
          if (summary?.pending) return 'Waiting to sync';
          return null;
        },
        selectId,
        renderDetail: (item, context) => (
          <LiveItemDetail
            key={item.id}
            client={client}
            itemId={item.id}
            version={version}
            readOnly={readOnly}
            headingRef={context.headingRef}
            vaultName={context.vaultName}
            onBack={context.onBack}
            onTag={context.onTag}
            onEdit={(existing) => {
              setEditing({ existing });
            }}
            onChanged={refresh}
          />
        ),
        ...(addingDevice
          ? {
              detailOverride: (
                <AddDevicePanel
                  client={client}
                  onClose={() => {
                    setAddingDevice(false);
                  }}
                />
              ),
            }
          : editing
            ? {
                detailOverride: (
                  <ItemEditor
                    key={editing.existing?.id ?? 'new'}
                    client={client}
                    existing={editing.existing}
                    onCancel={() => {
                      setEditing(null);
                    }}
                    onSaved={(saved) => {
                      setEditing(null);
                      setSelectId(saved.id);
                      refresh();
                    }}
                  />
                ),
              }
            : {}),
      }}
    />
  );
}
