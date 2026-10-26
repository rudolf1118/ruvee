'use client';

import '@/vault/zod-config';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { DevicePhase, ItemDetail, ItemSummary, SyncStatus, UnlockedVault } from '@ruvee/vault';
import { VaultClient, VaultClientError } from '@/vault/client';
import { messageFor } from './messages';
import { DevicesIcon, InfoIcon, LogoutIcon } from '../ui/icons';
import { NavButton } from '../vault/sidebar';
import { VaultShell } from '../vault/vault-shell';
import { AuthCard } from './auth-layout';
import { clearClipboard } from './clipboard';
import { LockScreen, LoginScreen, WelcomeScreen } from './entry-screens';
import { ActivityPanel } from './activity';
import { ExportViewer } from './export';
import { DevicesPanel, SecurityPanel } from './devices';
import { needsRestoreHelp, restoreExplanation, RestoreHelpSection } from './restore-help';
import { ItemEditor } from './item-editor';
import { LiveItemDetail } from './live-item-detail';
import { AddDevicePanel } from './pairing';
import { PendingDeviceScreen } from './pending-device';
import { RecoveryFlow, type RecoveryMode } from './recovery-flow';
import { Notice } from './fields';
import { Button } from '../ui/button';
import { relativeTime } from './view-model';
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
  | { name: 'recovery'; username?: string; mode?: RecoveryMode; back: Screen }
  | { name: 'export-viewer' }
  | { name: 'restore-setup' }
  | { name: 'unlocked'; vault: UnlockedVault; startImport?: boolean };

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
          onRecover={() => {
            setScreen({ name: 'recovery', back: screen });
          }}
          onOpenExport={() => {
            setScreen({ name: 'export-viewer' });
          }}
          onReopen={() => {
            setScreen({ name: 'recovery', mode: 'reopen-kit', back: screen });
          }}
        />
      );
    case 'export-viewer':
      return (
        <ExportViewer
          client={client}
          onClose={() => {
            setScreen({ name: 'welcome' });
          }}
          onRestore={() => {
            // The opened export stays in the worker for the import after setup.
            setScreen({ name: 'restore-setup' });
          }}
        />
      );
    case 'restore-setup':
      return (
        <SetupFlow
          client={client}
          restoring
          onCancel={() => {
            void client.call('exportClose');
            setScreen({ name: 'welcome' });
          }}
          onDone={(vault) => {
            setScreen({ name: 'unlocked', vault, startImport: true });
          }}
        />
      );
    case 'recovery':
      return (
        <RecoveryFlow
          client={client}
          {...(screen.username ? { initialUsername: screen.username } : {})}
          {...(screen.mode ? { mode: screen.mode } : {})}
          onCancel={() => {
            setScreen(screen.back);
          }}
          onDone={(vault) => {
            setScreen({ name: 'unlocked', vault });
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
          onRecover={() => {
            setScreen({ name: 'recovery', username: screen.username, back: screen });
          }}
        />
      );
    case 'unlocked':
      return (
        <UnlockedApp
          key={screen.vault.deviceId}
          client={client}
          vault={screen.vault}
          startImport={screen.startImport ?? false}
          onLock={(notice) => {
            void lock(screen.vault.username, notice);
          }}
          onReopen={() => {
            setScreen({
              name: 'recovery',
              mode: 'reopen-password',
              username: screen.vault.username,
              back: screen,
            });
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
  startImport,
  onLock,
  onReopen,
}: {
  client: VaultClient;
  vault: UnlockedVault;
  startImport: boolean;
  onLock: (notice?: string) => void;
  /** The restored server waits to be reopened: the password path on this device (§3.13). */
  onReopen: () => void;
}) {
  const [items, setItems] = useState<readonly ItemSummary[]>(vault.items);
  const [status, setStatus] = useState<SyncStatus>(vault.sync);
  const [editing, setEditing] = useState<{ existing: ItemDetail | null } | null>(null);
  const [panel, setPanel] = useState<'devices' | 'add-device' | 'password' | 'activity' | null>(
    null,
  );
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

  // After "Restore into a new account": the export opened before setup is imported now.
  const [importError, setImportError] = useState<string | null>(null);
  const importStarted = useRef(false);
  useEffect(() => {
    if (!startImport || importStarted.current) return;
    importStarted.current = true;
    client.call('importIntoEmptyVault').then(setStatus, (e: unknown) => {
      setImportError(
        e instanceof VaultClientError
          ? messageFor(e.code, e.retryAfterSeconds)
          : messageFor('internal'),
      );
    });
  }, [client, startImport]);

  const views = useMemo(() => items.map(toView), [items]);
  const [dismissed, setDismissed] = useState<readonly string[]>([]);
  const notices = [
    ...vaultNotices(vault, status),
    ...(importError
      ? [
          {
            id: 'import-error',
            tone: 'caution' as const,
            text: `The import did not start. ${importError}`,
          },
        ]
      : []),
  ].filter((n) => !dismissed.includes(n.id));
  const byId = useMemo(() => new Map(items.map((i) => [i.id, i])), [items]);
  const readOnly =
    status.state === 'integrity_error' ||
    status.state === 'maintenance' ||
    status.state === 'reopening';
  const restoreHelp = needsRestoreHelp(status, vault.sessionProblem);

  return (
    <VaultShell
      items={views}
      vaults={[PERSONAL_VAULT]}
      banner={
        notices.length > 0 ? (
          <div className="flex flex-col gap-2 border-b border-line bg-canvas px-4 py-3">
            {notices.map((n) => (
              <Notice key={n.id} tone={n.tone}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span>{n.text}</span>
                  {n.id === 'reopen' ? (
                    <Button size="sm" variant="primary" onClick={onReopen}>
                      Reopen the server
                    </Button>
                  ) : null}
                  {n.id === 'restore' ? (
                    <Button
                      size="sm"
                      onClick={() => {
                        setEditing(null);
                        setPanel('password');
                      }}
                    >
                      What to do
                    </Button>
                  ) : null}
                  {n.id === 'recovered' ? (
                    <Button
                      size="sm"
                      onClick={() => {
                        setEditing(null);
                        setPanel('devices');
                      }}
                    >
                      Review devices
                    </Button>
                  ) : null}
                  <Button
                    size="sm"
                    onClick={() => {
                      setDismissed((d) => [...d, n.id]);
                      if (n.id === 'recovery-used') void client.call('acknowledgeRecoveryNotice');
                    }}
                  >
                    Dismiss
                  </Button>
                </div>
              </Notice>
            ))}
          </div>
        ) : undefined
      }
      live={{
        onAddItem: () => {
          if (readOnly) return;
          setPanel(null);
          setEditing({ existing: null });
        },
        onLock: () => {
          onLock();
        },
        statusPanel: <SyncPanel status={status} onSync={syncNow} />,
        security: {
          current: panel === 'password',
          onSelect: () => {
            setEditing(null);
            setPanel('password');
          },
        },
        extraNav: (
          <>
            <NavButton
              icon={DevicesIcon}
              label="Devices"
              current={panel === 'devices' || panel === 'add-device'}
              onSelect={() => {
                setEditing(null);
                setPanel('devices');
              }}
            />
            <NavButton
              icon={InfoIcon}
              label="Activity"
              current={panel === 'activity'}
              onSelect={() => {
                setEditing(null);
                setPanel('activity');
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
        ...(panel
          ? {
              detailOverride:
                panel === 'add-device' ? (
                  <AddDevicePanel
                    client={client}
                    onClose={() => {
                      setPanel(null);
                    }}
                  />
                ) : panel === 'activity' ? (
                  <ActivityPanel
                    client={client}
                    onClose={() => {
                      setPanel(null);
                    }}
                  />
                ) : panel === 'devices' ? (
                  <DevicesPanel
                    client={client}
                    onClose={() => {
                      setPanel(null);
                    }}
                    onAddDevice={() => {
                      setPanel('add-device');
                    }}
                    onChangePassword={() => {
                      setPanel('password');
                    }}
                  />
                ) : (
                  <SecurityPanel
                    client={client}
                    // A hint only: the worker refuses any vault that ever held an item.
                    canImport={items.length === 0 && status.import === undefined}
                    restoreHelp={
                      restoreHelp ? (
                        <RestoreHelpSection
                          client={client}
                          status={status}
                          {...(vault.sessionProblem
                            ? { sessionProblem: vault.sessionProblem }
                            : {})}
                          onErased={() => {
                            onLock('This device was erased. Log in to start over.');
                          }}
                        />
                      ) : undefined
                    }
                    onClose={() => {
                      setPanel(null);
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

interface VaultNotice {
  readonly id: string;
  readonly tone: 'caution' | 'brand';
  readonly text: string;
}

const plural = (n: number, one: string, many: string) => `${String(n)} ${n === 1 ? one : many}`;

/** What the user must know right after unlocking (account-recovery.md §3, authentication.md §9). */
function vaultNotices(vault: UnlockedVault, status: SyncStatus): VaultNotice[] {
  const out: VaultNotice[] = [];
  if (vault.recovered) {
    const last = vault.recovered.lastChange;
    const where = last
      ? `the last change was ${relativeTime(last.atMs)} on ${last.byThisDevice ? 'this' : 'another'} device.`
      : 'it has no changes yet.';
    const kept = vault.recovered.keptLocal;
    const earlier = kept
      ? `This browser kept its own copy of your vault${
          kept.pending + kept.conflicts > 0
            ? `, including ${[
                kept.pending > 0
                  ? plural(kept.pending, 'change', 'changes') + ' not yet uploaded'
                  : '',
                kept.conflicts > 0 ? plural(kept.conflicts, 'conflict', 'conflicts') : '',
              ]
                .filter(Boolean)
                .join(' and ')}`
            : ''
        }; ${where}`
      : `This device had no earlier record of your vault, so check that it looks current: ${where}`;
    out.push({
      id: 'recovered',
      tone: 'brand',
      text: `Recovery is complete. ${earlier} If you lost devices, they still hold a copy of your vault and your Secret Key: remove them as lost under Devices, which also replaces your Secret Key.`,
    });
  }
  if (status.recoveryUsedAtMs !== undefined)
    out.push({
      id: 'recovery-used',
      tone: 'caution',
      text: `Your Recovery Kit was used ${relativeTime(status.recoveryUsedAtMs)}. If that wasn't you, someone else has your kit and can open your vault.`,
    });
  if (vault.reopened)
    out.push({
      id: 'reopened',
      tone: 'brand',
      text: 'The server is open again, with your new master password and Recovery Kit. If a device was lost, also replace your Secret Key in Security.',
    });
  if (vault.passwordUpdated)
    out.push({
      id: 'password-updated',
      tone: 'brand',
      text: 'Your master password was changed on another device. This device now uses the new one.',
    });
  if (vault.secretKeyUpdated)
    out.push({
      id: 'secret-key-updated',
      tone: 'brand',
      text: 'Your Secret Key was replaced on another device. This device now uses the new one.',
    });
  if (status.import?.state === 'uploading')
    out.push({
      id: `import-uploading-${String(status.import.uploaded)}`,
      tone: 'caution',
      text: `Importing your export: ${String(status.import.uploaded)} of ${String(status.import.total)} items are on the server. It continues by itself while this tab is open, and after the next unlock if it stops.`,
    });
  if (status.import?.state === 'complete')
    out.push({
      id: 'import-complete',
      tone: 'brand',
      text: `Import complete: all ${String(status.import.total)} items from the export of ${new Date(status.import.sourceAsOfMs).toLocaleString()} are in this vault.`,
    });
  if (status.state === 'reopening')
    out.push({
      id: 'reopen',
      tone: 'caution',
      text: restoreExplanation(status, vault.sessionProblem),
    });
  else if (needsRestoreHelp(status, vault.sessionProblem))
    out.push({
      id: 'restore',
      tone: 'caution',
      text: restoreExplanation(status, vault.sessionProblem),
    });
  if (vault.sessionProblem === 'login_failed')
    out.push({
      id: 'login-failed',
      tone: 'caution',
      text: "This device opened its local copy but couldn't sign in, so it won't sync. If your password was changed on another device, lock and unlock with the new one.",
    });
  return out;
}
