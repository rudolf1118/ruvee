import type { VaultErrorPayload, VaultMethod } from './protocol.js';
import { VaultError, type VaultEngine } from './vault-engine.js';

type Handler = (engine: VaultEngine, params: never) => unknown;

/**
 * The one list of engine methods a UI may call, shared by the web worker and the extension
 * service worker. Anything else is refused.
 */
const HANDLERS: Record<VaultMethod, Handler> = {
  phase: (e) => e.phase(),
  setupBegin: (e, p: Parameters<VaultEngine['setupBegin']>[0]) => e.setupBegin(p),
  setupVerifyKit: (e, p: Parameters<VaultEngine['setupVerifyKit']>[0]) => e.setupVerifyKit(p),
  setupFinish: (e) => e.setupFinish(),
  login: (e, p: Parameters<VaultEngine['login']>[0]) => e.login(p),
  unlock: (e, p: Parameters<VaultEngine['unlock']>[0]) => e.unlock(p),
  items: (e) => e.items(),
  detail: (e, p: Parameters<VaultEngine['detail']>[0]) => e.detail(p),
  secret: (e, p: Parameters<VaultEngine['secret']>[0]) => e.secret(p),
  save: (e, p: Parameters<VaultEngine['save']>[0]) => e.save(p),
  setFavorite: (e, p: Parameters<VaultEngine['setFavorite']>[0]) => e.setFavorite(p),
  trash: (e, p: Parameters<VaultEngine['trash']>[0]) => e.trash(p),
  restore: (e, p: Parameters<VaultEngine['restore']>[0]) => e.restore(p),
  purge: (e, p: Parameters<VaultEngine['purge']>[0]) => e.purge(p),
  conflict: (e, p: Parameters<VaultEngine['conflict']>[0]) => e.conflict(p),
  resolveConflict: (e, p: Parameters<VaultEngine['resolveConflict']>[0]) => e.resolveConflict(p),
  sync: (e) => e.sync(),
  pairingStart: (e) => e.pairingStart(),
  pairingStatus: (e, p: Parameters<VaultEngine['pairingStatus']>[0]) => e.pairingStatus(p),
  pairingApprove: (e, p: Parameters<VaultEngine['pairingApprove']>[0]) => e.pairingApprove(p),
  pairingCancel: (e, p: Parameters<VaultEngine['pairingCancel']>[0]) => e.pairingCancel(p),
  pairingNeedsPassword: (e) => e.pairingNeedsPassword(),
  pairingJoin: (e, p: Parameters<VaultEngine['pairingJoin']>[0]) => e.pairingJoin(p),
  pairingWait: (e) => e.pairingWait(),
  recoveryBegin: (e, p: Parameters<VaultEngine['recoveryBegin']>[0]) => e.recoveryBegin(p),
  recoverySetPassword: (e, p: Parameters<VaultEngine['recoverySetPassword']>[0]) =>
    e.recoverySetPassword(p),
  recoveryVerifyKit: (e, p: Parameters<VaultEngine['recoveryVerifyKit']>[0]) =>
    e.recoveryVerifyKit(p),
  recoveryFinish: (e) => e.recoveryFinish(),
  acknowledgeRecoveryNotice: (e) => e.acknowledgeRecoveryNotice(),
  devices: (e) => e.devices(),
  activity: (e, p: Parameters<VaultEngine['activity']>[0]) => e.activity(p),
  endSession: (e, p: Parameters<VaultEngine['endSession']>[0]) => e.endSession(p),
  revokeDevice: (e, p: Parameters<VaultEngine['revokeDevice']>[0]) => e.revokeDevice(p),
  changePassword: (e, p: Parameters<VaultEngine['changePassword']>[0]) => e.changePassword(p),
  rotateSecretKey: (e, p: Parameters<VaultEngine['rotateSecretKey']>[0]) => e.rotateSecretKey(p),
  kitRotateBegin: (e) => e.kitRotateBegin(),
  kitRotateVerify: (e, p: Parameters<VaultEngine['kitRotateVerify']>[0]) => e.kitRotateVerify(p),
  kitRotateFinish: (e, p: Parameters<VaultEngine['kitRotateFinish']>[0]) => e.kitRotateFinish(p),
  kitRotateCancel: (e) => e.kitRotateCancel(),
  exportVault: (e, p: Parameters<VaultEngine['exportVault']>[0]) => e.exportVault(p),
  exportOpen: (e, p: Parameters<VaultEngine['exportOpen']>[0]) => e.exportOpen(p),
  exportSecret: (e, p: Parameters<VaultEngine['exportSecret']>[0]) => e.exportSecret(p),
  exportClose: (e) => e.exportClose(),
  logout: (e) => e.logout(),
  wipe: (e) => {
    e.wipeMemory();
    return true;
  },
};

export function errorPayload(error: unknown): VaultErrorPayload {
  if (error instanceof VaultError)
    return error.retryAfterSeconds === undefined
      ? { code: error.code }
      : { code: error.code, retryAfterSeconds: error.retryAfterSeconds };
  // Nothing else leaves the worker: library errors could describe inputs.
  return { code: 'internal' };
}

/** Runs an allow-listed method; unknown names fail like any other error. */
export function dispatch(engine: VaultEngine, method: string, params: unknown): Promise<unknown> {
  const handler = Object.hasOwn(HANDLERS, method) ? HANDLERS[method as VaultMethod] : undefined;
  if (!handler) return Promise.reject(new VaultError('internal'));
  // Through a promise, so a handler that throws synchronously is reported the same way.
  return Promise.resolve().then(() => handler(engine, params as never));
}
