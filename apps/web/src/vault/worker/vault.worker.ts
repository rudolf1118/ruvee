import '../zod-config';
import { initRuveeCrypto } from '@ruvee/crypto';
import * as opaque from '@serenity-kit/opaque';
import type { VaultErrorPayload, VaultMethod, VaultRequest, VaultResponse } from '../protocol';
import { api } from './api';
import { DeviceStore } from './store';
import { VaultEngine, VaultError, type OpaqueClient } from './vault-engine';

/**
 * The vault worker: the only place that holds `SK`, `AK`, `VK` and item plaintext beyond what the
 * UI displays. Locking terminates it, which releases its memory and the WebAssembly heaps
 * (sync-protocol §Memory and lock).
 */

/** D-02: fixed on every client; registration and login must use the same preset. */
const KEY_STRETCHING = 'memory-constrained' as const;

const opaqueClient: OpaqueClient = {
  startRegistration: (password) => opaque.client.startRegistration({ password }),
  finishRegistration: (state, response, password) =>
    opaque.client.finishRegistration({
      clientRegistrationState: state,
      registrationResponse: response,
      password,
      keyStretching: KEY_STRETCHING,
    }).registrationRecord,
  startLogin: (password) => opaque.client.startLogin({ password }),
  finishLogin: (state, response, password) =>
    opaque.client.finishLogin({
      clientLoginState: state,
      loginResponse: response,
      password,
      keyStretching: KEY_STRETCHING,
    })?.finishLoginRequest,
};

let engine: Promise<VaultEngine> | undefined;

function getEngine(): Promise<VaultEngine> {
  engine ??= (async () => {
    const [crypto] = await Promise.all([initRuveeCrypto(), opaque.ready]);
    const store = await DeviceStore.open();
    return new VaultEngine({
      crypto,
      api,
      store,
      opaque: opaqueClient,
      origin: self.location.origin,
      now: () => Date.now(),
      emit: (event) => {
        self.postMessage(event);
      },
    });
  })();
  return engine;
}

type Handler = (engine: VaultEngine, params: never) => unknown;

/** The methods the UI may call; anything else is refused. */
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
  endSession: (e, p: Parameters<VaultEngine['endSession']>[0]) => e.endSession(p),
  revokeDevice: (e, p: Parameters<VaultEngine['revokeDevice']>[0]) => e.revokeDevice(p),
  changePassword: (e, p: Parameters<VaultEngine['changePassword']>[0]) => e.changePassword(p),
  rotateSecretKey: (e, p: Parameters<VaultEngine['rotateSecretKey']>[0]) => e.rotateSecretKey(p),
  logout: (e) => e.logout(),
  wipe: (e) => {
    e.wipeMemory();
    return true;
  },
};

function errorPayload(error: unknown): VaultErrorPayload {
  if (error instanceof VaultError)
    return error.retryAfterSeconds === undefined
      ? { code: error.code }
      : { code: error.code, retryAfterSeconds: error.retryAfterSeconds };
  // Nothing else leaves the worker: library errors could describe inputs.
  return { code: 'internal' };
}

self.onmessage = (event: MessageEvent<VaultRequest>) => {
  const { id, method, params } = event.data;
  const handler = Object.hasOwn(HANDLERS, method) ? HANDLERS[method] : undefined;
  const reply = (response: VaultResponse) => {
    self.postMessage(response);
  };
  if (!handler) {
    reply({ id, ok: false, error: { code: 'internal' } });
    return;
  }
  void getEngine()
    .then((e) => handler(e, params as never))
    .then(
      (result) => {
        reply({ id, ok: true, result });
      },
      (error: unknown) => {
        reply({ id, ok: false, error: errorPayload(error) });
      },
    );
};
