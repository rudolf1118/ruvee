import '../zod-config';
import { initRuveeCrypto } from '@ruvee/crypto';
import {
  createApi,
  DeviceStore,
  dispatch,
  errorPayload,
  SAME_ORIGIN,
  VaultEngine,
  type OpaqueClient,
  type VaultRequest,
  type VaultResponse,
} from '@ruvee/vault';
import * as opaque from '@serenity-kit/opaque';

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
  // A failed start is not cached: the next request tries again (follow-up review F-5).
  engine ??= (async () => {
    const [crypto] = await Promise.all([initRuveeCrypto(), opaque.ready]);
    const store = await DeviceStore.open();
    return new VaultEngine({
      crypto,
      api: createApi(SAME_ORIGIN),
      platform: 'web',
      store,
      opaque: opaqueClient,
      origin: self.location.origin,
      now: () => Date.now(),
      emit: (event) => {
        self.postMessage(event);
      },
    });
  })().catch((error: unknown) => {
    engine = undefined;
    throw error;
  });
  return engine;
}

self.onmessage = (event: MessageEvent<VaultRequest>) => {
  const { id, method, params } = event.data;
  const reply = (response: VaultResponse) => {
    self.postMessage(response);
  };
  void getEngine()
    .then((e) => dispatch(e, method, params))
    .then(
      (result) => {
        reply({ id, ok: true, result });
      },
      (error: unknown) => {
        reply({ id, ok: false, error: errorPayload(error) });
      },
    );
};
