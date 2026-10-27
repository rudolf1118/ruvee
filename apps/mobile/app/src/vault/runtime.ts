import {
  createApi,
  dispatch,
  errorPayload,
  VaultEngine,
  type OpaqueClient,
  type VaultErrorPayload,
  type VaultEvent,
  type VaultMethod,
  type VaultMethods,
} from '@ruvee/vault';
import { Platform } from 'react-native';
import { mobileRuveeCrypto } from '../crypto/ruvee-crypto';
import { mobileTransport, type MobileTransport } from '../platform/transport';
import { MobileDeviceStore } from '../storage/device-store';

/**
 * The shared vault engine (packages/vault), unchanged, with the mobile adapters:
 * crypto (src/crypto), the token transport, the SQLite + Keystore device store and an OPAQUE
 * client. The UI talks to it only through `call`, the same allow-listed `dispatch` the web
 * worker and the extension use, so it receives views and never keys.
 *
 * React Native has no worker isolation by default: the engine shares the JS heap with the UI.
 * The boundary is the dispatch surface, not a separate context (docs/mobile/storage-policy.md).
 */

export class VaultCallError extends Error {
  constructor(readonly payload: VaultErrorPayload) {
    super(payload.code);
    this.name = 'VaultCallError';
  }
}

export interface VaultRuntime {
  readonly origin: string;
  call<M extends VaultMethod>(
    method: M,
    ...params: Parameters<VaultMethods[M]> extends [] ? [] : Parameters<VaultMethods[M]>
  ): Promise<Awaited<ReturnType<VaultMethods[M]>>>;
  /** INV-15: zero the engine's keys now. The next unlock needs the master password. */
  lock(): void;
  /** After logout or revocation: also forget this server's tokens. */
  forgetTokens(): Promise<void>;
  close(): void;
}

export async function startVault(params: {
  origin: string;
  store: MobileDeviceStore;
  opaque: OpaqueClient;
  onEvent: (event: VaultEvent) => void;
}): Promise<VaultRuntime> {
  const transport: MobileTransport = mobileTransport(params.origin);
  const engine = new VaultEngine({
    crypto: mobileRuveeCrypto(),
    api: createApi(transport),
    store: params.store.asDeviceStore(),
    opaque: params.opaque,
    origin: params.origin,
    platform: Platform.OS === 'ios' ? 'ios' : 'android',
    now: () => Date.now(),
    emit: (event) => {
      params.onEvent(event);
    },
  });
  return {
    origin: params.origin,
    async call(method, ...rest) {
      try {
        return (await dispatch(engine, method, rest[0])) as never;
      } catch (error) {
        throw new VaultCallError(errorPayload(error));
      }
    },
    lock() {
      engine.wipeMemory();
    },
    forgetTokens: () => transport.clear(),
    close() {
      engine.wipeMemory();
    },
  };
}
