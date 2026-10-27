import type { OpaqueClient } from '@ruvee/vault';
import { NativeModules } from 'react-native';

/**
 * The engine's OPAQUE client (D-02) over the app's native binding of opaque-ke 4.0.1
 * (native/opaque, android/.../opaque/OpaqueModule.kt). Same calls and results as the
 * @serenity-kit/opaque wrapper in the extension's service worker; the "memory-constrained"
 * key stretching is fixed in the binding, not chosen here or by the server.
 *
 * Interoperability with @serenity-kit/opaque 1.1.0 is checked on the host by
 * scripts/opaque-interop.mjs and on the device by every login against the real API.
 */
interface NativeOpaque {
  startRegistration(password: string): { state: string; request: string };
  finishRegistration(state: string, response: string, password: string): string;
  startLogin(password: string): { state: string; request: string };
  finishLogin(state: string, response: string, password: string): string | null;
}

function binding(): NativeOpaque {
  const native = (NativeModules as { RuveeOpaque?: NativeOpaque }).RuveeOpaque;
  if (!native) throw new Error('OPAQUE binding is not available');
  return native;
}

export function nativeOpaqueClient(): OpaqueClient {
  const native = binding();
  return {
    startRegistration: (password) => {
      const started = native.startRegistration(password);
      return { clientRegistrationState: started.state, registrationRequest: started.request };
    },
    finishRegistration: (state, response, password) =>
      native.finishRegistration(state, response, password),
    startLogin: (password) => {
      const started = native.startLogin(password);
      return { clientLoginState: started.state, startLoginRequest: started.request };
    },
    finishLogin: (state, response, password) =>
      native.finishLogin(state, response, password) ?? undefined,
  };
}
