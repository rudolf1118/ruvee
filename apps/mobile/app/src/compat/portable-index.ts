// Development runner only (metro.config.js maps `../../src/index.js` here for files under
// packages/crypto/test/). The portable checks call `initRuveeCrypto()` to get the operations under
// test; on the device that must be the app's own build over native primitives, not the
// WebAssembly build. Everything else is the package's index, unchanged.
import type { RuveeCrypto } from '@ruvee/crypto';
import { mobileRuveeCrypto } from '../crypto/ruvee-crypto';

export * from '../../../../../packages/crypto/src/index';

export function initRuveeCrypto(): Promise<RuveeCrypto> {
  return Promise.resolve(mobileRuveeCrypto());
}
