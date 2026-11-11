import { initRuveeCrypto } from '@ruvee/crypto';
import { evalIsBlocked, type ProbeResult } from './probe-result';

self.onmessage = () => {
  const evalBlocked = evalIsBlocked();
  void initRuveeCrypto().then(
    (crypto) => {
      const key = crypto.generateKey();
      const ok = key.length === 32;
      key.fill(0);
      const result: ProbeResult = { ok, evalBlocked };
      self.postMessage(result);
    },
    (error: unknown) => {
      const result: ProbeResult = {
        ok: false,
        evalBlocked,
        error: error instanceof Error ? error.message : 'init failed',
      };
      self.postMessage(result);
    },
  );
};
