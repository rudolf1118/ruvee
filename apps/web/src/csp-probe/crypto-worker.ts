import { initRuveeCrypto } from '@ruvee/crypto';

export interface ProbeResult {
  readonly ok: boolean;
  readonly evalBlocked: boolean;
  readonly error?: string;
}

function evalIsBlocked(): boolean {
  try {
    // CSP probe only: script-src must reject JavaScript eval. Not a cryptography check.
    const evalFn: (code: string) => unknown = globalThis.eval;
    return evalFn('1') !== 1;
  } catch {
    return true;
  }
}

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
