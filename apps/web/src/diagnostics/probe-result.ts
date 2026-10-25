export interface ProbeResult<Details = undefined> {
  readonly ok: boolean;
  readonly evalBlocked: boolean;
  readonly details?: Details;
  readonly error?: string;
}

export function evalIsBlocked(): boolean {
  try {
    // CSP probe only: script-src must reject JavaScript eval. Not a cryptography check.
    const evalFn: (code: string) => unknown = globalThis.eval;
    return evalFn('1') !== 1;
  } catch {
    return true;
  }
}
