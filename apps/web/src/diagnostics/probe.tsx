'use client';

import { useEffect, useState } from 'react';
import type { ProbeResult } from './probe-result';

/** Worker bundles written next to the diagnostics export by scripts/build-diagnostics.mjs. */
export const DIAGNOSTIC_WORKERS = {
  crypto: '/diagnostics/crypto-worker.js',
  opaque: '/diagnostics/opaque-worker.js',
} as const;

type State = ProbeResult<unknown> | { pending: true } | { error: string };

export function Probe({ name }: { name: keyof typeof DIAGNOSTIC_WORKERS }) {
  const [result, setResult] = useState<State>({ pending: true });

  useEffect(() => {
    const worker = new Worker(DIAGNOSTIC_WORKERS[name]);
    worker.onmessage = (event: MessageEvent<ProbeResult<unknown>>) => {
      setResult(event.data);
      worker.terminate();
    };
    worker.onerror = (event) => {
      setResult({ error: event.message });
      worker.terminate();
    };
    worker.postMessage('run');
    return () => {
      worker.terminate();
    };
  }, [name]);

  const text =
    'pending' in result
      ? 'pending'
      : 'error' in result && !('ok' in result)
        ? `error ${result.error}`
        : JSON.stringify(result);

  return (
    <output id={`probe-${name}`} className="font-mono text-caption break-all">
      {text}
    </output>
  );
}
