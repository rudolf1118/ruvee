'use client';

import { useEffect, useState } from 'react';
import type { ProbeResult } from './crypto-worker';

const WORKER_PATH = '/csp-probe-worker.js';

export function Probe() {
  const [result, setResult] = useState<ProbeResult | { pending: true } | { error: string }>({
    pending: true,
  });

  useEffect(() => {
    const worker = new Worker(WORKER_PATH);
    worker.onmessage = (event: MessageEvent<ProbeResult>) => {
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
  }, []);

  const text =
    'pending' in result
      ? 'pending'
      : 'error' in result
        ? `error ${result.error}`
        : JSON.stringify(result);

  return (
    <output id="csp-probe-result" className="font-mono text-body">
      {text}
    </output>
  );
}
