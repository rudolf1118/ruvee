// Browser entry for the portable checks. The same bundle runs on the page and, loaded as a
// classic script, in a dedicated worker. It compiles the package's TypeScript sources with the
// real pinned libsodium.js; nothing is mocked.

import sodium from 'libsodium-wrappers-sumo';
import { loadLibsodiumPrimitives } from '../../src/libsodium.js';
import { PORTABLE_CHECKS, type PortableEnv } from '../portable/checks.js';
import type { ProvisionalVectorFile } from '../portable/provisional.js';

export interface BrowserCheckResult {
  id: string;
  category: string;
  ok: boolean;
  ms: number;
  error?: string;
}

async function fetchBytes(path: string): Promise<Uint8Array> {
  const response = await fetch(path);
  if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function runAll(): Promise<BrowserCheckResult[]> {
  await sodium.ready;
  const env: PortableEnv = {
    raw: await loadLibsodiumPrimitives(),
    sodium,
    readVector: (file) => fetchBytes(`/vectors/${file}`),
    committedVectors: JSON.parse(
      new TextDecoder().decode(await fetchBytes('/provisional.json')),
    ) as ProvisionalVectorFile,
  };
  const results: BrowserCheckResult[] = [];
  for (const check of PORTABLE_CHECKS) {
    const start = performance.now();
    try {
      await check.run(env);
      results.push({
        id: check.id,
        category: check.category,
        ok: true,
        ms: performance.now() - start,
      });
    } catch (e) {
      results.push({
        id: check.id,
        category: check.category,
        ok: false,
        ms: performance.now() - start,
        error: e instanceof Error ? `${e.name}: ${e.message}` : String(e),
      });
    }
  }
  return results;
}

interface WorkerScope {
  onmessage: (() => void) | null;
  postMessage(message: unknown): void;
}
interface PageScope {
  Worker: new (url: string) => {
    onmessage: ((event: { data: unknown }) => void) | null;
    onerror: ((event: { message?: string }) => void) | null;
    postMessage(message: unknown): void;
    terminate(): void;
  };
  ruveeChecks?: { page(): Promise<BrowserCheckResult[]>; worker(): Promise<unknown> };
}

const scope = globalThis as unknown as Partial<WorkerScope> & PageScope & { document?: unknown };

if (scope.document === undefined) {
  const worker = scope as unknown as WorkerScope;
  worker.onmessage = () => {
    runAll().then(
      (results) => {
        worker.postMessage({ results });
      },
      (e: unknown) => {
        worker.postMessage({ fatal: e instanceof Error ? e.message : String(e) });
      },
    );
  };
} else {
  scope.ruveeChecks = {
    page: runAll,
    worker: () =>
      new Promise((resolve) => {
        const w = new scope.Worker('/checks.js');
        w.onmessage = (event) => {
          w.terminate();
          resolve(event.data);
        };
        w.onerror = (event) => {
          w.terminate();
          resolve({ fatal: event.message ?? 'worker error' });
        };
        w.postMessage('run');
      }),
  };
}
