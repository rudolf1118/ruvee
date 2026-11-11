// Controller side of the benchmark, shared by Node (worker_threads) and browsers (Web Worker).
// createWorker() must return { post(msg), onMessage(fn), terminate() } for a fresh worker.
// Everything runs sequentially: at most one worker, and one derivation, exists at a time.

import { RUN_MODES, configById, stats } from './core.mjs';
import { epoch } from './worker-protocol.mjs';

export const INIT_SERIES = 10;
const READY_TIMEOUT_MS = 60000;
const CONFIG_TIMEOUT_MS = 900000;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const r3 = (x) => Math.round(x * 1000) / 1000;

function wrap(worker) {
  const listeners = new Set();
  const seen = [];
  worker.onMessage((m) => {
    seen.push({ at: epoch(), m });
    for (const l of [...listeners]) l(m);
  });
  const waitFor = (pred, timeoutMs, what) =>
    new Promise((resolve, reject) => {
      const hit = seen.find((s) => pred(s.m));
      if (hit) return resolve(hit.m);
      const timer = setTimeout(() => {
        listeners.delete(l);
        reject(new Error(`${what}: no answer after ${timeoutMs} ms`));
      }, timeoutMs);
      const l = (m) => {
        if (!pred(m)) return;
        clearTimeout(timer);
        listeners.delete(l);
        resolve(m);
      };
      listeners.add(l);
    });
  return { ...worker, seen, waitFor, listeners };
}

async function startReady(createWorker) {
  const createdAt = epoch();
  const w = wrap(createWorker());
  try {
    const ready = await w.waitFor(
      (m) => m.type === 'ready' || m.type === 'error',
      READY_TIMEOUT_MS,
      'worker ready',
    );
    if (ready.type === 'error') throw new Error(ready.error);
    return {
      w,
      init: {
        totalMs: r3(ready.readyEpochMs - createdAt),
        loadAndEvaluateMs: r3(ready.scriptStartEpochMs - createdAt),
        libsodiumReadyMs: ready.initMs,
        version: ready.version,
      },
    };
  } catch (e) {
    await w.terminate();
    throw e;
  }
}

export async function measureInit(createWorker, count = INIT_SERIES) {
  const runs = [];
  const failures = [];
  for (let i = 0; i < count; i++) {
    try {
      const { w, init } = await startReady(createWorker);
      runs.push(init);
      await w.terminate();
    } catch (e) {
      failures.push(String(e?.message ?? e));
    }
  }
  const warm = runs.slice(1);
  return {
    count,
    failures,
    first: runs[0] ?? null,
    subsequent: {
      totalMs: stats(warm.map((r) => r.totalMs)),
      loadAndEvaluateMs: stats(warm.map((r) => r.loadAndEvaluateMs)),
      libsodiumReadyMs: stats(warm.map((r) => r.libsodiumReadyMs)),
    },
    runs,
  };
}

export async function runOne(createWorker, configId, mode, onProgress = () => {}) {
  configById(configId);
  const { warmup, samples } = RUN_MODES[mode] ?? RUN_MODES.standard;
  let started;
  try {
    started = await startReady(createWorker);
  } catch (e) {
    return {
      configId,
      status: 'failed',
      failures: [{ phase: 'init', error: String(e?.message ?? e) }],
    };
  }
  const { w, init } = started;
  const progress = (m) => m.type === 'progress' && onProgress(m);
  w.listeners.add(progress);
  try {
    w.post({ type: 'run', configId, warmup, samples });
    const end = await w.waitFor(
      (m) => ['result', 'cancelled', 'error'].includes(m.type),
      CONFIG_TIMEOUT_MS,
      configId,
    );
    if (end.type === 'error')
      return { configId, status: 'failed', init, failures: [{ phase: 'run', error: end.error }] };
    return { ...end.result, init };
  } catch (e) {
    return {
      configId,
      status: 'failed',
      init,
      failures: [{ phase: 'run', error: String(e?.message ?? e) }],
    };
  } finally {
    w.listeners.delete(progress);
    await w.terminate();
  }
}

// Two ways to stop a derivation, and what each guarantees.
export async function testCancellation(createWorker) {
  const out = {};

  // 1. Cooperative: the worker checks a flag between derivations.
  {
    const { w } = await startReady(createWorker);
    try {
      w.post({ type: 'run', configId: 'p1-64m-t3', warmup: 0, samples: 1000 });
      await w.waitFor((m) => m.type === 'progress' && m.index >= 1, 60000, 'cooperative start');
      const sentAt = epoch();
      w.post({ type: 'cancel' });
      const end = await w.waitFor(
        (m) => m.type === 'cancelled' || m.type === 'result',
        60000,
        'cancel',
      );
      out.cooperative = {
        stopped: end.type === 'cancelled',
        latencyMs: r3(epoch() - sentAt),
        samplesCompleted: end.result.samplesMs.length,
        meaning: 'The current derivation finishes; the worker stops before the next one.',
      };
    } finally {
      await w.terminate();
    }
  }

  // 2. Terminate during a derivation: the only way to stop one in progress.
  {
    const { w } = await startReady(createWorker);
    w.post({ type: 'run', configId: 'p2-256m-t3', warmup: 0, samples: 1000 });
    await w.waitFor((m) => m.type === 'progress' && m.index >= 0, 60000, 'terminate start');
    await sleep(50);
    const before = w.seen.length;
    const t0 = epoch();
    await w.terminate();
    const terminateMs = r3(epoch() - t0);
    await sleep(500);
    const lateMessages = w.seen.length - before;
    let recovered = false;
    let recoveryError = null;
    try {
      const next = await runOne(createWorker, 'ref-19m-t2', 'quick');
      recovered = next.status === 'ok' && next.samplesMs.length === RUN_MODES.quick.samples;
      if (!recovered) recoveryError = JSON.stringify(next.failures);
    } catch (e) {
      recoveryError = String(e?.message ?? e);
    }
    out.terminate = {
      terminateCallMs: terminateMs,
      messagesAfterTerminate: lateMessages,
      newWorkerRunsAfterwards: recovered,
      recoveryError,
      meaning:
        'terminate() stops the derivation in progress and discards the worker and its WebAssembly memory; nothing it computed is delivered.',
    };
  }
  out.passed =
    out.cooperative.stopped &&
    out.terminate.messagesAfterTerminate === 0 &&
    out.terminate.newWorkerRunsAfterwards;
  return out;
}
