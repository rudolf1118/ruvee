// Message protocol between a controller and one calibration worker. A worker runs one
// configuration at a time; the controller creates a fresh worker per configuration and
// terminates it afterwards, so WebAssembly memory from one run never carries into the next.
//
// controller -> worker: { type: 'run', configId, warmup, samples } | { type: 'cancel' }
// worker -> controller: { type: 'ready', scriptStartEpochMs, readyEpochMs, initMs, version }
//                       { type: 'progress', configId, kind, index, ms }
//                       { type: 'result', result } | { type: 'cancelled', result }
//                       { type: 'error', error }

import { runConfig, timerResolution } from './core.mjs';

const epoch = () => performance.timeOrigin + performance.now();

export function startWorker({ sodium, post, onMessage, scriptStartEpochMs, scriptStartNow }) {
  let cancel = false;
  let busy = false;
  onMessage(async (msg) => {
    if (msg?.type === 'cancel') {
      cancel = true;
      return;
    }
    if (msg?.type !== 'run' || busy) return;
    busy = true;
    try {
      const result = await runConfig(sodium, msg.configId, {
        warmup: msg.warmup,
        samples: msg.samples,
        now: () => performance.now(),
        // Yielding between derivations lets a cancel message be processed. A derivation in
        // progress cannot be interrupted; only terminating the worker stops it.
        pause: () => new Promise((r) => setTimeout(r, 0)),
        cancelled: () => cancel,
        onProgress: (p) => post({ type: 'progress', ...p }),
      });
      result.timerResolutionMs = timerResolution(() => performance.now());
      post({ type: result.status === 'cancelled' ? 'cancelled' : 'result', result });
    } catch (e) {
      post({ type: 'error', error: e instanceof Error ? `${e.name}: ${e.message}` : String(e) });
    } finally {
      busy = false;
    }
  });
  sodium.ready.then(
    () =>
      post({
        type: 'ready',
        scriptStartEpochMs,
        readyEpochMs: epoch(),
        initMs: Math.round((performance.now() - scriptStartNow) * 1000) / 1000,
        version: sodium.sodium_version_string(),
      }),
    (e) => post({ type: 'error', error: `libsodium failed to initialise: ${e?.message ?? e}` }),
  );
}

export { epoch };
