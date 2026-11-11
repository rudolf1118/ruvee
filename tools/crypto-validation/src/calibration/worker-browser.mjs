// Dedicated Web Worker entry for the benchmark page.

import sodium from 'libsodium-wrappers-sumo';
import { epoch, startWorker } from './worker-protocol.mjs';

const scriptStartNow = performance.now();
startWorker({
  sodium,
  post: (m) => globalThis.postMessage(m),
  onMessage: (fn) => {
    globalThis.onmessage = (e) => fn(e.data);
  },
  scriptStartEpochMs: epoch(),
  scriptStartNow,
});
