// worker_threads entry for the Node benchmark.

import { parentPort } from 'node:worker_threads';
import sodium from 'libsodium-wrappers-sumo';
import { epoch, startWorker } from './worker-protocol.mjs';

const scriptStartNow = performance.now();
startWorker({
  sodium,
  post: (m) => parentPort.postMessage(m),
  onMessage: (fn) => parentPort.on('message', fn),
  scriptStartEpochMs: epoch(),
  scriptStartNow,
});
