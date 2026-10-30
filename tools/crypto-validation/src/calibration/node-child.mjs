// One benchmark task in its own Node process, so the process peak RSS belongs to that task.
// Usage: node node-child.mjs <init|config|cancellation> [configId] [mode]
// Prints one JSON line on stdout.

import { loadavg } from 'node:os';
import { Worker } from 'node:worker_threads';
import { measureInit, runOne, testCancellation } from './controller.mjs';

const [task, configId, mode = 'standard'] = process.argv.slice(2);
const idleMaxRssKiB = process.resourceUsage().maxRSS;
const loadAtStart = loadavg()[0];

function createWorker() {
  const w = new Worker(new URL('./worker-node.mjs', import.meta.url));
  return {
    post: (m) => w.postMessage(m),
    onMessage: (fn) => {
      w.on('message', fn);
      w.on('error', (e) => fn({ type: 'error', error: `${e?.name}: ${e?.message}` }));
    },
    terminate: () => w.terminate(),
  };
}

let result;
if (task === 'init') result = await measureInit(createWorker);
else if (task === 'config') result = await runOne(createWorker, configId, mode);
else if (task === 'cancellation') result = await testCancellation(createWorker);
else throw new Error(`unknown task ${task}`);

process.stdout.write(
  JSON.stringify({
    task,
    configId: configId ?? null,
    mode,
    loadAverage1m: { start: loadAtStart, end: loadavg()[0] },
    result,
    memory: {
      processPeakRssKiB: process.resourceUsage().maxRSS,
      processIdleRssKiB: idleMaxRssKiB,
      meaning:
        'Peak resident set size of the whole Node process (getrusage ru_maxrss), including the runtime and the worker thread.',
    },
  }) + '\n',
);
