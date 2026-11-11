// Node calibration run: one child process per task, strictly one after another.
// Writes results/calibration/node-<timestamp>.json. Exit code 1 on any failure.

import { spawn } from 'node:child_process';
import { mkdir, writeFile } from 'node:fs/promises';
import { CONFIGS, DEFAULT_ORDER, RUN_MODES, argon2Mapping } from './core.mjs';
import { hostInfo } from './host.mjs';
import { pinnedVersions, root, toJson } from '../preflight.mjs';

const mode = process.env.MODE === 'quick' ? 'quick' : 'standard';
const CHILD_TIMEOUT_MS = 900000;

const versions = await pinnedVersions();
if (versions.problems.length) {
  console.error('Version preflight failed:\n  ' + versions.problems.join('\n  '));
  process.exit(1);
}

const childPids = [];
function child(args) {
  return new Promise((resolve) => {
    const p = spawn(
      process.execPath,
      [new URL('./node-child.mjs', import.meta.url).pathname, ...args],
      {
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    childPids.push(p.pid);
    let stdout = '';
    let stderr = '';
    p.stdout.on('data', (d) => (stdout += d));
    p.stderr.on('data', (d) => (stderr += d));
    const timer = setTimeout(() => p.kill('SIGKILL'), CHILD_TIMEOUT_MS);
    p.on('close', (code, signal) => {
      clearTimeout(timer);
      try {
        resolve({ pid: p.pid, code, ...JSON.parse(stdout.trim().split('\n').pop()) });
      } catch {
        resolve({
          pid: p.pid,
          code,
          signal,
          error: stderr.trim().split('\n').slice(-3).join(' ') || 'no output',
        });
      }
    });
  });
}

const host = hostInfo();
console.log(
  `Node ${process.versions.node} on ${host.hardwareModel ?? host.cpuModel} (${host.platform}), power: ${host.powerSource ?? 'unknown'}, mode ${mode}`,
);
const startedAt = new Date().toISOString();
const problems = [];

console.log('Worker initialisation series');
const init = await child(['init']);
if (init.error || init.result.failures.length)
  problems.push(`init: ${init.error ?? init.result.failures}`);

const configs = [];
for (const id of DEFAULT_ORDER) {
  const r = await child(['config', id, mode]);
  configs.push(r);
  const s = r.result?.stats;
  if (r.error || r.result.status !== 'ok')
    problems.push(`${id}: ${r.error ?? JSON.stringify(r.result.failures)}`);
  console.log(
    `  ${id.padEnd(11)} ${s ? `median ${s.median} ms, p95 ${s.p95} ms, n ${s.n}` : 'FAILED'}; process peak RSS ${Math.round((r.memory?.processPeakRssKiB ?? 0) / 1024)} MiB`,
  );
}

const fingerprints = {};
for (const r of configs) {
  const fp = r.result?.outputFingerprint;
  if (!fp) continue;
  if (fingerprints[r.configId] && fingerprints[r.configId] !== fp)
    problems.push(`${r.configId}: output differs between runs`);
  fingerprints[r.configId] = fp;
}

console.log('Cancellation and cleanup');
const cancellation = await child(['cancellation']);
if (cancellation.error || !cancellation.result.passed)
  problems.push(`cancellation: ${cancellation.error ?? JSON.stringify(cancellation.result)}`);
else
  console.log(
    `  cooperative stop after ${cancellation.result.cooperative.latencyMs} ms; terminate ${cancellation.result.terminate.terminateCallMs} ms, new worker afterwards: ${cancellation.result.terminate.newWorkerRunsAfterwards}`,
  );

const report = {
  kind: 'argon2id-calibration',
  environment: {
    runtime: 'node',
    node: process.versions.node,
    v8: process.versions.v8,
    scope: 'worker_threads Worker, one child process per task',
    host,
    packages: versions.installed,
  },
  startedAt,
  finishedAt: new Date().toISOString(),
  mode: { name: mode, ...RUN_MODES[mode] },
  order: DEFAULT_ORDER,
  configurations: CONFIGS.map((c) => ({ ...c, mapping: argon2Mapping(c) })),
  init,
  results: configs,
  cancellation,
  childPids,
  problems,
};
const dir = new URL('results/calibration/', root);
await mkdir(dir, { recursive: true });
const name = `node-${startedAt.replace(/[:.]/g, '-')}.json`;
await writeFile(new URL(name, dir), toJson(report));
console.log(
  problems.length ? `FAILED\n  ${problems.join('\n  ')}` : `OK: results/calibration/${name}`,
);
process.exit(problems.length ? 1 : 0);
