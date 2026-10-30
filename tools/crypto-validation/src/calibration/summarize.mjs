// Prints Markdown tables from calibration result files, and checks that every environment
// produced the same output for each configuration.
// Usage: node summarize.mjs [files...]   (default: every JSON file in results/calibration/)

import { readFile, readdir } from 'node:fs/promises';
import { root } from '../preflight.mjs';

const dir = new URL('results/calibration/', root);
const args = process.argv.slice(2);
const files = args.length
  ? args
  : [
      ...(await readdir(dir))
        .filter((f) => f.endsWith('.json'))
        .map((f) => new URL(f, dir).pathname),
      ...(await readdir(new URL('manual/', dir)).catch(() => []))
        .filter((f) => f.endsWith('.json'))
        .map((f) => new URL(`manual/${f}`, dir).pathname),
    ];

const at = (j) => `run ${String(j.startedAt).slice(0, 16).replace('T', ' ')} UTC`;
const envs = [];
for (const f of files) {
  const j = JSON.parse(await readFile(f, 'utf8'));
  if (j.kind === 'argon2id-calibration-browsers') {
    for (const run of j.runs)
      if (run.report)
        envs.push({
          name: `${run.label} ${run.version} [${at(j)}]`,
          results: run.report.results,
          init: run.report.init,
          cancellation: run.report.cancellation,
          env: run.report.environment,
        });
  } else if (j.kind === 'argon2id-calibration' && j.environment?.runtime === 'node') {
    envs.push({
      name: `Node ${j.environment.node} [${at(j)}]`,
      results: j.results.map((r) => ({ ...r.result, memory: r.memory, load: r.loadAverage1m })),
      init: j.init.result,
      cancellation: j.cancellation.result,
      env: j.environment,
    });
  } else if (j.kind === 'argon2id-calibration') {
    envs.push({
      name: `${j.deviceLabel || j.environment?.userAgent} [${at(j)}]`,
      results: j.results,
      init: j.init,
      cancellation: j.cancellation,
      env: j.environment,
    });
  }
}

const ids = [...new Set(envs.flatMap((e) => e.results.map((r) => r.configId)))];
const longest = envs.reduce((a, e) => (e.results.length > a.length ? e.results : a), []);
const cols = longest.map((r, i) =>
  longest.slice(0, i).some((x) => x.configId === r.configId)
    ? `${r.configId} (repeat)`
    : r.configId,
);
const row = (cells) => `| ${cells.join(' | ')} |`;
const fmt = (s) => (s?.n ? `${s.median} / ${s.p95} (${s.min}–${s.max})` : 'failed');

console.log('### Median / p95 (min–max), ms\n');
console.log(row(['Environment', ...cols]));
console.log(row(['---', ...cols.map(() => '---')]));
for (const e of envs) console.log(row([e.name, ...e.results.map((r) => fmt(r.stats))]));

console.log('\n### Samples and failures\n');
console.log(row(['Environment', 'Samples per configuration', 'Failures', 'Mapping verified']));
console.log(row(['---', '---', '---', '---']));
for (const e of envs)
  console.log(
    row([
      e.name,
      [...new Set(e.results.map((r) => r.stats?.n ?? 0))].join(', '),
      e.results.reduce((a, r) => a + (r.failures?.length ?? 0), 0),
      e.results.every((r) => r.mappingCheck?.ok) ? 'yes' : 'NO',
    ]),
  );

console.log('\n### Worker initialisation, ms\n');
console.log(
  row([
    'Environment',
    'First worker: total (load and evaluate + libsodium ready)',
    'Next 9: median total (min–max)',
  ]),
);
console.log(row(['---', '---', '---']));
for (const e of envs) {
  const f = e.init?.first;
  const s = e.init?.subsequent?.totalMs;
  console.log(
    row([
      e.name,
      f ? `${f.totalMs} (${f.loadAndEvaluateMs} + ${f.libsodiumReadyMs})` : 'failed',
      s?.n ? `${s.median} (${s.min}–${s.max})` : 'n/a',
    ]),
  );
}

console.log('\n### Cancellation and cleanup\n');
console.log(
  row([
    'Environment',
    'Cooperative stop latency ms',
    'terminate() call ms',
    'Messages after terminate',
    'New worker works',
    'Passed',
  ]),
);
console.log(row(['---', '---', '---', '---', '---', '---']));
for (const e of envs) {
  const c = e.cancellation;
  console.log(
    row([
      e.name,
      c?.cooperative?.latencyMs ?? 'n/a',
      c?.terminate?.terminateCallMs ?? 'n/a',
      c?.terminate?.messagesAfterTerminate ?? 'n/a',
      c?.terminate?.newWorkerRunsAfterwards ?? 'n/a',
      c?.passed ?? 'n/a',
    ]),
  );
}

console.log('\n### Memory\n');
console.log(row(['Environment', ...cols]));
console.log(row(['---', ...cols.map(() => '---')]));
for (const e of envs) {
  const cells = e.results.map((r) =>
    r.memory
      ? `process peak RSS ${Math.round(r.memory.processPeakRssKiB / 1024)} MiB (idle ${Math.round(r.memory.processIdleRssKiB / 1024)} MiB)`
      : r.wasmLinearMemoryBytesAfter
        ? `WASM linear memory ${Math.round((r.wasmLinearMemoryBytesAfter / 1048576) * 100) / 100} MiB`
        : 'n/a',
  );
  console.log(row([e.name, ...cells]));
}

console.log('\n### Timer\n');
for (const e of envs)
  console.log(
    `- ${e.name}: worker timer resolution ${e.results[0]?.timerResolutionMs} ms` +
      (e.env?.crossOriginIsolated !== undefined
        ? `, cross-origin isolated: ${e.env.crossOriginIsolated}`
        : ''),
  );

const problems = [];
for (const id of ids) {
  const fps = new Set(
    envs.flatMap((e) =>
      e.results
        .filter((r) => r.configId === id && r.outputFingerprint)
        .map((r) => r.outputFingerprint),
    ),
  );
  if (fps.size > 1) problems.push(`${id}: environments produced different outputs`);
}
console.log(
  problems.length
    ? `\nOUTPUT MISMATCH\n  ${problems.join('\n  ')}`
    : `\nEvery environment produced identical output for each configuration (${envs.length} environments).`,
);
process.exit(problems.length ? 1 : 0);
