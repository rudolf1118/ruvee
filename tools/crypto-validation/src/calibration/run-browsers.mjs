// Runs the benchmark page in Playwright browsers on this machine, one engine at a time, on
// 127.0.0.1 only. Writes results/calibration/browsers-<timestamp>.json.

import { mkdir, writeFile } from 'node:fs/promises';
import { chromium, firefox, webkit } from 'playwright-core';
import { hostInfo } from './host.mjs';
import { startServer } from './serve.mjs';
import { pinnedVersions, root, toJson } from '../preflight.mjs';

const ENGINES = {
  chromium: {
    type: chromium,
    opts: {},
    label: 'Playwright Chromium (headless shell)',
    note: 'Chromium build bundled with Playwright, not Google Chrome',
  },
  firefox: {
    type: firefox,
    opts: {},
    label: 'Playwright Firefox',
    note: 'Firefox build patched by Playwright, not a stock Firefox release',
  },
  webkit: {
    type: webkit,
    opts: {},
    label: 'Playwright WebKit',
    note: 'WebKit engine built by Playwright; this is not Safari',
  },
  chrome: {
    type: chromium,
    opts: { channel: 'chrome' },
    label: 'Google Chrome (installed, launched by Playwright with a temporary profile)',
    note: 'Stock Google Chrome, headless',
  },
};
const mode = process.env.MODE === 'quick' ? 'quick' : 'standard';
const requested = (process.env.BROWSERS ?? 'chromium,firefox,webkit,chrome')
  .split(',')
  .filter(Boolean);
const unknown = requested.filter((e) => !ENGINES[e]);
if (unknown.length) {
  console.error(`Unknown BROWSERS entries: ${unknown.join(', ')}`);
  process.exit(1);
}

const versions = await pinnedVersions();
if (versions.problems.length) {
  console.error('Version preflight failed:\n  ' + versions.problems.join('\n  '));
  process.exit(1);
}

const { server, origin } = await startServer({ host: '127.0.0.1', port: 0 });
const startedAt = new Date().toISOString();
const report = {
  kind: 'argon2id-calibration-browsers',
  startedAt,
  host: hostInfo(),
  packages: versions.installed,
  mode,
  runs: [],
};
let failed = false;

for (const name of requested) {
  const engine = ENGINES[name];
  let browser;
  try {
    browser = await engine.type.launch({ headless: true, ...engine.opts });
  } catch (e) {
    const error = String(e).split('\n')[0];
    report.runs.push({ engine: name, label: engine.label, status: 'unavailable', error });
    console.log(`UNAVAILABLE ${name}: ${error}`);
    failed = true;
    continue;
  }
  const version = browser.version();
  const context = await browser.newContext();
  const page = await context.newPage();
  const consoleErrors = [];
  page.on('console', (m) => m.type() === 'error' && consoleErrors.push(m.text()));
  page.on('pageerror', (e) => consoleErrors.push(String(e)));
  const t0 = Date.now();
  let out;
  try {
    await page.goto(`${origin}/`);
    out = await page.evaluate(
      ({ mode, label }) => globalThis.runCalibration({ mode, deviceLabel: label }),
      { mode, label: `this computer, ${engine.label} ${version}` },
    );
  } catch (e) {
    out = { fatal: String(e).split('\n')[0] };
  } finally {
    await context.close();
    await browser.close();
  }
  const problems = [];
  if (out.fatal) problems.push(out.fatal);
  for (const r of out.results ?? [])
    if (r.status !== 'ok') problems.push(`${r.configId}: ${JSON.stringify(r.failures)}`);
  if (out.init?.failures?.length) problems.push(`init: ${out.init.failures.join('; ')}`);
  if (out.cancellation && !out.cancellation.passed)
    problems.push(`cancellation: ${JSON.stringify(out.cancellation)}`);
  if (problems.length) failed = true;
  report.runs.push({
    engine: name,
    label: engine.label,
    note: engine.note,
    version,
    headless: true,
    status: problems.length ? 'failed' : 'ok',
    problems,
    wallMs: Date.now() - t0,
    consoleErrors: consoleErrors.slice(0, 10),
    report: out,
  });
  console.log(
    `${problems.length ? 'FAILED' : 'OK'} ${engine.label} ${version} (${Math.round((Date.now() - t0) / 1000)} s)`,
  );
  for (const r of out.results ?? []) {
    const s = r.stats ?? {};
    console.log(`  ${r.configId.padEnd(11)} median ${s.median} ms, p95 ${s.p95} ms, n ${s.n}`);
  }
  for (const p of problems) console.log(`  ${p}`);
}

server.close();
report.finishedAt = new Date().toISOString();
const dir = new URL('results/calibration/', root);
await mkdir(dir, { recursive: true });
const file = `browsers-${startedAt.replace(/[:.]/g, '-')}.json`;
await writeFile(new URL(file, dir), toJson(report));
console.log(failed ? 'FAILED' : `OK: results/calibration/${file}`);
process.exit(failed ? 1 : 0);
