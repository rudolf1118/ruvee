import { createServer } from 'node:http';
import { readFile, mkdir, writeFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, extname } from 'node:path';
import { chromium, firefox, webkit } from 'playwright-core';

const root = new URL('../', import.meta.url);
const RUNS = Number(process.env.BENCH_RUNS || 5);
const only = process.env.ONLY ? process.env.ONLY.split(',') : null;

const CSP = {
  strict:
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  nowasm: "default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'",
};
const types = {
  '.js': 'text/javascript',
  '.json': 'application/json',
  '.txt': 'text/plain',
  '.html': 'text/html',
};
const html =
  '<!doctype html><meta charset="utf-8"><title>spike</title><script src="/dist/page.js"></script>';

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const csp = CSP[url.searchParams.get('csp') ?? url.pathname.split('/')[1]] ?? CSP.strict;
  const path = url.pathname.replace(/^\/(strict|nowasm)/, '');
  const headers = { 'Content-Security-Policy': csp, 'Cache-Control': 'no-store' };
  try {
    if (path === '/' || path === '/index.html') {
      res.writeHead(200, { ...headers, 'Content-Type': 'text/html' }).end(html);
      return;
    }
    if (!/^\/(dist|kat)\/[\w.\-/]+$/.test(path) || path.includes('..'))
      throw new Error('not found');
    const body = await readFile(new URL(`.${path}`, root));
    res
      .writeHead(200, {
        ...headers,
        'Content-Type': types[extname(path)] ?? 'application/octet-stream',
      })
      .end(body);
  } catch {
    res.writeHead(404, headers).end();
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;

function summarize(out) {
  if (!out || out.fatal) return { fatal: out?.fatal ?? 'no result' };
  const failed = out.results
    .filter((r) => r.status !== 'pass')
    .map((r) => ({ id: r.id, error: r.error }));
  return {
    checks: out.results.length,
    failed,
    bench: out.benchmarks.map((b) => `${b.label}: ${b.error ?? `${b.medianMs}ms`}`),
  };
}

async function inPage(page, cspName, mode, runs) {
  const errors = [];
  page.on('console', (m) => m.type() === 'error' && errors.push(m.text()));
  page.on('pageerror', (e) => errors.push(String(e)));
  await page.goto(`${origin}/?csp=${cspName}`);
  const out = await page.evaluate(
    async ({ mode, runs, cspName }) => {
      if (mode === 'main') {
        if (typeof globalThis.runSpike !== 'function')
          return { fatal: 'bundle did not initialise' };
        return globalThis.runSpike({ runs });
      }
      return new Promise((resolve) => {
        const w = new Worker(`/dist/worker.js?csp=${cspName}`);
        w.onmessage = (e) => resolve(e.data);
        w.onerror = (e) => resolve({ fatal: `worker error: ${e.message}` });
        w.postMessage({ runs });
      });
    },
    { mode, runs, cspName },
  );
  return { out, consoleErrors: errors.slice(0, 5) };
}

const targets = [
  { name: 'playwright-chromium', type: chromium, opts: {} },
  { name: 'google-chrome', type: chromium, opts: { channel: 'chrome' } },
  { name: 'playwright-firefox', type: firefox, opts: {} },
  { name: 'playwright-webkit', type: webkit, opts: {} },
];

const report = {
  generatedAt: new Date().toISOString(),
  node: process.version,
  benchRuns: RUNS,
  runs: [],
};
await mkdir(new URL('results/', root), { recursive: true });

for (const t of targets) {
  if (only && !only.includes(t.name)) continue;
  let browser;
  try {
    browser = await t.type.launch({ headless: true, ...t.opts });
  } catch (e) {
    report.runs.push({ target: t.name, launchError: String(e).split('\n')[0] });
    console.log(`SKIP ${t.name}: ${String(e).split('\n')[0]}`);
    continue;
  }
  const version = browser.version();
  for (const [cspName, mode, runs] of [
    ['strict', 'worker', RUNS],
    ['strict', 'main', 1],
    ['nowasm', 'main', 0],
    ['nowasm', 'worker', 0],
  ]) {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    const started = Date.now();
    let res;
    try {
      res = await inPage(page, cspName, mode, runs);
    } catch (e) {
      res = { out: { fatal: String(e).split('\n')[0] } };
    }
    const entry = {
      target: t.name,
      version,
      csp: cspName,
      mode,
      wallMs: Date.now() - started,
      summary: summarize(res.out),
      consoleErrors: res.consoleErrors,
      env: res.out?.env,
      results: res.out?.results,
      benchmarks: res.out?.benchmarks,
    };
    report.runs.push(entry);
    console.log(`${t.name} ${version} csp=${cspName} ${mode}:`, JSON.stringify(entry.summary));
    await ctx.close();
  }
  await browser.close();
}

if (!only || only.includes('opaque-csp')) {
  const browser = await chromium.launch({ headless: true });
  const probe = { target: 'playwright-chromium OPAQUE alone', version: browser.version() };
  for (const cspName of ['strict', 'nowasm']) {
    const page = await browser.newPage();
    await page.goto(`${origin}/?csp=${cspName}`);
    probe[cspName] = await page.evaluate(() => globalThis.probeOpaqueOnly());
    await page.close();
  }
  await browser.close();
  report.runs.push(probe);
  console.log(`${probe.target}:`, JSON.stringify({ strict: probe.strict, nowasm: probe.nowasm }));
}

for (const extDir of ['extension-default-csp', 'extension-wasm-csp']) {
  if (only && !only.includes('extension')) break;
  const userDataDir = await mkdtemp(join(tmpdir(), 'ruvee-spike-ext-'));
  const ext = new URL(`dist/${extDir}/`, root).pathname;
  const entry = { target: `playwright-chromium MV3 service worker (${extDir})` };
  try {
    const ctx = await chromium.launchPersistentContext(userDataDir, {
      channel: 'chromium',
      headless: process.env.EXT_HEADED !== '1',
      args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
    });
    let [sw] = ctx.serviceWorkers();
    if (!sw) sw = await ctx.waitForEvent('serviceworker', { timeout: 15000 });
    entry.version = ctx.browser()?.version() ?? null;
    entry.serviceWorkerUrl = sw.url();
    const out = await sw.evaluate(
      async (runs) => globalThis.runSpike({ base: globalThis.location.origin, runs }),
      Math.min(RUNS, 3),
    );
    entry.summary = summarize(out);
    entry.env = out?.env;
    entry.results = out?.results;
    entry.benchmarks = out?.benchmarks;
    await ctx.close();
  } catch (e) {
    entry.error = String(e).split('\n')[0];
  }
  await rm(userDataDir, { recursive: true, force: true });
  report.runs.push(entry);
  console.log(`${entry.target}:`, JSON.stringify(entry.summary ?? entry.error));
}

const resultFile = new URL('results/browser.json', root);
if (only) {
  try {
    const previous = JSON.parse(await readFile(resultFile, 'utf8'));
    const replaced = new Set(report.runs.map((r) => r.target));
    report.runs = [...previous.runs.filter((r) => !replaced.has(r.target)), ...report.runs];
  } catch {
    // no previous result file
  }
}
await writeFile(resultFile, JSON.stringify(report, null, 2));
server.close();
