// Runs the suite and negative controls in real Playwright browsers, on the page and in a dedicated
// worker, one engine and one context at a time. A browser that cannot launch is a failed
// environment, never a skip. Exit code 1 on any failure.

import { createServer } from 'node:http';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { chromium, firefox, webkit } from 'playwright-core';
import { CATEGORIES } from '../harness.mjs';
import { runNegativeControls } from '../negative-controls.mjs';
import { pinnedVersions, readJson, readVector, root, toJson } from '../preflight.mjs';
import { CHECK_IDS, createContext } from '../suite.mjs';

const ENGINES = {
  chromium: { type: chromium, opts: {} },
  firefox: { type: firefox, opts: {} },
  webkit: { type: webkit, opts: {} },
  chrome: { type: chromium, opts: { channel: 'chrome' } },
};
const DEFAULT_ENGINES = ['chromium', 'firefox', 'webkit'];
const RUN_TIMEOUT_MS = Number(process.env.RUN_TIMEOUT_MS || 600000);

// Only 'wasm-unsafe-eval' is added for WebAssembly; 'unsafe-eval' is deliberately absent.
const CSP = {
  strict:
    "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  nowasm:
    "default-src 'none'; script-src 'self'; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
};

const versions = await pinnedVersions();
if (versions.problems.length) {
  console.error('Version preflight failed:\n  ' + versions.problems.join('\n  '));
  process.exit(1);
}
const manifest = await readJson('vectors/sources.json');
const servable = new Set(['sources.json', ...manifest.sources.map((s) => s.file)]);
const bundle = await readFile(new URL('dist/validation.js', root)).catch(() => null);
if (!bundle) {
  console.error('dist/validation.js missing; run npm run build:browser');
  process.exit(1);
}

const requested = (process.env.BROWSERS ?? DEFAULT_ENGINES.join(','))
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);
const unknown = requested.filter((e) => !ENGINES[e]);
if (unknown.length) {
  console.error(`Unknown BROWSERS entries: ${unknown.join(', ')}`);
  process.exit(1);
}

console.log('Computing the expected negative-control set in Node');
const expectedControls = (
  await runNegativeControls({
    ctx: await createContext({ manifest, readBytes: readVector }),
    manifest,
    readBytes: readVector,
  })
).map((c) => c.id);

const html =
  '<!doctype html><meta charset="utf-8"><title>crypto validation (synthetic)</title><script src="/dist/validation.js"></script>';
const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const headers = {
    'Content-Security-Policy': CSP[url.searchParams.get('csp')] ?? CSP.strict,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  };
  try {
    if (url.pathname === '/') {
      res.writeHead(200, { ...headers, 'Content-Type': 'text/html; charset=utf-8' }).end(html);
    } else if (url.pathname === '/dist/validation.js') {
      res.writeHead(200, { ...headers, 'Content-Type': 'text/javascript' }).end(bundle);
    } else if (url.pathname.startsWith('/vectors/') && servable.has(url.pathname.slice(9))) {
      const file = url.pathname.slice(9);
      const type = file.endsWith('.json') ? 'application/json' : 'text/plain; charset=utf-8';
      res.writeHead(200, { ...headers, 'Content-Type': type }).end(await readVector(file));
    } else {
      res.writeHead(404, headers).end();
    }
  } catch {
    res.writeHead(500, headers).end();
  }
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const origin = `http://127.0.0.1:${server.address().port}`;

const withTimeout = (promise, ms, what) =>
  Promise.race([
    promise,
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error(`${what} timed out after ${ms} ms`)), ms),
    ),
  ]);

async function evaluate(browser, csp, scope, action) {
  const context = await browser.newContext();
  const page = await context.newPage();
  const consoleErrors = [];
  page.on('console', (m) => m.type() === 'error' && consoleErrors.push(m.text()));
  page.on('pageerror', (e) => consoleErrors.push(String(e)));
  await page.addInitScript(() => {
    globalThis.__violations = [];
    globalThis.addEventListener('securitypolicyviolation', (e) =>
      globalThis.__violations.push(`${e.effectiveDirective}: ${e.blockedURI}`),
    );
  });
  try {
    await page.goto(`${origin}/?csp=${csp}`);
    const out = await withTimeout(
      page.evaluate(
        async ({ csp, scope, action }) => {
          if (scope === 'window') {
            if (typeof globalThis.runValidation !== 'function')
              return { fatal: 'bundle did not initialise' };
            const out =
              action === 'probe' ? await globalThis.probeWasm() : await globalThis.runValidation();
            return { ...out, violations: globalThis.__violations };
          }
          return new Promise((resolve) => {
            const w = new Worker(`/dist/validation.js?csp=${csp}`);
            w.onmessage = (e) => resolve(e.data);
            w.onerror = (e) => resolve({ fatal: `worker error: ${e.message}` });
            w.postMessage(action);
          });
        },
        { csp, scope, action },
      ),
      RUN_TIMEOUT_MS,
      `${scope} ${action}`,
    );
    return { ...out, consoleErrors: consoleErrors.slice(0, 10) };
  } catch (e) {
    return { fatal: String(e).split('\n')[0], consoleErrors: consoleErrors.slice(0, 10) };
  } finally {
    await context.close();
  }
}

function judgeValidation(out, scope) {
  if (out.fatal) return [`fatal: ${out.fatal}`];
  const problems = [];
  if (out.environment?.scope !== scope)
    problems.push(`ran in scope ${out.environment?.scope}, expected ${scope}`);
  const ids = out.results.map((r) => r.id);
  for (const r of out.results) if (r.status !== 'pass') problems.push(`${r.id}: ${r.error}`);
  for (const p of out.completenessProblems) problems.push(`incomplete: ${p}`);
  const missing = CHECK_IDS.filter((id) => !ids.includes(id));
  if (missing.length) problems.push(`missing checks: ${missing.join(', ')}`);
  const controlIds = out.negativeControls.map((c) => c.id);
  for (const c of out.negativeControls)
    if (!c.passed) problems.push(`negative control not detected: ${c.id}`);
  const missingControls = expectedControls.filter((id) => !controlIds.includes(id));
  if (missingControls.length)
    problems.push(`negative controls missing: ${missingControls.join(', ')}`);
  for (const [name, v] of Object.entries(out.packages ?? {}))
    if (v !== versions.installed[name])
      problems.push(`bundle built from ${name} ${v}, installed ${versions.installed[name]}`);
  return problems;
}

const report = {
  generatedAt: new Date().toISOString(),
  node: process.versions.node,
  playwrightCore: versions.installed['playwright-core'],
  packages: versions.installed,
  csp: CSP,
  requested,
  notRequested: DEFAULT_ENGINES.filter((e) => !requested.includes(e)),
  environments: [],
};
let failed = report.notRequested.length > 0;
if (failed) console.log(`NOT RUN (counted as failure): ${report.notRequested.join(', ')}`);

for (const name of requested) {
  const engine = ENGINES[name];
  let browser;
  try {
    browser = await engine.type.launch({ headless: true, ...engine.opts });
  } catch (e) {
    const error = String(e).split('\n')[0];
    report.environments.push({ engine: name, status: 'unavailable', error });
    console.log(`FAIL ${name}: could not launch (${error})`);
    failed = true;
    continue;
  }
  const version = browser.version();
  for (const scope of ['window', 'dedicated-worker']) {
    const t0 = Date.now();
    const out = await evaluate(browser, 'strict', scope, 'validate');
    const problems = judgeValidation(out, scope);
    const byCategory = out.summary?.byCategory ?? {};
    report.environments.push({
      engine: name,
      version,
      scope,
      csp: 'strict',
      status: problems.length ? 'fail' : 'pass',
      problems,
      wallMs: Date.now() - t0,
      byCategory,
      environment: out.environment,
      results: out.results,
      negativeControls: out.negativeControls && {
        total: out.negativeControls.length,
        detected: out.negativeControls.filter((c) => c.passed).length,
      },
      violations: out.violations,
      consoleErrors: out.consoleErrors,
    });
    const counts = Object.entries(CATEGORIES)
      .map(
        ([cat, m]) =>
          `${m.order}:${byCategory[cat]?.pass ?? 0}/${(byCategory[cat]?.pass ?? 0) + (byCategory[cat]?.fail ?? 0)}`,
      )
      .join(' ');
    console.log(
      `${problems.length ? 'FAIL' : 'PASS'} ${name} ${version} ${scope}: categories ${counts}; controls ${out.negativeControls?.filter((c) => c.passed).length ?? 0}/${expectedControls.length} (${Date.now() - t0} ms)`,
    );
    for (const p of problems.slice(0, 20)) console.log(`     ${p}`);
    if (problems.length) failed = true;
  }

  // 'wasm-unsafe-eval' must be necessary (WebAssembly fails without it) and sufficient (the strict runs above).
  for (const scope of ['window', 'dedicated-worker']) {
    const out = await evaluate(browser, 'nowasm', scope, 'probe');
    const problems =
      out.ok === false
        ? []
        : [`libsodium initialised without 'wasm-unsafe-eval' (${out.fatal ?? out.version})`];
    report.environments.push({
      engine: name,
      version,
      scope,
      csp: 'nowasm',
      check: 'ENV-WASM-CSP-REQUIRED',
      status: problems.length ? 'fail' : 'pass',
      problems,
      probe: { ok: out.ok, error: out.error ?? out.fatal, violations: out.violations },
      consoleErrors: out.consoleErrors,
    });
    console.log(
      `${problems.length ? 'FAIL' : 'PASS'} ${name} ${scope}: WebAssembly blocked without 'wasm-unsafe-eval' (${out.error ?? out.fatal ?? 'initialised'})`,
    );
    if (problems.length) failed = true;
  }
  await browser.close();
}

server.close();
await mkdir(new URL('results/', root), { recursive: true });
await writeFile(new URL('results/browsers.json', root), toJson(report));
console.log(failed ? 'RESULT: FAILED' : 'RESULT: every requested engine passed in page and worker');
process.exit(failed ? 1 : 0);
