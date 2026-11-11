// Runs the portable checks (test/portable/checks.ts) against the package source in Playwright
// Chromium, Firefox and WebKit, on the page and in a dedicated worker, under a strict CSP that
// allows only 'wasm-unsafe-eval'. Playwright WebKit is not Safari. A browser that cannot launch
// is a failure, never a skip. Exit code 1 on any failure.

import { readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { build } from 'esbuild';
import { chromium, firefox, webkit } from 'playwright-core';

const root = new URL('../', import.meta.url);
const vectorDir = new URL('../../tools/crypto-validation/vectors/', root);
const ENGINES = { chromium, firefox, webkit };
const requested = (process.env.BROWSERS ?? 'chromium,firefox,webkit').split(',').filter(Boolean);
const TIMEOUT_MS = Number(process.env.RUN_TIMEOUT_MS ?? 600_000);
const CSP =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

for (const name of requested) {
  if (!(name in ENGINES)) {
    console.error(`Unknown engine in BROWSERS: ${name}`);
    process.exit(1);
  }
}

const bundle = await build({
  entryPoints: [new URL('test/browser/entry.ts', root).pathname],
  bundle: true,
  write: false,
  format: 'iife',
  platform: 'browser',
  target: 'es2022',
  logLevel: 'warning',
  // libsodium.js probes for Node built-ins behind runtime checks that a browser never reaches.
  external: ['fs', 'path', 'crypto', 'url', 'module', 'worker_threads'],
});
const script = bundle.outputFiles[0].contents;
const provisional = await readFile(new URL('test/vectors/provisional-protocol-vectors.json', root));
const manifest = JSON.parse(await readFile(new URL('sources.json', vectorDir), 'utf8'));
const servable = new Set(['sources.json', ...manifest.sources.map((s) => s.file)]);
const html =
  '<!doctype html><meta charset="utf-8"><title>@ruvee/crypto checks (synthetic)</title><script src="/checks.js"></script>';

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? '/', 'http://127.0.0.1');
  const headers = {
    'Content-Security-Policy': CSP,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  };
  const send = (type, body) => res.writeHead(200, { ...headers, 'Content-Type': type }).end(body);
  if (url.pathname === '/') return send('text/html; charset=utf-8', html);
  if (url.pathname === '/checks.js') return send('text/javascript', script);
  if (url.pathname === '/provisional.json') return send('application/json', provisional);
  const file = url.pathname.startsWith('/vectors/') ? url.pathname.slice(9) : '';
  if (servable.has(file))
    return send('application/octet-stream', await readFile(new URL(file, vectorDir)));
  res.writeHead(404, headers).end();
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;

const rows = [];
let failed = false;
try {
  for (const name of requested) {
    let browser;
    try {
      browser = await ENGINES[name].launch();
      const page = await (await browser.newContext()).newPage();
      const pageErrors = [];
      page.on('pageerror', (e) => pageErrors.push(e.message));
      await page.goto(`${origin}/`);
      await page.waitForFunction(() => 'ruveeChecks' in globalThis, null, { timeout: 30_000 });
      for (const context of ['page', 'worker']) {
        const outcome = await page.evaluate((c) => globalThis.ruveeChecks[c](), context, {
          timeout: TIMEOUT_MS,
        });
        const results = Array.isArray(outcome) ? outcome : outcome.results;
        if (!results) {
          failed = true;
          rows.push({
            engine: `${name} ${browser.version()}`,
            context,
            id: '(fatal)',
            ok: false,
            error: outcome.fatal,
          });
          continue;
        }
        for (const r of results) {
          if (!r.ok) failed = true;
          rows.push({ engine: `${name} ${browser.version()}`, context, ...r });
        }
      }
      if (pageErrors.length) {
        failed = true;
        rows.push({
          engine: name,
          context: 'page',
          id: '(page errors)',
          ok: false,
          error: pageErrors.join('; '),
        });
      }
    } catch (e) {
      failed = true;
      rows.push({
        engine: name,
        context: '-',
        id: '(launch or run)',
        ok: false,
        error: String(e?.message ?? e),
      });
    } finally {
      await browser?.close();
    }
  }
} finally {
  await new Promise((resolve) => server.close(resolve));
}

const byEnv = new Map();
for (const r of rows) {
  const key = `${r.engine} / ${r.context}`;
  const entry = byEnv.get(key) ?? { passed: 0, failed: 0 };
  entry[r.ok ? 'passed' : 'failed']++;
  byEnv.set(key, entry);
}
for (const [key, { passed, failed: f }] of byEnv)
  console.log(`${f ? 'FAIL' : 'ok  '} ${key}: ${passed} passed, ${f} failed`);
for (const r of rows.filter((x) => !x.ok))
  console.log(`  ${r.engine} / ${r.context} / ${r.id}: ${r.error}`);
console.log('Playwright WebKit is not Safari; Safari is checked by hand.');
process.exit(failed ? 1 : 0);
