// Local server for the benchmark page. Listens on 127.0.0.1 unless HOST names another address.
// Serves only the built page and accepts result uploads into results/calibration/manual/.

import { createServer } from 'node:http';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { fileURLToPath } from 'node:url';
import { root } from '../preflight.mjs';

const CSP =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; connect-src 'self'; worker-src 'self'; img-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const FILES = {
  '/': ['index.html', 'text/html; charset=utf-8'],
  '/calibration/page.js': ['page.js', 'text/javascript'],
  '/calibration/worker.js': ['worker.js', 'text/javascript'],
  '/calibration/style.css': ['style.css', 'text/css'],
};
const MAX_UPLOAD_BYTES = 4 * 1024 * 1024;
const dist = new URL('dist/calibration/', root);
const manualDir = new URL('results/calibration/manual/', root);

const headers = {
  'Content-Security-Policy': CSP,
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

async function receive(req, res, onResult) {
  if (!/^application\/json\b/.test(req.headers['content-type'] ?? ''))
    return res.writeHead(415, headers).end();
  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_UPLOAD_BYTES) return res.writeHead(413, headers).end();
    chunks.push(c);
  }
  let report;
  try {
    report = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return res.writeHead(400, headers).end();
  }
  if (report?.kind !== 'argon2id-calibration') return res.writeHead(400, headers).end();
  const slug = String(report.deviceLabel || 'unlabelled')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 60);
  const name = `${new Date().toISOString().replace(/[:.]/g, '-')}-${slug || 'unlabelled'}.json`;
  await mkdir(manualDir, { recursive: true });
  await writeFile(new URL(name, manualDir), JSON.stringify(report, null, 2));
  onResult?.(name, report);
  res
    .writeHead(201, { ...headers, 'Content-Type': 'application/json' })
    .end(JSON.stringify({ saved: name }));
}

export async function startServer({ host = '127.0.0.1', port = 0, onResult } = {}) {
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    try {
      if (req.method === 'POST' && url.pathname === '/results')
        return await receive(req, res, onResult);
      const entry = req.method === 'GET' ? FILES[url.pathname] : undefined;
      if (!entry) return res.writeHead(404, headers).end();
      const body = await readFile(new URL(entry[0], dist));
      res.writeHead(200, { ...headers, 'Content-Type': entry[1] }).end(body);
    } catch {
      res.writeHead(500, headers).end();
    }
  });
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, resolve);
  });
  const a = server.address();
  return {
    server,
    origin: `http://${a.family === 'IPv6' ? `[${a.address}]` : a.address}:${a.port}`,
  };
}

const isLoopback = (h) => h === '127.0.0.1' || h === '::1' || h === 'localhost';

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const host = process.env.HOST || '127.0.0.1';
  const port = Number(process.env.PORT || 8787);
  if (host === '0.0.0.0' || host === '::' || (!isLoopback(host) && !isIP(host))) {
    console.error(
      'HOST must be 127.0.0.1 or one specific IP address of this computer, not all interfaces.',
    );
    process.exit(1);
  }
  await readFile(new URL('page.js', dist)).catch(() => {
    console.error('dist/calibration is missing; run npm run calibration:build first.');
    process.exit(1);
  });
  const { origin } = await startServer({
    host,
    port,
    onResult: (name) => console.log(`saved results/calibration/manual/${name}`),
  });
  console.log(`Benchmark page: ${origin}/`);
  if (!isLoopback(host))
    console.log(
      'WARNING: reachable by other devices that can reach this address. Use only on a network you trust, and stop with Ctrl+C when done.',
    );
  console.log('Press Ctrl+C to stop.');
}
