/**
 * Serves the static export with the production security headers. Used by the P2-04 header tests
 * and as the local stand-in for Caddy (the Caddy binary is not required).
 */
import { createReadStream, existsSync, statSync } from 'node:fs';
import { createServer, request as httpRequest } from 'node:http';
import { extname, join, normalize, relative, resolve, sep } from 'node:path';
import {
  CACHE_HASHED_STATIC,
  CACHE_HTML,
  EXPORT_PORT,
  STATIC_SECURITY_HEADERS,
  isHashedStaticPath,
} from '../security-headers.ts';
import { exportDir, productionCsp } from './csp-from-export.mjs';

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.txt': 'text/plain; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
};

if (!existsSync(join(exportDir.pathname, 'index.html'))) {
  console.error(`Static export missing in ${exportDir.pathname}. Run the web build first.`);
  process.exit(1);
}

const csp = await productionCsp();
const port = Number(process.env.RUVEE_EXPORT_PORT ?? EXPORT_PORT);
// Same-origin API (api-design.md §Conventions): /api/* goes to the API, as Caddy does in
// deployment. Unset, /api/* is a 404 like any other missing file.
const apiOrigin = process.env.RUVEE_API_ORIGIN ? new URL(process.env.RUVEE_API_ORIGIN) : undefined;
if (apiOrigin && !['127.0.0.1', 'localhost', '[::1]'].includes(apiOrigin.hostname)) {
  console.error('RUVEE_API_ORIGIN must be a loopback address for this local server.');
  process.exit(1);
}

/** Streams the request to the API unchanged and its response back, without logging either. */
function proxyToApi(req, res) {
  const upstream = httpRequest(
    {
      hostname: apiOrigin.hostname,
      port: apiOrigin.port,
      method: req.method,
      path: req.url,
      headers: { ...req.headers, host: apiOrigin.host },
    },
    (apiRes) => {
      res.writeHead(apiRes.statusCode ?? 502, apiRes.headers);
      apiRes.pipe(res);
    },
  );
  upstream.on('error', () => {
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('API unavailable');
  });
  req.pipe(upstream);
}
const root = resolve(exportDir.pathname);

function headersFor(pathname, status) {
  const hashed = isHashedStaticPath(pathname);
  return {
    ...STATIC_SECURITY_HEADERS,
    'Content-Security-Policy': csp,
    'Cache-Control': hashed ? CACHE_HASHED_STATIC : CACHE_HTML,
    'X-Ruvee-Export-Status': String(status),
  };
}

function locate(urlPath) {
  const decoded = decodeURIComponent(urlPath.split('?')[0] ?? '/');
  const relativePath = decoded === '/' ? 'index.html' : decoded.replace(/^\/+/, '');
  const candidate = normalize(join(root, relativePath));
  const rel = relative(root, candidate);
  if (rel.startsWith('..') || rel.startsWith(`..${sep}`)) return undefined;
  if (existsSync(candidate) && statSync(candidate).isFile()) return candidate;
  if (existsSync(`${candidate}.html`) && statSync(`${candidate}.html`).isFile())
    return `${candidate}.html`;
  const asIndex = join(candidate, 'index.html');
  if (existsSync(asIndex) && statSync(asIndex).isFile()) return asIndex;
  return undefined;
}

const server = createServer((req, res) => {
  const url = new URL(req.url ?? '/', `http://127.0.0.1:${port}`);
  if (apiOrigin && url.pathname.startsWith('/api/')) {
    proxyToApi(req, res);
    return;
  }
  const file = locate(url.pathname);
  if (file === undefined) {
    const fallback = join(root, '404.html');
    const status = 404;
    const headers = headersFor(url.pathname, status);
    if (!existsSync(fallback)) {
      res.writeHead(status, { ...headers, 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not found');
      return;
    }
    res.writeHead(status, { ...headers, 'Content-Type': 'text/html; charset=utf-8' });
    createReadStream(fallback).pipe(res);
    return;
  }
  const pathname = '/' + relative(root, file).split(sep).join('/');
  const type = TYPES[extname(file).toLowerCase()] ?? 'application/octet-stream';
  res.writeHead(200, { ...headersFor(pathname, 200), 'Content-Type': type });
  createReadStream(file).pipe(res);
});

await new Promise((resolve) => {
  server.listen(port, '127.0.0.1', resolve);
});
const address = server.address();
if (address === null || typeof address === 'string')
  throw new Error('export server failed to bind');
console.log(`export server http://127.0.0.1:${address.port}`);
