// Bundles the CSP-probe worker so the static export can load @ruvee/crypto under worker-src 'self'.
import { mkdir } from 'node:fs/promises';
import { build } from 'esbuild';

const root = new URL('../', import.meta.url);
const outfile = new URL('public/csp-probe-worker.js', root);

await mkdir(new URL('public/', root), { recursive: true });
await build({
  entryPoints: [new URL('src/csp-probe/crypto-worker.ts', root).pathname],
  outfile: outfile.pathname,
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: 'es2022',
  logLevel: 'warning',
  // libsodium.js probes for Node built-ins behind runtime checks that a browser never reaches.
  external: ['fs', 'path', 'crypto', 'url', 'module', 'worker_threads'],
});
console.log(`wrote ${outfile.pathname}`);
