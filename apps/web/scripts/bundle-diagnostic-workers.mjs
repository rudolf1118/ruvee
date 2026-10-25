// Bundles the diagnostic workers into <outdir>/diagnostics/ so they load under worker-src 'self'.
// Only scripts/build-diagnostics.mjs calls this; the ordinary export never contains them.
import { mkdir } from 'node:fs/promises';
import { build } from 'esbuild';

const root = new URL('../', import.meta.url);
const WORKERS = ['crypto-worker', 'opaque-worker'];

export async function bundleDiagnosticWorkers(outdir) {
  await mkdir(new URL('diagnostics/', outdir), { recursive: true });
  for (const name of WORKERS) {
    const outfile = new URL(`diagnostics/${name}.js`, outdir);
    await build({
      entryPoints: [new URL(`src/diagnostics/${name}.ts`, root).pathname],
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
  }
}
