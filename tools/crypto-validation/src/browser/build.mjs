// Bundles the shared suite into one IIFE served to the page and to the dedicated worker.

import { build } from 'esbuild';
import { mkdir, stat } from 'node:fs/promises';
import { pinnedVersions, root } from '../preflight.mjs';

const versions = await pinnedVersions();
if (versions.problems.length) {
  console.error('Version preflight failed:\n  ' + versions.problems.join('\n  '));
  process.exit(1);
}
await mkdir(new URL('dist/', root), { recursive: true });
const outfile = new URL('dist/validation.js', root).pathname;
await build({
  entryPoints: [new URL('src/browser/entry.mjs', root).pathname],
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: 'es2022',
  logLevel: 'warning',
  outfile,
  define: { __PACKAGES__: JSON.stringify(versions.installed) },
  // libsodium.js probes for Node built-ins behind runtime checks; they are never reached in a browser.
  external: ['fs', 'path', 'crypto', 'url', 'module', 'worker_threads'],
});
console.log(`dist/validation.js ${Math.round((await stat(outfile)).size / 1024)} KiB`);
