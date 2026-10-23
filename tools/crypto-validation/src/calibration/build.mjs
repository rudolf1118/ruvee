// Builds the benchmark page into dist/calibration/.

import { build } from 'esbuild';
import { copyFile, mkdir, stat } from 'node:fs/promises';
import { pinnedVersions, root } from '../preflight.mjs';

const versions = await pinnedVersions();
if (versions.problems.length) {
  console.error('Version preflight failed:\n  ' + versions.problems.join('\n  '));
  process.exit(1);
}
const out = new URL('dist/calibration/', root);
await mkdir(out, { recursive: true });
const common = {
  bundle: true,
  format: 'iife',
  platform: 'browser',
  target: 'es2022',
  logLevel: 'warning',
  define: { __PACKAGES__: JSON.stringify(versions.installed) },
  // libsodium.js probes for Node built-ins behind runtime checks; they are never reached in a browser.
  external: ['fs', 'path', 'crypto', 'url', 'module', 'worker_threads'],
};
for (const [entry, file] of [
  ['page.mjs', 'page.js'],
  ['worker-browser.mjs', 'worker.js'],
]) {
  await build({
    ...common,
    entryPoints: [new URL(`src/calibration/${entry}`, root).pathname],
    outfile: new URL(file, out).pathname,
  });
}
for (const f of ['index.html', 'style.css'])
  await copyFile(new URL(`src/calibration/static/${f}`, root), new URL(f, out));
for (const f of ['page.js', 'worker.js'])
  console.log(`dist/calibration/${f} ${Math.round((await stat(new URL(f, out))).size / 1024)} KiB`);
