import { build } from 'esbuild';
import { mkdirSync, writeFileSync, copyFileSync, statSync } from 'node:fs';

const root = new URL('../', import.meta.url);
mkdirSync(new URL('dist/', root), { recursive: true });
const extensions = {
  'extension-default-csp': undefined,
  'extension-wasm-csp': {
    extension_pages: "script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
  },
};

const common = {
  entryPoints: [new URL('src/browser-entry.mjs', root).pathname],
  bundle: true,
  platform: 'browser',
  target: 'es2022',
  logLevel: 'warning',
  external: ['fs', 'path', 'crypto', 'url', 'module', 'worker_threads'],
};

await build({ ...common, format: 'iife', outfile: new URL('dist/page.js', root).pathname });
await build({ ...common, format: 'iife', outfile: new URL('dist/worker.js', root).pathname });
for (const [dir, csp] of Object.entries(extensions)) {
  mkdirSync(new URL(`dist/${dir}/kat/`, root), { recursive: true });
  await build({ ...common, format: 'esm', outfile: new URL(`dist/${dir}/sw.js`, root).pathname });
  const manifest = {
    manifest_version: 3,
    name: `Ruvee spike ${dir} (synthetic)`,
    version: '0.0.1',
    background: { service_worker: 'sw.js', type: 'module' },
    ...(csp ? { content_security_policy: csp } : {}),
  };
  writeFileSync(new URL(`dist/${dir}/manifest.json`, root), JSON.stringify(manifest, null, 2));
  for (const f of ['wycheproof-xchacha20_poly1305_test.json', 'blake2b-kat.txt']) {
    copyFileSync(new URL(`kat/${f}`, root), new URL(`dist/${dir}/kat/${f}`, root));
  }
}
for (const f of ['dist/page.js', 'dist/extension-wasm-csp/sw.js']) {
  console.log(f, `${Math.round(statSync(new URL(f, root)).size / 1024)} KiB`);
}
