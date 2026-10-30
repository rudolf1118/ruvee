// Builds the unpacked extension into dist/ (or dist-test/ with RUVEE_EXTENSION_TEST=1).
// The test build differs only in __RUVEE_TEST__ and in host permission for 127.0.0.1, which the
// browser tests need because they cannot click a permission prompt (extension-design.md §6).
import { cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { build } from 'esbuild';

const test = process.env.RUVEE_EXTENSION_TEST === '1';
const root = new URL('../', import.meta.url);
const out = new URL(test ? 'dist-test/' : 'dist/', root);

await rm(out, { recursive: true, force: true });
await mkdir(out, { recursive: true });

const common = {
  bundle: true,
  platform: 'browser',
  target: 'chrome120',
  logLevel: 'warning',
  // Minified, not obfuscated; names stay readable enough for store review.
  minify: true,
  legalComments: 'none',
  define: { __RUVEE_TEST__: String(test), 'process.env.NODE_ENV': '"production"' },
};
await build({
  ...common,
  entryPoints: [new URL('src/background.ts', root).pathname],
  outfile: new URL('background.js', out).pathname,
  format: 'esm',
});
for (const page of ['popup', 'options'])
  await build({
    ...common,
    entryPoints: [new URL(`src/ui/${page}.tsx`, root).pathname],
    outfile: new URL(`${page}.js`, out).pathname,
    format: 'iife',
    jsx: 'automatic',
  });

await cp(new URL('static/', root), out, { recursive: true });
const manifest = JSON.parse(await readFile(new URL('manifest.json', root), 'utf8'));
if (test) {
  manifest.name = 'Ruvee (test build)';
  manifest.host_permissions = ['http://127.0.0.1/*'];
}
await writeFile(new URL('manifest.json', out), `${JSON.stringify(manifest, null, 2)}\n`);
console.log(`built ${out.pathname}`);
