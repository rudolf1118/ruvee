// Fails the production build if the development preview or its fixtures leaked into it.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const MARKER = 'ruvee-synthetic-preview-fixture';
const buildDir = new URL('../.next/', import.meta.url).pathname;
const problems = [];

const routes = JSON.parse(readFileSync(join(buildDir, 'app-path-routes-manifest.json'), 'utf8'));
for (const route of Object.values(routes)) {
  if (route === '/preview' || route.startsWith('/preview/'))
    problems.push(`route ${route} is in the build`);
}

// `.next/dev` belongs to `next dev`, which legitimately contains the preview.
const skipped = new Set([join(buildDir, 'cache'), join(buildDir, 'dev')]);

function scan(dir) {
  for (const name of readdirSync(dir)) {
    if (skipped.has(join(dir, name))) continue;
    const path = join(dir, name);
    if (statSync(path).isDirectory()) scan(path);
    else if (
      /\.(js|json|html|rsc|txt|map)$/.test(name) &&
      readFileSync(path, 'utf8').includes(MARKER)
    ) {
      problems.push(`fixture marker found in ${path.slice(buildDir.length)}`);
    }
  }
}
scan(buildDir);

if (problems.length) {
  console.error('Development preview leaked into the production build:');
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}
console.log('OK: development preview is excluded from the production build.');
