// Fails the production build if the development preview, its fixtures or the diagnostic routes
// (P2-04 CSP probes, `page.diag.tsx`) leaked into it.
import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';

const MARKER = 'ruvee-synthetic-preview-fixture';
const buildDir = new URL('../.next/', import.meta.url).pathname;
const problems = [];

const routes = JSON.parse(readFileSync(join(buildDir, 'app-path-routes-manifest.json'), 'utf8'));
for (const route of Object.values(routes)) {
  if (route === '/preview' || route.startsWith('/preview/'))
    problems.push(`route ${route} is in the build`);
  if (route === '/csp-probe' || route.startsWith('/csp-probe/'))
    problems.push(`diagnostic route ${route} is in the build`);
}

const exportDir = new URL('../out/', import.meta.url).pathname;
for (const path of ['csp-probe.html', 'csp-probe', 'diagnostics', 'csp-probe-worker.js']) {
  if (existsSync(join(exportDir, path)))
    problems.push(`diagnostic file out/${path} is in the export`);
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
  console.error('Development or diagnostic code leaked into the production build:');
  for (const problem of problems) console.error(`  - ${problem}`);
  process.exit(1);
}
console.log('OK: development preview and diagnostics are excluded from the production build.');
