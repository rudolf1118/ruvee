// Test-only build: the ordinary pages plus `page.diag.tsx` routes, exported to out-diagnostics/
// with the diagnostic workers. The ordinary export (out/) is not touched; run the normal build
// afterwards if .next/ must match it, since both builds share .next/.
import { spawnSync } from 'node:child_process';
import { rm } from 'node:fs/promises';
import { bundleDiagnosticWorkers } from './bundle-diagnostic-workers.mjs';

const root = new URL('../', import.meta.url);
export const diagnosticsDir = new URL('out-diagnostics/', root);

await rm(diagnosticsDir, { recursive: true, force: true });
const result = spawnSync('node_modules/.bin/next', ['build'], {
  cwd: root.pathname,
  stdio: 'inherit',
  env: { ...process.env, NODE_ENV: 'production', RUVEE_DIAGNOSTICS: '1' },
});
if (result.status !== 0) process.exit(result.status ?? 1);
await bundleDiagnosticWorkers(diagnosticsDir);
