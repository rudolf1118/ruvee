import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defineConfig, devices } from '@playwright/test';

/**
 * Browser end-to-end tests of the vault against the real API, on the static export with the
 * production headers. Needs a PostgreSQL server in RUVEE_E2E_ADMIN_DATABASE_URL whose role may
 * create databases; the stack creates and drops its own `ruvee_e2e_*` database. Needs prior
 * builds of the API and the web export. One engine per run (RUVEE_E2E_BROWSER), because the
 * server holds one account.
 */
const webPort = Number(process.env.RUVEE_E2E_WEB_PORT ?? 3103);
const apiPort = Number(process.env.RUVEE_E2E_API_PORT ?? 4101);
const origin = `http://127.0.0.1:${webPort}`;
// Outside test-results/, which Playwright empties when a run starts.
export const STATE_FILE = join(tmpdir(), `ruvee-vault-e2e-${String(webPort)}.json`);
const browser = (process.env.RUVEE_E2E_BROWSER ?? 'chromium') as 'chromium' | 'firefox' | 'webkit';
const device = { chromium: 'Desktop Chrome', firefox: 'Desktop Firefox', webkit: 'Desktop Safari' }[
  browser
];
const channel = process.env.PLAYWRIGHT_CHANNEL;

export default defineConfig({
  testDir: './e2e-vault',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 120_000,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: origin,
    trace: 'retain-on-failure',
    viewport: { width: 1440, height: 900 },
  },
  projects: [
    {
      name: browser,
      use: {
        ...devices[device],
        viewport: { width: 1440, height: 900 },
        ...(channel && browser === 'chromium' ? { channel } : {}),
      },
    },
  ],
  webServer: [
    {
      command: 'node ../api/scripts/e2e-stack.mjs',
      url: `http://127.0.0.1:${apiPort}/health/ready`,
      env: {
        RUVEE_E2E_STATE_FILE: STATE_FILE,
        RUVEE_E2E_API_PORT: String(apiPort),
        RUVEE_E2E_PUBLIC_ORIGIN: origin,
      },
      reuseExistingServer: false,
      timeout: 60_000,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 10_000 },
    },
    {
      command: 'node scripts/serve-export.mjs',
      url: origin,
      env: {
        RUVEE_EXPORT_DIR: 'out',
        RUVEE_EXPORT_PORT: String(webPort),
        RUVEE_API_ORIGIN: `http://127.0.0.1:${apiPort}`,
      },
      reuseExistingServer: false,
      timeout: 30_000,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
    },
  ],
});
