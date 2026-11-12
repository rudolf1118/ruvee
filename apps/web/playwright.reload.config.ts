import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defineConfig, devices } from '@playwright/test';

/**
 * D-34 web reload tickets in a real browser against the real API (docs/security/
 * web-reload-unlock.md §7): its own installation, ports and throwaway `ruvee_e2e_*` database, as
 * the vault suite's. Needs RUVEE_E2E_ADMIN_DATABASE_URL (the spec also reads and ages the ticket
 * rows there) and prior builds of the API and the web export. One engine per run.
 */
const webPort = Number(process.env.RUVEE_E2E_RELOAD_WEB_PORT ?? 3161);
const apiPort = Number(process.env.RUVEE_E2E_RELOAD_API_PORT ?? 4161);
const origin = `http://127.0.0.1:${webPort}`;
// Outside test-results/, which Playwright empties when a run starts.
export const STATE_FILE = join(tmpdir(), `ruvee-reload-e2e-${String(webPort)}.json`);
const browser = (process.env.RUVEE_E2E_BROWSER ?? 'chromium') as 'chromium' | 'firefox' | 'webkit';
const device = { chromium: 'Desktop Chrome', firefox: 'Desktop Firefox', webkit: 'Desktop Safari' }[
  browser
];
const channel = process.env.PLAYWRIGHT_CHANNEL;

export default defineConfig({
  testDir: './e2e-reload',
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
