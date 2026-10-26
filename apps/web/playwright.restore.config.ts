import { defineConfig, devices } from '@playwright/test';

/**
 * R14 (backup-restore.md §6): two devices against a server that is backed up, restored from an
 * encrypted backup into a new database and reviewed, under the same web origin. The test starts
 * and stops the API itself (e2e-restore/stack.ts); only the static export runs as a web server.
 * Needs RUVEE_E2E_ADMIN_DATABASE_URL, the PostgreSQL client tools of the server's version (or
 * RUVEE_PG_TOOLS_PREFIX), and prior builds of the API and the web export.
 */
export const WEB_PORT = Number(process.env.RUVEE_E2E_RESTORE_WEB_PORT ?? 3141);
export const API_PORT = WEB_PORT + 1000;
export const ORIGIN = `http://127.0.0.1:${String(WEB_PORT)}`;
const browser = (process.env.RUVEE_E2E_BROWSER ?? 'chromium') as 'chromium' | 'firefox' | 'webkit';
const device = { chromium: 'Desktop Chrome', firefox: 'Desktop Firefox', webkit: 'Desktop Safari' }[
  browser
];

export default defineConfig({
  testDir: './e2e-restore',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 300_000,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: ORIGIN,
    trace: 'retain-on-failure',
    viewport: { width: 1440, height: 900 },
    acceptDownloads: true,
  },
  projects: [
    { name: browser, use: { ...devices[device], viewport: { width: 1440, height: 900 } } },
  ],
  webServer: {
    command: 'node scripts/serve-export.mjs',
    url: ORIGIN,
    env: {
      RUVEE_EXPORT_DIR: 'out',
      RUVEE_EXPORT_PORT: String(WEB_PORT),
      RUVEE_API_ORIGIN: `http://127.0.0.1:${String(API_PORT)}`,
    },
    reuseExistingServer: false,
    timeout: 30_000,
    gracefulShutdown: { signal: 'SIGTERM' as const, timeout: 5_000 },
  },
});
