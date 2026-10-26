import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defineConfig, devices } from '@playwright/test';

/**
 * Restoring an export into a fresh installation (backup-restore.md §4.4a): two independent
 * installations, each with its own API, throwaway database and web origin, as two servers would
 * be. Needs RUVEE_E2E_ADMIN_DATABASE_URL and prior builds of the API and the web export.
 */
const base = Number(process.env.RUVEE_E2E_IMPORT_PORT ?? 3121);
export const INSTALLS = {
  a: {
    web: base,
    api: base + 1000,
    state: join(tmpdir(), `ruvee-import-e2e-a-${String(base)}.json`),
  },
  b: {
    web: base + 1,
    api: base + 1001,
    state: join(tmpdir(), `ruvee-import-e2e-b-${String(base + 1)}.json`),
  },
} as const;
export const origin = (port: number) => `http://127.0.0.1:${String(port)}`;
const browser = (process.env.RUVEE_E2E_BROWSER ?? 'chromium') as 'chromium' | 'firefox' | 'webkit';
const device = { chromium: 'Desktop Chrome', firefox: 'Desktop Firefox', webkit: 'Desktop Safari' }[
  browser
];

export default defineConfig({
  testDir: './e2e-import',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 240_000,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    trace: 'retain-on-failure',
    viewport: { width: 1440, height: 900 },
    acceptDownloads: true,
  },
  projects: [
    { name: browser, use: { ...devices[device], viewport: { width: 1440, height: 900 } } },
  ],
  webServer: (['a', 'b'] as const).flatMap((name) => {
    const install = INSTALLS[name];
    return [
      {
        command: 'node ../api/scripts/e2e-stack.mjs',
        url: `${origin(install.api)}/health/ready`,
        env: {
          RUVEE_E2E_STATE_FILE: install.state,
          RUVEE_E2E_API_PORT: String(install.api),
          RUVEE_E2E_PUBLIC_ORIGIN: origin(install.web),
        },
        reuseExistingServer: false,
        timeout: 60_000,
        gracefulShutdown: { signal: 'SIGTERM' as const, timeout: 10_000 },
      },
      {
        command: 'node scripts/serve-export.mjs',
        url: origin(install.web),
        env: {
          RUVEE_EXPORT_DIR: 'out',
          RUVEE_EXPORT_PORT: String(install.web),
          RUVEE_API_ORIGIN: origin(install.api),
        },
        reuseExistingServer: false,
        timeout: 30_000,
        gracefulShutdown: { signal: 'SIGTERM' as const, timeout: 5_000 },
      },
    ];
  }),
});
