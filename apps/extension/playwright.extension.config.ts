import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { defineConfig } from '@playwright/test';

/**
 * The extension against the real API and the web app, in Chromium with the unpacked test build
 * (extension-design.md §6). Needs RUVEE_E2E_ADMIN_DATABASE_URL like the web vault suite, and prior
 * builds of the API and the web export.
 */
const webPort = Number(process.env.RUVEE_E2E_WEB_PORT ?? 3107);
const apiPort = Number(process.env.RUVEE_E2E_API_PORT ?? 4107);
export const WEB_ORIGIN = `http://127.0.0.1:${String(webPort)}`;
export const STATE_FILE = join(tmpdir(), `ruvee-extension-e2e-${String(webPort)}.json`);
/** The development build's fixed id, from the public key in manifest.json. */
export const EXTENSION_ID = 'ikjjmgfofphmclnkphkceboclijkfkbd';

export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  workers: 1,
  forbidOnly: !!process.env.CI,
  retries: 0,
  timeout: 180_000,
  reporter: process.env.CI ? 'github' : 'list',
  use: { trace: 'retain-on-failure' },
  webServer: [
    {
      command: 'node ../api/scripts/e2e-stack.mjs',
      url: `http://127.0.0.1:${String(apiPort)}/health/ready`,
      env: {
        RUVEE_E2E_STATE_FILE: STATE_FILE,
        RUVEE_E2E_API_PORT: String(apiPort),
        RUVEE_E2E_PUBLIC_ORIGIN: WEB_ORIGIN,
        RUVEE_E2E_EXTENSION_ORIGINS: `chrome-extension://${EXTENSION_ID}`,
      },
      reuseExistingServer: false,
      timeout: 60_000,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 10_000 },
    },
    {
      command: 'node ../web/scripts/serve-export.mjs',
      url: WEB_ORIGIN,
      env: {
        RUVEE_EXPORT_DIR: 'out',
        RUVEE_EXPORT_PORT: String(webPort),
        RUVEE_API_ORIGIN: `http://127.0.0.1:${String(apiPort)}`,
      },
      reuseExistingServer: false,
      timeout: 30_000,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
    },
  ],
});
