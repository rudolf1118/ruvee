import { defineConfig, devices } from '@playwright/test';
import { DIAGNOSTICS_EXPORT_PORT, EXPORT_PORT } from './security-headers';

const port = Number(process.env.RUVEE_EXPORT_PORT ?? EXPORT_PORT);
const diagnosticsPort = Number(process.env.RUVEE_DIAGNOSTICS_PORT ?? DIAGNOSTICS_EXPORT_PORT);
const channel = process.env.PLAYWRIGHT_CHANNEL;
const viewport = { width: 1440, height: 900 };

export default defineConfig({
  testDir: './e2e-headers',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: 'retain-on-failure',
  },
  // A channel (a locally installed Chrome) only replaces the Chromium project.
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'], viewport, ...(channel ? { channel } : {}) },
    },
    { name: 'firefox', use: { ...devices['Desktop Firefox'], viewport } },
    { name: 'webkit', use: { ...devices['Desktop Safari'], viewport } },
  ],
  webServer: [
    {
      command: `node scripts/serve-export.mjs`,
      url: `http://127.0.0.1:${port}`,
      env: { RUVEE_EXPORT_DIR: 'out', RUVEE_EXPORT_PORT: String(port) },
      reuseExistingServer: false,
      timeout: 30_000,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
    },
    {
      command: `node scripts/serve-export.mjs`,
      url: `http://127.0.0.1:${diagnosticsPort}`,
      env: { RUVEE_EXPORT_DIR: 'out-diagnostics', RUVEE_EXPORT_PORT: String(diagnosticsPort) },
      reuseExistingServer: false,
      timeout: 30_000,
      gracefulShutdown: { signal: 'SIGTERM', timeout: 5_000 },
    },
  ],
});
