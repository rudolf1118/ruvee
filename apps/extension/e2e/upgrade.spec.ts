import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium, expect, test } from '@playwright/test';
import { EXTENSION_ID } from '../playwright.extension.config';

/**
 * Rehearsal bug, 2026-11-12: the unpacked extension's files were replaced by a newer build
 * without a reload. Chrome opened the new popup but kept the old service worker (even across a
 * worker restart), which refused the popup's new messages: "Something went wrong" and no save
 * offer. The popup now notices the other build and offers to reload. Needs no server.
 */

const built = new URL('../dist-test/', import.meta.url).pathname;
const BUILD_ID = /"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z"/g;

test('a popup newer than the running worker says so and offers a reload, instead of failing', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ruvee-ext-inplace-'));
  const profile = mkdtempSync(join(tmpdir(), 'ruvee-ext-inplace-profile-'));
  const ext = join(dir, 'ext');
  cpSync(built, ext, { recursive: true });
  // The "previous version": the same worker with another build id.
  const worker = readFileSync(join(ext, 'background.js'), 'utf8');
  expect(worker.match(BUILD_ID)?.length).toBe(1);
  writeFileSync(join(ext, 'background.js'), worker.replace(BUILD_ID, '"2000-01-01T00:00:00.000Z"'));

  const context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`],
  });
  try {
    await (context.serviceWorkers()[0] ?? context.waitForEvent('serviceworker'));
    // In use before the update: the old worker has answered the old pages.
    const popup = await context.newPage();
    await popup.goto(`chrome-extension://${EXTENSION_ID}/options.html`);
    await expect(popup.getByRole('heading', { name: 'Ruvee settings' })).toBeVisible();
    // The update copies the new files in place; the browser keeps the old worker running.
    cpSync(built, ext, { recursive: true });
    await popup.goto(`chrome-extension://${EXTENSION_ID}/popup.html`);
    await expect(popup.getByText(/still running the previous version/)).toBeVisible();
    await expect(popup.getByText(/Something went wrong/)).toHaveCount(0);

    await expect(popup.getByRole('button', { name: 'Reload Ruvee' })).toBeVisible();
    // Nothing but `status` reached the old worker: no request it would refuse.
    // The button itself (chrome.runtime.reload) is not exercised here: Chromium unloads an
    // extension given with --load-extension when it reloads itself, and does not bring it back.
    // With "Load unpacked" in Chrome it reloads from disk; that is a hand check.
  } finally {
    await context.close();
    rmSync(dir, { recursive: true, force: true });
    rmSync(profile, { recursive: true, force: true });
  }
});
