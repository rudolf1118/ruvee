import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { expect, type Page, test } from '@playwright/test';
import { INSTALLS, origin } from '../playwright.import.config';

/**
 * Moving an account from before D-31 to a fresh account (docs/security/device-proof.md §9,
 * docs/guides/legacy-account-migration.md): installation A's account is made pre-D-31 (no AVPK,
 * no device keys), its browser keeps working offline, the Recovery Kit is refused without
 * changing anything, and the verified copy moves to a fresh D-31 account on installation B. The
 * change no export can hold is named. Synthetic data only.
 */

const A_USER = 'synthetic-legacy-source';
const A_MASTER = 'synthetic legacy harbor lantern 18';
const B_USER = 'synthetic-legacy-target';
const B_MASTER = 'synthetic fresh harbor lantern 64';
const PORTAL_PASSWORD = 'synthetic-legacy-portal-secret-3d1';

const token = (state: string) =>
  (JSON.parse(readFileSync(state, 'utf8')) as { bootstrapToken: string }).bootstrapToken;
const row = (page: Page, title: RegExp) =>
  page.locator('#item-list').getByRole('button', { name: title });

async function setUp(page: Page, bootstrap: string, user: string, master: string) {
  await page.getByLabel('Setup token').fill(bootstrap);
  await page.getByLabel('Username').fill(user);
  await page.getByRole('button', { name: 'Continue' }).click();
  await page.getByRole('textbox', { name: 'Master password', exact: true }).fill(master);
  await page.getByRole('textbox', { name: 'Type it again', exact: true }).fill(master);
  await page.getByRole('checkbox').check();
  await page.getByRole('button', { name: 'Continue' }).click();
  const kit = (await page.getByTestId('recovery-key').innerText()).trim();
  await page.getByRole('button', { name: "I've saved it" }).click();
  await page.getByLabel('Recovery Key').fill(kit);
  await page.getByRole('button', { name: 'Finish setup' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'All items' })).toBeVisible({
    timeout: 30_000,
  });
  return kit;
}

async function addNote(page: Page, title: string) {
  await page.getByRole('button', { name: 'Add item' }).click();
  await page.getByRole('radio', { name: 'Secure note' }).click();
  await page.getByLabel('Title (required)').fill(title);
  await page.getByLabel('Note').fill('synthetic legacy note body');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { level: 2, name: title })).toBeVisible();
}

async function unlock(page: Page) {
  await page.getByRole('textbox', { name: 'Master password', exact: true }).fill(A_MASTER);
  await page.getByRole('button', { name: 'Unlock' }).click();
  await expect(page.getByText(/created before device keys and can no longer sync/)).toBeVisible({
    timeout: 30_000,
  });
}

/** As the development migration left a pre-D-31 browser: no `device-key` record. */
const dropLocalDeviceKey = (page: Page) =>
  page.evaluate(
    () =>
      new Promise<void>((resolve, reject) => {
        const req = indexedDB.open('ruvee');
        req.onerror = () => {
          reject(new Error('open failed'));
        };
        req.onsuccess = () => {
          const db = req.result;
          const tx = db.transaction('local', 'readwrite');
          tx.objectStore('local').delete('device-key');
          tx.oncomplete = () => {
            db.close();
            resolve();
          };
        };
      }),
  );

test('move a pre-D-31 account from installation A to a fresh account on B', async ({ browser }) => {
  // ---- A: a D-31 account with two synced items, then made pre-D-31 ----
  const contextA = await browser.newContext();
  const a = await contextA.newPage();
  await a.goto(origin(INSTALLS.a.web));
  await a.getByRole('button', { name: 'Create an account' }).click();
  const kitA = await setUp(a, token(INSTALLS.a.state), A_USER, A_MASTER);
  await a.getByRole('button', { name: 'Add item' }).click();
  await a.getByLabel('Title (required)').fill('Synthetic Legacy Portal');
  await a.getByLabel('Website').fill('https://portal.example');
  await a.getByRole('textbox', { name: 'Password', exact: true }).fill(PORTAL_PASSWORD);
  await a.getByRole('button', { name: 'Save' }).click();
  await addNote(a, 'Synthetic Legacy Note');
  await expect(a.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });
  // An edit the server never takes: made offline, it stays pending.
  await contextA.setOffline(true);
  await addNote(a, 'Synthetic Pending Note');
  await a.getByRole('button', { name: 'Lock now' }).click();
  await contextA.setOffline(false);
  execFileSync('node', ['../api/scripts/e2e-make-legacy.mjs', INSTALLS.a.state], {
    env: process.env,
  });
  await dropLocalDeviceKey(a);

  // ---- The browser keeps its copy offline and says it must move, not re-enroll ----
  await unlock(a);
  await expect(a.getByText('3 items in all vaults')).toBeVisible();

  // ---- The Recovery Kit is refused and changes nothing ----
  await a.getByRole('button', { name: 'Lock now' }).click();
  await a.getByRole('button', { name: /Use your Recovery Kit/ }).click();
  await a.getByLabel('Username').fill(A_USER);
  await a.getByLabel('Recovery Key').fill(kitA);
  await a.getByRole('button', { name: 'Continue' }).click();
  await expect(a.getByText(/created before device keys and can't be enrolled/)).toBeVisible({
    timeout: 30_000,
  });
  await a.getByRole('button', { name: 'Back' }).click();
  await unlock(a);
  await expect(a.getByText('3 items in all vaults')).toBeVisible();

  // ---- Security → Move to a new account: the pending note is named, the copy downloaded ----
  await a.getByRole('button', { name: 'Security', exact: true }).click();
  const move = a.getByRole('region', { name: 'Move to a new account' });
  await expect(move.getByText(/2 items in the last verified copy/)).toBeVisible();
  const missing = move.getByRole('list', { name: 'Not in the export' });
  await expect(missing.getByRole('listitem')).toHaveText(['Synthetic Pending Note (new)']);
  await expect(move.getByText(/not complete until you have copied each item/)).toBeVisible();
  await expect(move.getByRole('button', { name: /Erase/ })).toHaveCount(0);
  await move.getByLabel('Recovery Key for this export').fill(kitA);
  await move.getByRole('textbox', { name: 'Master password on this device' }).fill(A_MASTER);
  await move.getByRole('checkbox').check();
  const downloading = a.waitForEvent('download');
  await move.getByRole('button', { name: 'Download verified copy' }).click();
  const exportPath = await (await downloading).path();
  await expect(move.getByText(/Not in the file: 1 change waiting to sync/)).toBeVisible();

  // ---- B: a fresh installation and browser, a D-31 bootstrap, the import ----
  const contextB = await browser.newContext();
  const b = await contextB.newPage();
  await b.goto(origin(INSTALLS.b.web));
  await b.getByRole('button', { name: 'Open an encrypted export' }).click();
  await b.getByLabel('Export file').setInputFiles(exportPath);
  await b.getByLabel('Recovery Key').fill(kitA);
  await b.getByRole('button', { name: /^Open / }).click();
  await expect(b.getByRole('region', { name: 'Restore preview' })).toBeVisible({
    timeout: 30_000,
  });
  await b.getByRole('button', { name: 'Restore into a new account' }).click();
  const kitB = await setUp(b, token(INSTALLS.b.state), B_USER, B_MASTER);
  expect(kitB).not.toBe(kitA);
  await expect(b.getByText(/Import complete: all 2 items/)).toBeVisible({ timeout: 30_000 });
  await expect(b.getByText(/created before device keys/)).toHaveCount(0);
  await expect(row(b, /Synthetic Legacy Portal/)).toBeVisible();
  await expect(row(b, /Synthetic Legacy Note/)).toBeVisible();
  await expect(row(b, /Synthetic Pending Note/)).toHaveCount(0);
  await row(b, /Synthetic Legacy Portal/).click();
  await b.getByRole('button', { name: 'Reveal password' }).click();
  await expect(b.getByText(PORTAL_PASSWORD)).toBeVisible();
  // The new account syncs: its own device key and AVPK were set at bootstrap.
  await b.getByRole('button', { name: 'Sync now' }).click();
  await expect(b.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });

  // ---- A still holds everything, the pending note included ----
  await a.reload();
  await unlock(a);
  await expect(a.getByText('3 items in all vaults')).toBeVisible();
  await expect(row(a, /Synthetic Pending Note/)).toBeVisible();
  await contextA.close();
  await contextB.close();
});
