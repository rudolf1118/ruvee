import { readFileSync } from 'node:fs';
import { expect, test, type Page } from '@playwright/test';
import { API_PORT, ORIGIN } from '../playwright.restore.config';
import { RestoreStack } from './stack';

/**
 * R14 (backup-restore.md §3.12, §6): device A is ahead of the backup and holds a pending edit;
 * device B is at the snapshot. The server is backed up with age, restored into a new database
 * with the operator's identity and trusted digest, reviewed and opened. A keeps every newer
 * item, read-only, explains the restore, exports its verified copy offline (saying what is not
 * in it), and is erased only after a typed confirmation. B continues. Synthetic data only.
 */

const USERNAME = 'synthetic-restore-owner';
const MASTER = 'synthetic restore harbor lantern 61';
const NEW_MASTER = 'synthetic reopened harbor lantern 62';
/** What the second test restores again: the backup, and the kit as of the backup. */
let saved: { backup: { manifest: string; digest: string }; kit: string } | undefined;

/** Everything this origin keeps in the browser: IndexedDB, both storages, script cookies. */
async function browserStorageText(page: Page): Promise<string> {
  return page.evaluate(async () => {
    const dump = (storage: Storage) =>
      JSON.stringify(
        Array.from({ length: storage.length }, (_, i) => {
          const k = storage.key(i) ?? '';
          return [k, storage.getItem(k)];
        }),
      );
    const parts = [dump(localStorage), dump(sessionStorage)];
    parts.push(document.cookie);
    for (const info of await indexedDB.databases()) {
      if (!info.name) continue;
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const req = indexedDB.open(info.name ?? '');
        req.onsuccess = () => {
          resolve(req.result);
        };
        req.onerror = () => {
          reject(new Error('open failed'));
        };
      });
      for (const name of Array.from(db.objectStoreNames))
        parts.push(
          await new Promise<string>((resolve) => {
            const all = db.transaction(name).objectStore(name).getAll();
            all.onsuccess = () => {
              resolve(
                JSON.stringify(all.result, (_k, v: unknown) =>
                  v instanceof Uint8Array ? new TextDecoder('latin1').decode(v) : v,
                ),
              );
            };
          }),
        );
      db.close();
    }
    return parts.join('\n');
  });
}

const row = (page: Page, title: RegExp) =>
  page.locator('#item-list').getByRole('button', { name: title });

async function addLogin(page: Page, title: string) {
  await page.getByRole('button', { name: 'Add item' }).click();
  await page.getByLabel('Title (required)').fill(title);
  await page.getByLabel('Website').fill('https://restore.example');
  await page.getByRole('textbox', { name: 'Password', exact: true }).fill(`${title} secret`);
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { level: 2, name: title })).toBeVisible();
}

test.describe.configure({ mode: 'serial' });

let stack: RestoreStack;
test.beforeAll(async () => {
  stack = new RestoreStack(API_PORT, ORIGIN);
  await stack.init();
});
test.afterAll(async () => {
  await stack.cleanup();
});

test('R14: a restored server, a device ahead with a pending edit, and a device in step', async ({
  browser,
}) => {
  const contextA = await browser.newContext();
  const contextB = await browser.newContext();
  const a = await contextA.newPage();
  const b = await contextB.newPage();

  // ---- A sets up the account and saves an item; B is paired and synced ----
  await a.goto('/');
  await a.getByRole('button', { name: 'Create an account' }).click();
  await a.getByLabel('Setup token').fill(stack.bootstrapToken);
  await a.getByLabel('Username').fill(USERNAME);
  await a.getByRole('button', { name: 'Continue' }).click();
  await a.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await a.getByRole('textbox', { name: 'Type it again', exact: true }).fill(MASTER);
  await a.getByRole('checkbox').check();
  await a.getByRole('button', { name: 'Continue' }).click();
  const kit = (await a.getByTestId('recovery-key').innerText()).trim();
  await a.getByRole('button', { name: "I've saved it" }).click();
  await a.getByLabel('Recovery Key').fill(kit);
  await a.getByRole('button', { name: 'Finish setup' }).click();
  await expect(a.getByRole('heading', { level: 1, name: 'All items' })).toBeVisible({
    timeout: 30_000,
  });
  await addLogin(a, 'Before the backup');
  await expect(a.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });

  await b.goto('/');
  await b.getByRole('button', { name: 'I already have an account' }).click();
  await b.getByLabel('Username').fill(USERNAME);
  await b.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await b.getByRole('button', { name: 'Log in' }).click();
  await expect(b.getByRole('heading', { name: 'Add this device' })).toBeVisible({
    timeout: 30_000,
  });
  await a.getByRole('button', { name: 'Devices' }).click();
  await a.getByRole('button', { name: 'Add a device' }).click();
  const codeBox = a.getByTestId('pairing-code');
  await expect(codeBox).toHaveText(/^PC1-/);
  const code = (await codeBox.innerText()).trim();
  await b.getByLabel('Pairing code').fill(code);
  await b.getByRole('button', { name: 'Add this device' }).click();
  await expect(b.getByText('Waiting for approval on your other device')).toBeVisible();
  await expect(a.getByText(/Approve a new\s+web browser/)).toBeVisible({ timeout: 15_000 });
  await a.getByRole('button', { name: 'Approve' }).click();
  await a.getByRole('button', { name: 'Done' }).click();
  await expect(
    b.getByText('1 items in all vaults').or(b.getByText('1 item in all vaults')),
  ).toBeVisible({
    timeout: 30_000,
  });
  // B stays at the snapshot: locked, it does not sync.
  await b.getByRole('button', { name: 'Lock now' }).click();

  // ---- The operator backs up; A then moves ahead, and makes an edit the server never sees ----
  const backup = stack.backup();
  expect(backup.digest).toMatch(/^[0-9a-f]{64}$/);
  saved = { backup, kit };
  await addLogin(a, 'After the backup');
  await expect(a.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });
  await stack.stop();
  await addLogin(a, 'Pending on this device');
  await a.getByRole('button', { name: 'Sync now' }).click();
  await expect(a.getByRole('status').filter({ hasText: 'Offline' })).toBeVisible({
    timeout: 15_000,
  });

  // ---- Restore into a new database: maintenance until the review is complete ----
  const restored = stack.restore(backup);
  expect(restored.restoreId).toMatch(/^[0-9a-f-]{36}$/);
  await stack.start(restored.database);
  await a.getByRole('button', { name: 'Sync now' }).click();
  await expect(a.getByRole('status').filter({ hasText: 'Server unavailable' })).toBeVisible({
    timeout: 15_000,
  });
  await expect(a.getByText(/being restored by its owner/).first()).toBeVisible();
  // Read-only: nothing new can be added while the server is closed.
  await a.getByRole('button', { name: 'Add item' }).click();
  await expect(a.getByLabel('Title (required)')).toHaveCount(0);
  await expect(row(a, /Pending on this device/)).toBeVisible();

  const review = stack.review(restored.database);
  expect(review).toContain('Provenance: the digest matched');
  expect(review).toMatch(/For the reopening only/);
  const firstCode = stack.complete(restored.database, restored.restoreId);
  expect(firstCode).toMatch(/^RC1-/);

  // ---- Reopening: still closed; the owner reopens from A with the code (password path) ----
  await a.getByRole('button', { name: 'Sync now' }).click();
  await expect(a.getByRole('status').filter({ hasText: 'Waiting to be reopened' })).toBeVisible({
    timeout: 15_000,
  });
  await a.getByRole('button', { name: 'Reopen the server' }).click();
  await a.getByLabel('Reopening code').fill(firstCode);
  await a
    .getByRole('textbox', { name: 'Master password at the time of the backup' })
    .fill('synthetic wrong guess 77');
  await a.getByRole('button', { name: 'Continue' }).click();
  await expect(a.getByText(/reopening code, username or credential doesn't work/)).toBeVisible();
  // The host retry path: a new code; the first one stops working.
  const reopenCode = stack.reopenCode(restored.database, restored.restoreId);
  await a.getByLabel('Reopening code').fill(firstCode);
  await a.getByRole('textbox', { name: 'Master password at the time of the backup' }).fill(MASTER);
  await a.getByRole('button', { name: 'Continue' }).click();
  await expect(a.getByText(/reopening code, username or credential doesn't work/)).toBeVisible();
  await a.getByLabel('Reopening code').fill(reopenCode);
  await a.getByRole('textbox', { name: 'Master password at the time of the backup' }).fill(MASTER);
  await a.getByRole('button', { name: 'Continue' }).click();
  await a.getByRole('textbox', { name: 'New master password', exact: true }).fill(NEW_MASTER);
  await a.getByRole('textbox', { name: 'Type it again', exact: true }).fill(NEW_MASTER);
  await a.getByRole('button', { name: 'Continue' }).click();
  await expect(a.getByRole('heading', { name: 'Save your new Recovery Kit' })).toBeVisible({
    timeout: 30_000,
  });
  const newKit = (await a.getByTestId('recovery-key').innerText()).trim();
  expect(newKit).not.toBe(kit);
  await a.getByRole('button', { name: "I've saved it" }).click();
  // The new kit is checked before the old one is retired.
  await a.getByLabel('Recovery Key').fill(kit);
  await a.getByRole('button', { name: 'Finish and reopen' }).click();
  await expect(a.getByText(/doesn't match/)).toBeVisible();
  await a.getByLabel('Recovery Key').fill(newKit);
  await a.getByRole('button', { name: 'Finish and reopen' }).click();
  await expect(a.getByText(/The server is open again/)).toBeVisible({ timeout: 30_000 });
  // A is ahead of the restored server and keeps everything, read-only.
  await expect(a.getByText(/reports that it was restored from a backup/).first()).toBeVisible({
    timeout: 30_000,
  });
  await expect(a.getByRole('status').filter({ hasText: 'Sync paused' })).toBeVisible();
  for (const title of [/Before the backup/, /After the backup/, /Pending on this device/])
    await expect(row(a, title)).toBeVisible();
  // The code was never kept by the browser.
  const stored = await browserStorageText(a);
  for (const c of [firstCode, reopenCode]) expect(stored).not.toContain(c);

  // ---- The restore help: an offline verified copy, then an explicit erase ----
  await a.getByRole('button', { name: 'What to do' }).click();
  const help = a.getByRole('region', { name: 'After a server restore' });
  await expect(help).toBeVisible();
  await expect(help.getByText(/2 items in the last verified copy/)).toBeVisible();
  await expect(help.getByText(/1 change waiting to sync/)).toBeVisible();
  await help.getByLabel('Recovery Key for this export').fill(kit);
  await help.getByRole('textbox', { name: 'Master password on this device' }).fill(NEW_MASTER);
  // Without the acknowledgement, the export is refused: the pending edit is not in it.
  await help.getByRole('button', { name: 'Download verified copy' }).click();
  await expect(help.getByText(/still waiting to sync/)).toBeVisible();
  await help.getByRole('checkbox', { name: /will not be in the file/ }).check();
  const downloading = a.waitForEvent('download');
  await help.getByRole('button', { name: 'Download verified copy' }).click();
  const download = await downloading;
  expect(download.suggestedFilename()).toMatch(/^ruvee-export-\d{4}-\d{2}-\d{2}-verified\.ruvee$/);
  await expect(help.getByText(/Not in the file: 1 change waiting to sync/)).toBeVisible();
  const exportPath = await download.path();

  // Erasing needs the exact typed confirmation.
  const erase = help.getByRole('button', { name: 'Erase this device' });
  await expect(erase).toHaveAttribute('aria-disabled', 'true');
  await help.getByLabel('Type "erase this device" to confirm').fill('erase');
  await expect(erase).toHaveAttribute('aria-disabled', 'true');
  await expect(row(a, /Pending on this device/)).toBeVisible();
  await help.getByLabel('Type "erase this device" to confirm').fill('erase this device');
  await expect(erase).not.toHaveAttribute('aria-disabled', 'true');
  await erase.click();
  // Nothing of the account is left on A: it is a new browser again.
  await expect(
    a.getByRole('heading', { name: 'Keep every password in one calm, safe place.' }),
  ).toBeVisible({ timeout: 30_000 });
  await expect(row(a, /Pending on this device/)).toHaveCount(0);

  // ---- The verified copy opens anywhere with the kit: the two verified items, not the pending
  // edit, which the user acknowledged and then chose to erase ----
  const contextC = await browser.newContext();
  const c = await contextC.newPage();
  await c.goto('/');
  await c.getByRole('button', { name: 'Open an encrypted export' }).click();
  await c.getByLabel('Export file').setInputFiles(exportPath);
  await c.getByLabel('Recovery Key').fill(kit);
  await c.getByRole('button', { name: /^Open / }).click();
  await expect(c.getByText(/2 items will be imported/)).toBeVisible({ timeout: 30_000 });
  expect(readFileSync(exportPath, 'utf8')).not.toContain('Pending on this device');

  // ---- B, in step with the snapshot, continues with the new password ----
  await b.getByRole('textbox', { name: 'Master password', exact: true }).fill(NEW_MASTER);
  await b.getByRole('button', { name: 'Unlock' }).click();
  await expect(b.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 30_000,
  });
  await expect(row(b, /Before the backup/)).toBeVisible();
  await expect(row(b, /After the backup/)).toHaveCount(0);

  await contextA.close();
  await contextB.close();
  await contextC.close();
});

test('reopening on a new browser with the Recovery Kit as of the backup', async ({ browser }) => {
  if (!saved) throw new Error('the first test did not run');
  // The same backup again, into another new database: a second, independent restore.
  await stack.stop();
  const restored = stack.restore(saved.backup);
  await stack.start(restored.database);
  const code = stack.complete(restored.database, restored.restoreId);

  const context = await browser.newContext();
  const c = await context.newPage();
  await c.goto('/');
  await c.getByRole('button', { name: 'Reopen a restored server with your Recovery Kit' }).click();
  await c.getByLabel('Reopening code').fill(code);
  await c.getByLabel('Username').fill(USERNAME);
  await c.getByLabel('Recovery Key').fill(saved.kit);
  await c.getByRole('button', { name: 'Continue' }).click();
  await c.getByRole('textbox', { name: 'New master password', exact: true }).fill(NEW_MASTER);
  await c.getByRole('textbox', { name: 'Type it again', exact: true }).fill(NEW_MASTER);
  await c.getByRole('button', { name: 'Continue' }).click();
  await expect(c.getByRole('heading', { name: 'Save your new Recovery Kit' })).toBeVisible({
    timeout: 30_000,
  });
  const newKit = (await c.getByTestId('recovery-key').innerText()).trim();
  await c.getByRole('button', { name: "I've saved it" }).click();
  await c.getByLabel('Recovery Key').fill(newKit);
  await c.getByRole('button', { name: 'Finish and reopen' }).click();
  await expect(c.getByRole('heading', { level: 1, name: 'All items' })).toBeVisible({
    timeout: 30_000,
  });
  await expect(row(c, /Before the backup/)).toBeVisible();
  expect(await browserStorageText(c)).not.toContain(code);

  // Afterwards: the password and the kit as of the backup are refused; the new password works.
  const d = await (await browser.newContext()).newPage();
  await d.goto('/');
  await d.getByRole('button', { name: 'I already have an account' }).click();
  await d.getByLabel('Username').fill(USERNAME);
  await d.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await d.getByRole('button', { name: 'Log in' }).click();
  await expect(d.getByText('The username or master password is not correct.')).toBeVisible();
  await d.getByRole('textbox', { name: 'Master password', exact: true }).fill(NEW_MASTER);
  await d.getByRole('button', { name: 'Log in' }).click();
  await expect(d.getByRole('heading', { name: 'Add this device' })).toBeVisible({
    timeout: 30_000,
  });
  await d.goto('/');
  const e = await (await browser.newContext()).newPage();
  await e.goto('/');
  await e.getByRole('button', { name: /Use your Recovery Kit/ }).click();
  await e.getByLabel('Username').fill(USERNAME);
  await e.getByLabel('Recovery Key').fill(saved.kit);
  await e.getByRole('button', { name: 'Continue' }).click();
  await expect(e.getByText(/username and Recovery Key don't work together/)).toBeVisible();
  await context.close();
});
