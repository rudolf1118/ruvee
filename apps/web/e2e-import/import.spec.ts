import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { type BrowserContext, expect, type Page, test } from '@playwright/test';
import { INSTALLS, origin } from '../playwright.import.config';

/**
 * Export from installation A, restore into a separate, fresh installation B
 * (backup-restore.md §4.4a). Synthetic data only; every value below is a sentinel the capture
 * checks look for.
 */

const A_USER = 'synthetic-import-source';
const A_MASTER = 'synthetic source harbor lantern 31';
const B_USER = 'synthetic-import-target';
const B_MASTER = 'synthetic target harbor lantern 75';
const PORTAL_PASSWORD = 'synthetic-import-portal-secret-6b2';
const BANK_PASSWORD = 'synthetic-import-bank-secret-91c';
const NOTE_TEXT = 'synthetic import note body e47';

interface Captured {
  readonly bodies: string[];
  readonly urls: string[];
  readonly console: string[];
}

function capture(context: BrowserContext): Captured {
  const captured: Captured = { bodies: [], urls: [], console: [] };
  context.on('request', (request) => {
    captured.urls.push(request.url());
    const body = request.postData();
    if (body) captured.bodies.push(body);
  });
  context.on('page', (page) => {
    page.on('console', (msg) => captured.console.push(msg.text()));
  });
  return captured;
}

const token = (state: string) =>
  (JSON.parse(readFileSync(state, 'utf8')) as { bootstrapToken: string }).bootstrapToken;
const row = (page: Page, title: RegExp) =>
  page.locator('#item-list').getByRole('button', { name: title });
const sha = (bytes: Buffer) => createHash('sha256').update(bytes).digest('hex');

async function storedText(page: Page): Promise<string> {
  return page.evaluate(
    () =>
      new Promise<string>((resolve, reject) => {
        const req = indexedDB.open('ruvee');
        req.onerror = () => {
          reject(new Error('open failed'));
        };
        req.onsuccess = async () => {
          const db = req.result;
          const out: Record<string, unknown[]> = {};
          for (const name of Array.from(db.objectStoreNames))
            out[name] = await new Promise<unknown[]>((r) => {
              const all = db.transaction(name).objectStore(name).getAll();
              all.onsuccess = () => {
                r(all.result as unknown[]);
              };
            });
          db.close();
          resolve(
            JSON.stringify(out, (_k, v: unknown) =>
              v instanceof Uint8Array ? new TextDecoder('latin1').decode(v) : v,
            ),
          );
        };
      }),
  );
}

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

async function addLogin(page: Page, title: string, url: string, password: string) {
  await page.getByRole('button', { name: 'Add item' }).click();
  await page.getByLabel('Title (required)').fill(title);
  await page.getByLabel('Website').fill(url);
  await page.getByLabel('Username or email').fill('owner@portal.example');
  await page.getByRole('textbox', { name: 'Password', exact: true }).fill(password);
  await page.getByLabel('Tags').fill('work, imported');
  await page.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { level: 2, name: title })).toBeVisible();
}

test('restore an export from installation A into a fresh installation B', async ({ browser }) => {
  // ---- Installation A: an account with a login, a note, a login in Trash, a deleted item ----
  const contextA = await browser.newContext();
  const capturedA = capture(contextA);
  const a = await contextA.newPage();
  await a.goto(origin(INSTALLS.a.web));
  await a.getByRole('button', { name: 'Create an account' }).click();
  const kitA = await setUp(a, token(INSTALLS.a.state), A_USER, A_MASTER);
  await addLogin(a, 'Synthetic Portal', 'https://portal.example', PORTAL_PASSWORD);
  await a.getByRole('button', { name: 'Add item' }).click();
  await a.getByRole('radio', { name: 'Secure note' }).click();
  await a.getByLabel('Title (required)').fill('Synthetic Wi-Fi');
  await a.getByLabel('Note').fill(NOTE_TEXT);
  await a.getByRole('button', { name: 'Save' }).click();
  await expect(a.getByRole('heading', { level: 2, name: 'Synthetic Wi-Fi' })).toBeVisible();
  await addLogin(a, 'Synthetic Old Bank', 'https://bank.example', BANK_PASSWORD);
  await a.getByRole('button', { name: 'Move to Trash' }).click();
  await addLogin(a, 'Synthetic Deleted', 'https://deleted.example', 'synthetic-deleted-pw-0f');
  await a.getByRole('button', { name: 'Move to Trash' }).click();
  await a.getByRole('button', { name: /^Trash/ }).click();
  await row(a, /Synthetic Deleted/).click();
  await a.getByRole('button', { name: 'Delete permanently' }).click();
  await a.getByRole('button', { name: 'Delete permanently' }).click();
  await expect(row(a, /Synthetic Deleted/)).toHaveCount(0);
  await expect(a.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });

  await a.getByRole('button', { name: 'Security', exact: true }).click();
  const exportSection = a.getByRole('region', { name: 'Encrypted export' });
  await exportSection.getByLabel('Recovery Key for this export').fill(kitA);
  await exportSection.getByRole('textbox', { name: 'Master password', exact: true }).fill(A_MASTER);
  const downloading = a.waitForEvent('download');
  await exportSection.getByRole('button', { name: 'Download encrypted export' }).click();
  const exportPath = await (await downloading).path();
  const exportBefore = sha(readFileSync(exportPath));

  // ---- Installation B, a separate server and browser profile: open, preview, restore ----
  const contextB = await browser.newContext();
  const capturedB = capture(contextB);
  const b = await contextB.newPage();
  await b.goto(origin(INSTALLS.b.web));
  await b.getByRole('button', { name: 'Open an encrypted export' }).click();
  await b.getByLabel('Export file').setInputFiles(exportPath);
  await b.getByLabel('Recovery Key').fill(kitA);
  await b.getByRole('button', { name: /^Open / }).click();
  const preview = b.getByRole('region', { name: 'Restore preview' });
  await expect(preview).toBeVisible({ timeout: 30_000 });
  await expect(
    preview.getByText(
      /3 items will be imported: 2 logins and 1 secure notes, of which 1 stay in Trash/,
    ),
  ).toBeVisible();
  await expect(preview.getByText(/1 deleted items are only deletion markers/)).toBeVisible();
  await expect(preview.getByText(/creates a new account with new keys/)).toBeVisible();
  await b.getByRole('button', { name: 'Restore into a new account' }).click();
  await expect(b.getByText(/creating a new account to restore your export/)).toBeVisible();
  const kitB = await setUp(b, token(INSTALLS.b.state), B_USER, B_MASTER);
  expect(kitB).not.toBe(kitA);
  await expect(b.getByText(/Import complete: all 3 items/)).toBeVisible({ timeout: 30_000 });

  // ---- Lock, unlock with B's own credentials, and check every item ----
  await b.getByRole('button', { name: 'Lock now' }).click();
  await b.getByRole('textbox', { name: 'Master password', exact: true }).fill(A_MASTER);
  await b.getByRole('button', { name: 'Unlock' }).click();
  await expect(b.getByText("That's not the right master password.", { exact: false })).toBeVisible({
    timeout: 30_000,
  });
  await b.getByRole('textbox', { name: 'Master password', exact: true }).fill(B_MASTER);
  await b.getByRole('button', { name: 'Unlock' }).click();
  await expect(b.getByText('2 items in all vaults')).toBeVisible({ timeout: 30_000 });
  await row(b, /Synthetic Portal/).click();
  await b.getByRole('button', { name: 'Reveal password' }).click();
  await expect(b.getByText(PORTAL_PASSWORD)).toBeVisible();
  await expect(b.getByText('https://portal.example')).toBeVisible();
  await expect(b.getByRole('button', { name: 'Show items tagged imported' })).toBeVisible();
  await row(b, /Synthetic Wi-Fi/).click();
  // The text shows twice once rendered: as the list row's subtitle and in the detail.
  await expect(b.getByText(NOTE_TEXT).first()).toBeVisible();
  await b.getByRole('button', { name: /^Trash/ }).click();
  await row(b, /Synthetic Old Bank/).click();
  await expect(b.getByText(/This item is in Trash/)).toBeVisible();
  await expect(row(b, /Synthetic Deleted/)).toHaveCount(0);

  // ---- A and the export are unchanged ----
  expect(sha(readFileSync(exportPath))).toBe(exportBefore);
  await a.getByRole('button', { name: 'Sync now' }).click();
  await expect(a.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });
  await a.getByRole('button', { name: /^All items/ }).click();
  await expect(a.getByText('2 items in all vaults')).toBeVisible();

  // ---- Capture: no plaintext, no source kit or file on any wire, in logs or at rest ----
  const exportText = readFileSync(exportPath, 'utf8');
  const sourceRecords = (JSON.parse(exportText) as { items: { record: string | null }[] }).items
    .map((i) => i.record)
    .filter((r): r is string => r !== null);
  const forbidden = [
    A_MASTER,
    B_MASTER,
    PORTAL_PASSWORD,
    BANK_PASSWORD,
    NOTE_TEXT,
    'Synthetic Portal',
    'Synthetic Old Bank',
    kitA,
    kitA.replace(/-/g, ''),
    kitB,
    kitB.replace(/-/g, ''),
  ];
  for (const [name, captured] of [
    ['A', capturedA],
    ['B', capturedB],
  ] as const) {
    const wire = [...captured.urls, ...captured.bodies].join('\n');
    for (const secret of forbidden) expect(wire, `${name} wire: ${secret}`).not.toContain(secret);
    for (const secret of forbidden)
      expect(captured.console.join('\n'), `${name} console: ${secret}`).not.toContain(secret);
    expect(wire, `${name} uploaded the export`).not.toContain('ruvee-export');
  }
  const wireB = capturedB.bodies.join('\n');
  for (const record of sourceRecords) expect(wireB).not.toContain(record);
  for (const page of [a, b]) {
    const stored = await storedText(page);
    for (const secret of forbidden) expect(stored, `stored: ${secret}`).not.toContain(secret);
    for (const key of ['localStorage', 'sessionStorage'] as const)
      expect(await page.evaluate((k) => window[k].length, key)).toBe(0);
  }
  await contextA.close();
  await contextB.close();
});
