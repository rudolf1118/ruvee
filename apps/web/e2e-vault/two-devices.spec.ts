import { readFileSync } from 'node:fs';
import AxeBuilder from '@axe-core/playwright';
import { type BrowserContext, expect, type Page, test } from '@playwright/test';
import { STATE_FILE } from '../playwright.vault.config';

/**
 * The whole web-vault workflow in two browser contexts (two devices) against the real API:
 * account setup with the Recovery Kit check, items, pairing a second device, sync both ways,
 * an offline edit that conflicts, lock and unlock, and the INV-01 / INV-16 capture checks.
 * Synthetic data only.
 */

const USERNAME = 'synthetic-e2e-owner';
const MASTER = 'synthetic e2e harbor lantern 58';
const ITEM_PASSWORD = 'synthetic-e2e-item-secret-3e9';
const NOTE_TEXT = 'synthetic note body 41f';
const RECOVERED = 'synthetic recovered lantern 93';
const CHANGED = 'synthetic changed lantern 27';

interface Captured {
  readonly urls: string[];
  readonly bodies: string[];
  readonly headers: string[];
}

function capture(context: BrowserContext): Captured {
  const captured: Captured = { urls: [], bodies: [], headers: [] };
  context.on('request', (request) => {
    captured.urls.push(request.url());
    captured.headers.push(JSON.stringify(request.headers()));
    const body = request.postData();
    if (body) captured.bodies.push(body);
  });
  return captured;
}

async function indexedDbText(page: Page): Promise<string> {
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
          for (const name of Array.from(db.objectStoreNames)) {
            out[name] = await new Promise<unknown[]>((r) => {
              const all = db.transaction(name).objectStore(name).getAll();
              all.onsuccess = () => {
                r(all.result as unknown[]);
              };
            });
          }
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

function bootstrapToken(): string {
  return (JSON.parse(readFileSync(STATE_FILE, 'utf8')) as { bootstrapToken: string })
    .bootstrapToken;
}

/** A row of the item list, by title. */
function row(page: Page, title: RegExp) {
  return page.locator('#item-list').getByRole('button', { name: title });
}

async function expectAccessible(page: Page) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
    .analyze();
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([]);
}

test.describe.configure({ mode: 'serial' });

test('devices: setup, items, pairing, sync, conflict, lock, recovery, password change, removal, SK and kit rotation', async ({
  browser,
}) => {
  test.setTimeout(300_000);
  const contextA = await browser.newContext();
  const contextB = await browser.newContext();
  const capturedA = capture(contextA);
  const capturedB = capture(contextB);
  const a = await contextA.newPage();
  const b = await contextB.newPage();
  const cspErrors: string[] = [];
  for (const page of [a, b])
    page.on('console', (msg) => {
      if (/content.security.policy|refused to/i.test(msg.text())) cspErrors.push(msg.text());
    });

  // ---- Device A: account setup (authentication.md §3, account-recovery.md §2) ----
  await a.goto('/');
  await expect(
    a.getByRole('heading', { name: 'Keep every password in one calm, safe place.' }),
  ).toBeVisible();
  await expectAccessible(a);
  await a.getByRole('button', { name: 'Create an account' }).click();
  await a.getByLabel('Setup token').fill(bootstrapToken());
  await a.getByLabel('Username').fill(USERNAME);
  await a.getByRole('button', { name: 'Continue' }).click();
  await a.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await a.getByRole('textbox', { name: 'Type it again', exact: true }).fill(MASTER);
  await a.getByRole('checkbox').check();
  await expectAccessible(a);
  await a.getByRole('button', { name: 'Continue' }).click();
  const kit = (await a.getByTestId('recovery-key').innerText()).trim();
  expect(kit).toMatch(/^RK1-/);
  await a.getByRole('button', { name: "I've saved it" }).click();
  await a.getByLabel('Recovery Key').fill(`${kit.slice(0, -1)}${kit.endsWith('0') ? '1' : '0'}`);
  await a.getByRole('button', { name: 'Finish setup' }).click();
  await expect(a.getByText(/has a typo|doesn't match/)).toBeVisible();
  await a.getByLabel('Recovery Key').fill(kit.toLowerCase());
  await a.getByRole('button', { name: 'Finish setup' }).click();
  await expect(a.getByRole('heading', { level: 1, name: 'All items' })).toBeVisible({
    timeout: 30_000,
  });
  await expect(a.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible();

  // ---- Device A: a login and a secure note ----
  await a.getByRole('button', { name: 'Add item' }).click();
  await a.getByLabel('Title (required)').fill('Synthetic Mail');
  await a.getByLabel('Website').fill('https://mail.example');
  await a.getByLabel('Username or email').fill('owner@mail.example');
  await a.getByRole('textbox', { name: 'Password', exact: true }).fill(ITEM_PASSWORD);
  await a.getByLabel('Tags').fill('work, email');
  await a.getByRole('button', { name: 'Save' }).click();
  await expect(a.getByRole('heading', { level: 2, name: 'Synthetic Mail' })).toBeVisible();
  await expect(a.getByText('Hidden')).toBeAttached();
  await a.getByRole('button', { name: 'Reveal password' }).click();
  await expect(a.getByText(ITEM_PASSWORD)).toBeVisible();
  await a.getByRole('button', { name: 'Hide password' }).click();

  await a.getByRole('button', { name: 'Add item' }).click();
  await a.getByRole('radio', { name: 'Secure note' }).click();
  await a.getByLabel('Title (required)').fill('Synthetic Wi-Fi');
  await a.getByLabel('Note').fill(NOTE_TEXT);
  await a.getByRole('button', { name: 'Save' }).click();
  await expect(a.getByRole('heading', { level: 2, name: 'Synthetic Wi-Fi' })).toBeVisible();
  await expect(a.getByText('2 items in all vaults')).toBeVisible();
  await expectAccessible(a);

  // ---- Device B: logs in, becomes pending, and is paired (device-enrollment.md §3) ----
  await b.goto('/');
  await b.getByRole('button', { name: 'I already have an account' }).click();
  await b.getByLabel('Username').fill(USERNAME);
  await b.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await b.getByRole('button', { name: 'Log in' }).click();
  await expect(b.getByRole('heading', { name: 'Add this device' })).toBeVisible();

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
  await expect(a.getByText('The new device was added.')).toBeVisible();
  await a.getByRole('button', { name: 'Done' }).click();

  await expect(b.getByRole('heading', { level: 1, name: 'All items' })).toBeVisible({
    timeout: 30_000,
  });
  await expect(b.getByText('2 items in all vaults')).toBeVisible();

  // ---- B edits the note; A pulls it ----
  await row(b, /Synthetic Wi-Fi/).click();
  await b.getByRole('button', { name: 'Edit' }).click();
  await b.getByLabel('Title (required)').fill('Synthetic Wi-Fi (from B)');
  await b.getByRole('button', { name: 'Save' }).click();
  await expect(
    b.getByRole('heading', { level: 2, name: 'Synthetic Wi-Fi (from B)' }),
  ).toBeVisible();
  await expect(b.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });
  await a.getByRole('button', { name: 'Sync now' }).click();
  await expect(row(a, /Synthetic Wi-Fi \(from B\)/)).toBeVisible({ timeout: 15_000 });

  // ---- Concurrent edits: B offline, A edits the same login first (sync-protocol §6) ----
  await contextB.setOffline(true);
  await row(b, /Synthetic Mail/).click();
  await b.getByRole('button', { name: 'Edit' }).click();
  await b.getByLabel('Title (required)').fill('Synthetic Mail (B offline)');
  await b.getByRole('button', { name: 'Save' }).click();
  await expect(b.getByRole('status').filter({ hasText: 'Offline' })).toBeVisible({
    timeout: 15_000,
  });

  await row(a, /Synthetic Mail/).click();
  await a.getByRole('button', { name: 'Edit' }).click();
  await a.getByLabel('Title (required)').fill('Synthetic Mail (A)');
  await a.getByRole('button', { name: 'Save' }).click();
  await expect(a.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });

  await contextB.setOffline(false);
  await b.getByRole('button', { name: 'Sync now' }).click();
  await expect(b.getByText('Changed on two devices').first()).toBeVisible({ timeout: 15_000 });
  await row(b, /Synthetic Mail \(A\)/).click();
  await expect(b.getByText(/edited on this device and on another device/)).toBeVisible();
  await b.getByRole('button', { name: 'Keep both' }).click();
  await expect(row(b, /Synthetic Mail \(B offline\) \(this device\)/)).toBeVisible({
    timeout: 15_000,
  });
  await expect(b.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });
  await a.getByRole('button', { name: 'Sync now' }).click();
  await expect(a.getByText('3 items in all vaults')).toBeVisible({ timeout: 15_000 });

  // ---- Lock and unlock on A; the worker and its keys are gone while locked ----
  await a.getByRole('button', { name: 'Lock now' }).click();
  await expect(a.getByRole('heading', { name: 'Your vault is locked' })).toBeVisible();
  await expect(a.getByText('Synthetic Mail (A)')).toHaveCount(0);
  await expectAccessible(a);
  await a
    .getByRole('textbox', { name: 'Master password', exact: true })
    .fill('synthetic wrong guess 00');
  await a.getByRole('button', { name: 'Unlock' }).click();
  await expect(
    a.getByText("That's not the right master password.", { exact: false }),
  ).toBeVisible();
  await a.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await a.getByRole('button', { name: 'Unlock' }).click();
  await expect(a.getByText('3 items in all vaults')).toBeVisible({ timeout: 30_000 });

  // ---- Device C: a new browser recovers with the Recovery Kit (account-recovery.md §3) ----
  const contextC = await browser.newContext();
  const capturedC = capture(contextC);
  const c = await contextC.newPage();
  await c.goto('/');
  await c.getByRole('button', { name: /Use your Recovery Kit/ }).click();
  await c.getByLabel('Username').fill(USERNAME);
  await c.getByLabel('Recovery Key').fill(kit);
  await c.getByRole('button', { name: 'Continue' }).click();
  await c.getByRole('textbox', { name: 'New master password', exact: true }).fill(RECOVERED);
  await c.getByRole('textbox', { name: 'Type it again', exact: true }).fill(RECOVERED);
  await c.getByRole('button', { name: 'Continue' }).click();
  await expect(c.getByRole('heading', { name: 'Save your new Recovery Kit' })).toBeVisible({
    timeout: 30_000,
  });
  const newKit = (await c.getByTestId('recovery-key').innerText()).trim();
  expect(newKit).not.toBe(kit);
  await c.getByRole('button', { name: "I've saved it" }).click();
  await c.getByLabel('Recovery Key').fill(kit);
  await c.getByRole('button', { name: 'Finish recovery' }).click();
  await expect(c.getByText("doesn't match")).toBeVisible();
  await c.getByLabel('Recovery Key').fill(newKit);
  await c.getByRole('button', { name: 'Finish recovery' }).click();
  await expect(c.getByText('3 items in all vaults')).toBeVisible({ timeout: 30_000 });
  await expect(c.getByText(/Recovery is complete/)).toBeVisible();

  // A: its session ended with the recovery, so it locks; the new password moves it over.
  await a.getByRole('button', { name: 'Sync now' }).click();
  await expect(a.getByRole('heading', { name: 'Your vault is locked' })).toBeVisible({
    timeout: 15_000,
  });
  await a.getByRole('textbox', { name: 'Master password', exact: true }).fill(RECOVERED);
  await a.getByRole('button', { name: 'Unlock' }).click();
  await expect(a.getByText('3 items in all vaults')).toBeVisible({ timeout: 30_000 });
  await expect(
    a.getByText(/changed on another device. This device now uses the new one/),
  ).toBeVisible();
  await expect(a.getByText(/Your Recovery Kit was used/)).toBeVisible({ timeout: 15_000 });

  // B: the old password still opens its local copy, but it can't sign in any more.
  await b.getByRole('button', { name: 'Lock now' }).click();
  await b.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await b.getByRole('button', { name: 'Unlock' }).click();
  await expect(b.getByText(/couldn't sign in, so it won't sync/)).toBeVisible({ timeout: 30_000 });

  // ---- A changes the master password; C moves to it (authentication.md §9) ----
  await a.getByRole('button', { name: 'Security', exact: true }).click();
  await a.getByRole('textbox', { name: 'Current master password', exact: true }).fill(MASTER);
  await a.getByRole('textbox', { name: 'New master password', exact: true }).fill(CHANGED);
  await a.getByRole('textbox', { name: 'Type the new password again', exact: true }).fill(CHANGED);
  await a.getByRole('button', { name: 'Change password' }).click();
  await expect(a.getByText(/not the right master password/)).toBeVisible({ timeout: 30_000 });
  await a.getByRole('textbox', { name: 'Current master password', exact: true }).fill(RECOVERED);
  await a.getByRole('button', { name: 'Change password' }).click();
  await expect(a.getByText('Your master password was changed.')).toBeVisible({
    timeout: 30_000,
  });
  await a.getByRole('button', { name: 'Done' }).click();
  await c.getByRole('button', { name: 'Sync now' }).click();
  await expect(c.getByRole('heading', { name: 'Your vault is locked' })).toBeVisible({
    timeout: 15_000,
  });
  await c.getByRole('textbox', { name: 'Master password', exact: true }).fill(CHANGED);
  await c.getByRole('button', { name: 'Unlock' }).click();
  await expect(
    c.getByText(/changed on another device. This device now uses the new one/),
  ).toBeVisible({ timeout: 30_000 });

  // ---- A removes B as lost (device-enrollment §6); B wipes itself when it next connects ----
  await a.getByRole('button', { name: 'Devices' }).click();
  await expect(a.getByText(/^Active, /)).toHaveCount(3, { timeout: 15_000 });
  await expectAccessible(a);
  const deviceB = a.getByRole('listitem').filter({ hasText: 'added with a pairing code' });
  await deviceB.getByRole('button', { name: /^Remove/ }).click();
  await a.getByLabel(/lost or stolen/).check();
  await expect(a.getByText(/A compromised device can ignore the erase/)).toBeVisible();
  await a.getByRole('textbox', { name: 'Master password', exact: true }).fill(CHANGED);
  await a.getByRole('button', { name: 'Remove device' }).click();
  await expect(a.getByText(/may be in someone else's hands/)).toBeVisible({ timeout: 30_000 });
  await expect(a.getByText(/your Secret Key was replaced/)).toBeVisible();
  await expect(a.getByText(/^Removed/)).toBeVisible();
  await b.getByRole('button', { name: 'Sync now' }).click();
  await expect(b.getByRole('button', { name: 'Create an account' })).toBeVisible({
    timeout: 15_000,
  });
  expect(await indexedDbText(b)).not.toContain('"deviceId"');

  // C still holds the old Secret Key; its next online unlock adopts the new one (D-24).
  await c.getByRole('button', { name: 'Lock now' }).click();
  await c.getByRole('textbox', { name: 'Master password', exact: true }).fill(CHANGED);
  await c.getByRole('button', { name: 'Unlock' }).click();
  await expect(c.getByText(/Secret Key was replaced on another device/)).toBeVisible({
    timeout: 30_000,
  });
  await expect(c.getByText('3 items in all vaults')).toBeVisible();

  // ---- A makes a new Recovery Kit from Security (account-recovery.md §5) ----
  await a.getByRole('button', { name: 'Security', exact: true }).click();
  const kitSection = a.getByRole('region', { name: 'Recovery Kit' });
  await expectAccessible(a);
  await kitSection.getByRole('button', { name: 'Make a new Recovery Kit' }).click();
  const rotatedKit = (await kitSection.getByTestId('recovery-key').innerText()).trim();
  expect(rotatedKit).not.toBe(newKit);
  await kitSection.getByRole('button', { name: "I've saved it" }).click();
  await kitSection.getByLabel('New Recovery Key').fill(newKit);
  await kitSection.getByRole('textbox', { name: 'Master password', exact: true }).fill(CHANGED);
  await kitSection.getByRole('button', { name: 'Use the new kit' }).click();
  await expect(kitSection.getByText("doesn't match")).toBeVisible();
  await kitSection.getByLabel('New Recovery Key').fill(rotatedKit);
  await kitSection.getByRole('button', { name: 'Use the new kit' }).click();
  await expect(kitSection.getByText('Your new Recovery Kit is active.')).toBeVisible({
    timeout: 30_000,
  });

  // ---- A's activity screen shows what happened (P2-15) ----
  await a.getByRole('button', { name: 'Activity', exact: true }).click();
  await expect(a.getByText('New Recovery Kit made').first()).toBeVisible({ timeout: 15_000 });
  await expect(a.getByText('A device was removed as lost').first()).toBeVisible();
  await expect(a.getByText('The Recovery Kit was used to start a recovery').first()).toBeVisible();
  await expectAccessible(a);

  // ---- Capture checks: nothing secret on the wire or at rest ----
  const forbidden = [
    CHANGED,
    rotatedKit,
    rotatedKit.replace(/-/g, ''),
    RECOVERED,
    newKit,
    newKit.replace(/-/g, ''),
    MASTER,
    ITEM_PASSWORD,
    NOTE_TEXT,
    kit,
    kit.replace(/-/g, ''),
    'Synthetic Mail',
    'owner@mail.example',
  ];
  for (const captured of [capturedA, capturedB, capturedC]) {
    const wire = [...captured.urls, ...captured.headers, ...captured.bodies].join('\n');
    for (const secret of forbidden) expect(wire, `on the wire: ${secret}`).not.toContain(secret);
  }
  for (const page of [a, b, c]) {
    const stored = await indexedDbText(page);
    for (const secret of forbidden) expect(stored, `in IndexedDB: ${secret}`).not.toContain(secret);
    for (const key of ['localStorage', 'sessionStorage'] as const)
      expect(await page.evaluate((k) => window[k].length, key)).toBe(0);
  }
  expect(cspErrors).toEqual([]);

  await contextA.close();
  await contextB.close();
  await contextC.close();
});
