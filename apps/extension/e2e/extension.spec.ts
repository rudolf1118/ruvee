import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  type BrowserContext,
  chromium,
  expect,
  type Page,
  type Worker,
  test,
} from '@playwright/test';
import { EXTENSION_ID, STATE_FILE, WEB_ORIGIN } from '../playwright.extension.config';

/**
 * The extension end to end (extension-design.md §6): the web app creates the account and a login,
 * the extension logs in, is paired from the web app, unlocks, and fills a page of exactly the
 * saved origin, and nothing else. Synthetic data only.
 */

const USERNAME = 'synthetic-extension-owner';
const MASTER = 'synthetic extension harbor 61';
const ITEM_PASSWORD = 'synthetic-extension-item-secret-7a1';
/** Pages the extension may fill: loopback HTTP, served by route interception (no extra server). */
const LOGIN_PAGE = 'http://127.0.0.1:3191/login';
const OTHER_PORT = 'http://127.0.0.1:3192/login';
const FORM = `<!doctype html><title>Synthetic login</title>
<form><label>Email <input id="user" type="email"></label>
<label>Password <input id="pw" type="password"></label><button>Sign in</button></form>`;

const extensionDir = new URL('../dist-test/', import.meta.url).pathname;
const popupUrl = (tab?: number) =>
  `chrome-extension://${EXTENSION_ID}/popup.html${tab === undefined ? '' : `?tab=${String(tab)}`}`;

function bootstrapToken(): string {
  return (JSON.parse(readFileSync(STATE_FILE, 'utf8')) as { bootstrapToken: string })
    .bootstrapToken;
}

async function tabIdOf(worker: Worker, url: string): Promise<number> {
  return worker.evaluate(async (pattern) => {
    const [tab] = await chrome.tabs.query({ url: pattern } as never);
    return tab?.id ?? -1;
  }, `${url}*`);
}

let profile: string;
let context: BrowserContext;
let worker: Worker;

test.beforeAll(async () => {
  profile = mkdtempSync(join(tmpdir(), 'ruvee-ext-profile-'));
  context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    args: [`--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`],
  });
  worker = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  for (const url of [LOGIN_PAGE, OTHER_PORT])
    await context.route(`${new URL(url).origin}/**`, (route) =>
      route.fulfill({ status: 200, contentType: 'text/html', body: FORM }),
    );
});

test.afterAll(async () => {
  await context.close();
  rmSync(profile, { recursive: true, force: true });
});

test('extension: pairing, unlock, exact-origin fill, lock, resume', async () => {
  expect(new URL(worker.url()).host).toBe(EXTENSION_ID);
  const wire: string[] = [];
  const cookiesToApi: string[] = [];
  context.on('request', (request) => {
    wire.push(request.url(), JSON.stringify(request.headers()), request.postData() ?? '');
    const fromExtension = request.headers().origin === `chrome-extension://${EXTENSION_ID}`;
    if (fromExtension && request.headers().cookie) cookiesToApi.push(request.url());
  });

  // ---- The web app creates the account and one login for the test page's origin ----
  const web = await context.newPage();
  await web.goto(WEB_ORIGIN);
  await web.getByRole('button', { name: 'Create an account' }).click();
  await web.getByLabel('Setup token').fill(bootstrapToken());
  await web.getByLabel('Username').fill(USERNAME);
  await web.getByRole('button', { name: 'Continue' }).click();
  await web.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await web.getByRole('textbox', { name: 'Type it again', exact: true }).fill(MASTER);
  await web.getByRole('checkbox').check();
  await web.getByRole('button', { name: 'Continue' }).click();
  const kit = (await web.getByTestId('recovery-key').innerText()).trim();
  await web.getByRole('button', { name: "I've saved it" }).click();
  await web.getByLabel('Recovery Key').fill(kit);
  await web.getByRole('button', { name: 'Finish setup' }).click();
  await expect(web.getByRole('heading', { level: 1, name: 'All items' })).toBeVisible({
    timeout: 30_000,
  });
  await web.getByRole('button', { name: 'Add item' }).click();
  await web.getByLabel('Title (required)').fill('Synthetic Portal');
  await web.getByLabel('Website').fill(new URL(LOGIN_PAGE).origin);
  await web.getByLabel('Username or email').fill('owner@portal.example');
  await web.getByRole('textbox', { name: 'Password', exact: true }).fill(ITEM_PASSWORD);
  await web.getByRole('button', { name: 'Save' }).click();
  await expect(web.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });

  // ---- Extension settings: the server origin (host permission comes with the test build) ----
  const options = await context.newPage();
  await options.goto(`chrome-extension://${EXTENSION_ID}/options.html`);
  await options.getByLabel('Server address').fill('https://vault.example/path');
  await options.getByRole('button', { name: 'Save' }).click();
  await expect(options.getByText(/address of your Ruvee server only/)).toBeVisible();
  await options.getByLabel('Server address').fill(WEB_ORIGIN);
  await options.getByRole('button', { name: 'Save' }).click();
  await expect(options.getByText('Saved.', { exact: false })).toBeVisible();

  // ---- The popup logs in; the extension is a pending device until paired ----
  const popup = await context.newPage();
  await popup.goto(popupUrl());
  await popup.getByLabel('Username').fill(USERNAME);
  await popup.getByLabel('Master password').fill(MASTER);
  await popup.getByRole('button', { name: 'Log in' }).click();
  await expect(popup.getByLabel('Pairing code')).toBeVisible({ timeout: 30_000 });

  await web.bringToFront();
  await web.getByRole('button', { name: 'Devices' }).click();
  await web.getByRole('button', { name: 'Add a device' }).click();
  const codeBox = web.getByTestId('pairing-code');
  await expect(codeBox).toHaveText(/^PC1-/);
  const code = (await codeBox.innerText()).trim();
  await popup.bringToFront();
  await popup.getByLabel('Pairing code').fill(code);
  await popup.getByRole('button', { name: 'Add this browser' }).click();
  await expect(popup.getByText('Waiting for approval')).toBeVisible();
  await web.bringToFront();
  await expect(web.getByText(/Approve a new\s+browser extension/)).toBeVisible({ timeout: 15_000 });
  await web.getByRole('button', { name: 'Approve' }).click();
  await expect(web.getByText('The new device was added.')).toBeVisible();

  // Enrolled and unlocked. A popup opened as a page targets itself: not a fillable page.
  await popup.bringToFront();
  await expect(popup.getByText(/fills only HTTPS pages/)).toBeVisible({ timeout: 30_000 });

  // ---- Fill on exactly the saved origin ----
  const site = await context.newPage();
  await site.goto(LOGIN_PAGE);
  const siteTab = await tabIdOf(worker, LOGIN_PAGE);
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByText(`Logins for ${new URL(LOGIN_PAGE).origin}`)).toBeVisible();
  await popup.getByRole('button', { name: 'Fill Synthetic Portal' }).click();
  await expect(popup.getByText(/^Filled\./)).toBeVisible();
  await expect(site.locator('#user')).toHaveValue('owner@portal.example');
  await expect(site.locator('#pw')).toHaveValue(ITEM_PASSWORD);
  // The popup never received the password.
  expect(await popup.content()).not.toContain(ITEM_PASSWORD);

  // ---- Another port of the same host is another origin: nothing is offered ----
  const other = await context.newPage();
  await other.goto(OTHER_PORT);
  const otherTab = await tabIdOf(worker, OTHER_PORT);
  await popup.goto(popupUrl(otherTab));
  await expect(popup.getByText('No login is saved for exactly this address.')).toBeVisible();
  // A forged fill request for that tab is refused by the worker, and nothing is injected.
  const forged = await popup.evaluate(
    async ([tabId, itemId]) => chrome.runtime.sendMessage({ kind: 'fill', tabId, itemId }),
    [otherTab, await firstItemId(popup, siteTab)] as const,
  );
  expect(forged).toEqual({ ok: true, result: 'not_allowed' });
  await expect(other.locator('#pw')).toHaveValue('');

  // ---- D-27: the worker restarts and resumes from chrome.storage.session ----
  expect(await sessionKeys(worker)).toContain('ak');
  // A marker in the old worker's global scope proves the next one is a fresh instance.
  await worker.evaluate(() => {
    (globalThis as { ruveeTestMarker?: boolean }).ruveeTestMarker = true;
  });
  const cdp = await context.newCDPSession(popup);
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');
  await popup.goto(popupUrl(siteTab));
  // Playwright keeps the same handle for the restarted worker; its global scope is new.
  expect(
    await worker.evaluate(() => (globalThis as { ruveeTestMarker?: boolean }).ruveeTestMarker),
  ).toBeUndefined();
  await expect(popup.getByRole('button', { name: 'Fill Synthetic Portal' })).toBeVisible({
    timeout: 30_000,
  });

  // ---- Lock: AK leaves storage.session; the popup asks for the password again ----
  await popup.getByRole('button', { name: 'Lock' }).click();
  await expect(popup.getByText('Your vault is locked.')).toBeVisible();
  expect(await sessionKeys(worker)).not.toContain('ak');
  await popup.getByLabel('Master password').fill('synthetic wrong guess 11');
  await popup.getByRole('button', { name: 'Unlock' }).click();
  await expect(popup.getByText("That's not the right master password.")).toBeVisible({
    timeout: 30_000,
  });

  // ---- Capture: nothing secret on the wire, in the extension's stores, or with a cookie ----
  expect(cookiesToApi).toEqual([]);
  const forbidden = [MASTER, ITEM_PASSWORD, kit, kit.replace(/-/g, ''), 'Synthetic Portal'];
  const wireText = wire.join('\n');
  for (const secret of forbidden) expect(wireText, `on the wire: ${secret}`).not.toContain(secret);
  const stored = await worker.evaluate(async () => {
    const dump: Record<string, unknown> = {
      local: await chrome.storage.local.get(null as never),
      session: await chrome.storage.session.get(null as never),
    };
    for (const name of ['ruvee', 'ruvee-extension']) {
      const db = await new Promise<IDBDatabase>((resolve, reject) => {
        const req = indexedDB.open(name);
        req.onsuccess = () => {
          resolve(req.result);
        };
        req.onerror = () => {
          reject(new Error('open failed'));
        };
      });
      for (const store of Array.from(db.objectStoreNames))
        dump[`${name}/${store}`] = await new Promise((resolve) => {
          const all = db.transaction(store).objectStore(store).getAll();
          all.onsuccess = () => {
            resolve(all.result);
          };
        });
      db.close();
    }
    return JSON.stringify(dump, (_k, v: unknown) =>
      v instanceof Uint8Array ? new TextDecoder('latin1').decode(v) : v,
    );
  });
  for (const secret of forbidden) expect(stored, `stored: ${secret}`).not.toContain(secret);
});

async function sessionKeys(w: Worker): Promise<string[]> {
  return w.evaluate(async () => Object.keys(await chrome.storage.session.get(null as never)));
}

async function firstItemId(popup: Page, tab: number): Promise<string> {
  return popup.evaluate(async (tabId) => {
    const reply = (await chrome.runtime.sendMessage({ kind: 'candidates', tabId })) as {
      result: { items: { id: string }[] };
    };
    return reply.result.items[0]?.id ?? '';
  }, tab);
}
