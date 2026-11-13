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
import pg from 'pg';
import { API_ORIGIN, EXTENSION_ID, STATE_FILE, WEB_ORIGIN } from '../playwright.extension.config';

/**
 * The extension end to end (extension-design.md §6): the web app creates the account and a login,
 * the extension logs in, is paired from the web app, unlocks, and fills a page of exactly the
 * saved origin, and nothing else. Synthetic data only.
 */

const USERNAME = 'synthetic-extension-owner';
const MASTER = 'synthetic extension harbor 61';
const ITEM_PASSWORD = 'synthetic-extension-item-secret-7a1';
const NEW_MASTER = 'synthetic extension lantern 84';
/** Pages the extension may fill: loopback HTTP, served by route interception (no extra server). */
const LOGIN_PAGE = 'http://127.0.0.1:3191/login';
const OTHER_PORT = 'http://127.0.0.1:3192/login';
const FORM = `<!doctype html><title>Synthetic login</title>
<form><label>Email <input id="user" type="email"></label>
<label>Password <input id="pw" type="password"></label><button>Sign in</button></form>`;
/**
 * Review R18: password fields on the saved origin that the user cannot see. Each one would have
 * been filled before: hidden by an ancestor, outside the page, clipped to nothing, covered, tiny.
 * Follow-up review F-9: faded by a filter, cut by a clip path, transparent text and box, or under
 * an overlay that hit testing looks through (`pointer-events: none`).
 */
const HIDDEN_FIELDS = `<!doctype html><title>Synthetic hidden fields</title>
<style>body{margin:0} .cover{position:absolute;left:0;top:200px;width:320px;height:40px;background:#fff}</style>
<form>
<div style="opacity:0"><input id="faded-user" type="email"><input id="faded" type="password"></div>
<div style="position:absolute;left:-9999px;top:0"><input id="away" type="password"></div>
<div style="width:0;height:0;overflow:hidden"><input id="clipped" type="password"></div>
<input id="covered" type="password" style="position:absolute;left:10px;top:205px">
<div class="cover"></div>
<input id="tiny" type="password" style="width:1px;height:1px;padding:0;border:0">
<div style="filter:opacity(0)"><input id="filtered" type="password"></div>
<div style="clip-path:inset(50%)"><input id="clip-path" type="password"></div>
<input id="transparent" type="password" style="color:transparent;background:transparent;border:0;outline:0;caret-color:transparent">
<input id="under-overlay" type="password" style="position:absolute;left:10px;top:305px">
<div style="position:absolute;left:0;top:300px;width:320px;height:40px;background:#fff;pointer-events:none"></div>
</form>`;
const HIDDEN_PAGE = `${new URL(LOGIN_PAGE).origin}/hidden`;
/** A page on the saved origin whose only login form is in a frame of another origin (E-15). */
const FRAMED = `<!doctype html><title>Synthetic framed login</title>
<iframe src="${OTHER_PORT}" width="400" height="200"></iframe>`;
const FRAMED_PAGE = `${new URL(LOGIN_PAGE).origin}/framed`;
const ICON = 'ruvee-inline-icon';
/**
 * Phase B: a sign-in form on the saved origin that posts to another origin, as many sign-ins do
 * (E-18: the save offer is for the form's origin, not where the tab ends up). The fields have no
 * `name`, so nothing typed into them is sent anywhere.
 */
const SIGNIN = `<!doctype html><title>Synthetic sign-in</title>
<form method="post" action="${new URL(OTHER_PORT).origin}/welcome">
<label>Email <input id="user" type="email"></label>
<label>Password <input id="pw" type="password"></label><button id="go">Sign in</button></form>`;
const SIGNIN_PAGE = `${new URL(LOGIN_PAGE).origin}/signin`;
/**
 * A sign-in that continues on a second page of the same origin, like a two-factor step: the form
 * posts to `/session`, which answers with a page that sends the browser on to `/two-factor`.
 */
const SIGNIN_2FA = `<!doctype html><title>Synthetic sign-in with a second step</title>
<form method="post" action="/session">
<label>Username <input id="user" type="text"></label>
<label>Password <input id="pw" type="password"></label><input id="go" type="submit" value="Sign in"></form>`;
const SESSION_REDIRECT = `<!doctype html><title>Signing in</title>
<script>location.replace('/two-factor/mobile')</script>`;
const TWO_FACTOR = `<!doctype html><title>Synthetic two-factor</title>
<p>Approve the sign-in on your phone.</p>`;
const WELCOME = '<!doctype html><title>Synthetic welcome</title><p>Signed in.</p>';
const SAVED_USER = 'saved-user@portal.example';
const SAVED_PASSWORD = 'synthetic-captured-secret-5c2';
const PAGES: Record<string, string> = {
  '/hidden': HIDDEN_FIELDS,
  '/framed': FRAMED,
  '/signin': SIGNIN,
  '/welcome': WELCOME,
  '/signin-2fa': SIGNIN_2FA,
  '/session': SESSION_REDIRECT,
  '/two-factor/mobile': TWO_FACTOR,
};
/** Every request to the Ruvee server (web origin and API), for the phase B capture check. */
const toServer: string[] = [];

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
// Shared by the serial tests below: one account, one paired extension.
let web: Page;
let popup: Page;
let site: Page;
let siteTab: number;
let kit = '';
const wire: string[] = [];
const cookiesToApi: string[] = [];

test.describe.configure({ mode: 'serial' });

test.beforeAll(async () => {
  profile = mkdtempSync(join(tmpdir(), 'ruvee-ext-profile-'));
  context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    args: [`--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`],
  });
  worker = context.serviceWorkers()[0] ?? (await context.waitForEvent('serviceworker'));
  for (const url of [LOGIN_PAGE, OTHER_PORT])
    await context.route(`${new URL(url).origin}/**`, (route) =>
      route.fulfill({
        status: 200,
        contentType: 'text/html',
        body: PAGES[new URL(route.request().url()).pathname] ?? FORM,
      }),
    );
});

test.afterAll(async () => {
  await context.close();
  rmSync(profile, { recursive: true, force: true });
});

test('extension: pairing, unlock, exact-origin fill, lock, resume', async () => {
  expect(new URL(worker.url()).host).toBe(EXTENSION_ID);
  context.on('request', (request) => {
    wire.push(request.url(), JSON.stringify(request.headers()), request.postData() ?? '');
    if ([WEB_ORIGIN, API_ORIGIN].some((o) => request.url().startsWith(o)))
      toServer.push(request.url(), request.postData() ?? '');
    const fromExtension = request.headers().origin === `chrome-extension://${EXTENSION_ID}`;
    if (fromExtension && request.headers().cookie) cookiesToApi.push(request.url());
  });

  // ---- The web app creates the account and one login for the test page's origin ----
  web = await context.newPage();
  await web.goto(WEB_ORIGIN);
  await web.getByRole('button', { name: 'Create an account' }).click();
  await web.getByLabel('Setup token').fill(bootstrapToken());
  await web.getByLabel('Username').fill(USERNAME);
  await web.getByRole('button', { name: 'Continue' }).click();
  await web.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await web.getByRole('textbox', { name: 'Type it again', exact: true }).fill(MASTER);
  await web.getByRole('checkbox').check();
  await web.getByRole('button', { name: 'Continue' }).click();
  kit = (await web.getByTestId('recovery-key').innerText()).trim();
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
  popup = await context.newPage();
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
  // Rehearsal A-07: the toolbar popup closes as soon as the user turns to the approving device.
  // The worker owns the join: a reopened popup resumes waiting instead of offering the code form.
  await popup.close();
  popup = await context.newPage();
  await popup.goto(popupUrl());
  await expect(popup.getByText('Waiting for approval')).toBeVisible({ timeout: 15_000 });
  await expect(popup.getByLabel('Pairing code')).toHaveCount(0);
  await popup.close();
  await web.bringToFront();
  await expect(web.getByText(/Approve a new\s+browser extension/)).toBeVisible({ timeout: 15_000 });
  await web.getByRole('button', { name: 'Approve' }).click();
  await expect(web.getByText('The new device was added.')).toBeVisible();
  // With no popup open, the worker finishes the enrollment and holds the unlocked state.
  await expect.poll(() => sessionKeys(worker), { timeout: 30_000 }).toContain('ak');
  expect(await sessionKeys(worker)).not.toContain('pairingJoin');

  // Enrolled and unlocked. A popup opened as a page targets itself: not a fillable page.
  popup = await context.newPage();
  await popup.goto(popupUrl());
  await expect(popup.getByText(/fills only HTTPS pages/)).toBeVisible({ timeout: 30_000 });

  // ---- Fill on exactly the saved origin ----
  site = await context.newPage();
  await site.goto(LOGIN_PAGE);
  siteTab = await tabIdOf(worker, LOGIN_PAGE);
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
});

async function unlock(password: string): Promise<void> {
  await popup.goto(popupUrl(siteTab));
  await popup.getByLabel('Master password', { exact: true }).fill(password);
  await popup.getByRole('button', { name: 'Unlock' }).click();
  await expect(popup.getByRole('button', { name: 'Fill Synthetic Portal' })).toBeVisible({
    timeout: 30_000,
  });
}

async function stopWorker(): Promise<void> {
  const cdp = await context.newCDPSession(popup);
  await cdp.send('ServiceWorker.enable');
  await cdp.send('ServiceWorker.stopAllWorkers');
  await cdp.detach();
}

/** Sets the last-activity time as if the user had been away for `minutes`. */
async function idleFor(minutes: number): Promise<void> {
  await worker.evaluate(
    (ms) => chrome.storage.session.set({ lastActivityMs: Date.now() - ms }),
    minutes * 60_000,
  );
}

test('auto-lock: an expired unlock is never resumed, and the alarm locks an idle vault', async () => {
  await unlock(MASTER);
  expect(await sessionKeys(worker)).toContain('ak');
  // Away for 16 minutes while Chrome had stopped the worker: the next message must not resume.
  await idleFor(16);
  await stopWorker();
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByText('Your vault is locked.')).toBeVisible({ timeout: 30_000 });
  expect(await sessionKeys(worker)).not.toContain('ak');

  // Idle with no message at all: the alarm (30 s in the test build) locks on its own.
  await unlock(MASTER);
  await idleFor(16);
  await expect
    .poll(() => sessionKeys(worker), { timeout: 75_000, intervals: [2_000] })
    .not.toContain('ak');
});

test('chrome.storage.session is out of reach of scripts running in pages', async () => {
  await unlock(MASTER);
  expect(await sessionKeys(worker)).toContain('ak');
  const seen = await worker.evaluate(async (tabId) => {
    const [isolated] = await chrome.scripting.executeScript({
      target: { tabId },
      world: 'ISOLATED',
      args: [],
      func: async () => {
        try {
          const area = chrome.storage.session as chrome.storage.StorageArea | undefined;
          if (!area) return 'no session storage';
          return `read ${String(Object.keys(await area.get(null as never)).length)} keys`;
        } catch (e) {
          return `refused: ${String(e).slice(0, 120)}`;
        }
      },
    });
    const [main] = await chrome.scripting.executeScript({
      target: { tabId },
      world: 'MAIN',
      args: [],
      func: () => typeof (globalThis as { chrome?: { storage?: unknown } }).chrome?.storage,
    });
    return { isolated: isolated?.result, main: main?.result };
  }, siteTab);
  // A content script (the isolated world) is refused; the page's own world has no storage API.
  expect(seen.isolated).not.toMatch(/^read/);
  expect(seen.main).toBe('undefined');
});

test('a fill requested for a page that has since navigated away fails closed', async () => {
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByRole('button', { name: 'Fill Synthetic Portal' })).toBeVisible();
  // The popup lists again after its own sync; let that finish so the list below stays as shown.
  await popup.waitForTimeout(1_500);
  // The listing is now stale: the same tab moves to another origin before the user clicks.
  await site.goto(OTHER_PORT);
  await popup.getByRole('button', { name: 'Fill Synthetic Portal' }).click();
  await expect(popup.getByText(/isn't saved for this page/)).toBeVisible();
  await expect(site.locator('#pw')).toHaveValue('');
  // Back on the saved origin, the same request fills again.
  await site.goto(LOGIN_PAGE);
  await popup.getByRole('button', { name: 'Fill Synthetic Portal' }).click();
  await expect(popup.getByText(/^Filled\./)).toBeVisible();
  await expect(site.locator('#pw')).toHaveValue(ITEM_PASSWORD);
});

test('R18: on the saved origin, fields the user cannot see are never filled', async () => {
  await site.goto(HIDDEN_PAGE);
  await popup.goto(popupUrl(siteTab));
  await popup.getByRole('button', { name: 'Fill Synthetic Portal' }).click();
  await expect(popup.getByText('No visible password field on this page.')).toBeVisible();
  for (const id of [
    'faded-user',
    'faded',
    'away',
    'clipped',
    'covered',
    'tiny',
    'filtered',
    'clip-path',
    'transparent',
    'under-overlay',
  ])
    await expect(site.locator(`#${id}`), id).toHaveValue('');
  await site.goto(LOGIN_PAGE);
});

/** Action popups open now: `chrome.action.openPopup()` from an inline click (not popup tabs). */
async function actionPopups(): Promise<number> {
  return worker.evaluate(
    async () => (await chrome.runtime.getContexts({ contextTypes: ['POPUP'] })).length,
  );
}

async function closeActionPopups(): Promise<void> {
  const cdp = await context.newCDPSession(popup);
  const { targetInfos } = await cdp.send('Target.getTargets');
  for (const target of targetInfos)
    if (target.url === popupUrl())
      await cdp.send('Target.closeTarget', { targetId: target.targetId });
  await cdp.detach();
  await expect.poll(actionPopups).toBe(0);
}

/** What any script in the page can see of the document, icons included. */
const pageMarkup = (page: Page) => page.evaluate(() => document.documentElement.outerHTML);

/** A message sent from a content script of this extension in the site's top frame. */
async function fromContentScript(message: unknown): Promise<unknown> {
  return worker.evaluate(
    async ([tabId, msg]) => {
      const [r] = await chrome.scripting.executeScript({
        target: { tabId },
        world: 'ISOLATED',
        args: [msg],
        func: async (m: unknown) => {
          try {
            // A message nobody answers resolves with `undefined`; the inline reply is `null`.
            const reply: unknown = await chrome.runtime.sendMessage(m);
            return { reply: reply === undefined ? 'no reply' : reply };
          } catch {
            return { reply: 'no reply' };
          }
        },
      });
      return r?.result;
    },
    [siteTab, message] as const,
  );
}

test('inline icon (phase A): opt-in, opens the popup, never fills, tells the page nothing', async () => {
  // ---- Off by default: no content script on a login page ----
  await site.goto(LOGIN_PAGE);
  await site.waitForTimeout(1000);
  await expect(site.locator(ICON)).toHaveCount(0);

  // ---- Turned on in the options page ----
  const options = await context.newPage();
  await options.goto(`chrome-extension://${EXTENSION_ID}/options.html`);
  await options.getByRole('button', { name: 'Turn on' }).click();
  await expect(options.getByText(/^On\./)).toBeVisible();

  await site.goto(LOGIN_PAGE);
  await expect(site.locator(ICON)).toHaveCount(2);
  // The page cannot reach into the icon.
  expect(
    await site.evaluate((tag) => document.querySelector(tag)?.shadowRoot ?? null, ICON),
  ).toBeNull();

  // ---- §4: the page sees the same thing whatever the vault holds ----
  const unlockedWithMatch = await pageMarkup(site);
  const other = await context.newPage();
  await other.goto(OTHER_PORT);
  await expect(other.locator(ICON)).toHaveCount(2);
  const unlockedNoMatch = await pageMarkup(other);
  await other.close();
  const unlockedReply = await fromContentScript({ kind: 'inlineOpen' });
  await closeActionPopups();
  await popup.goto(popupUrl(siteTab));
  await popup.getByRole('button', { name: 'Lock' }).click();
  await expect(popup.getByText('Your vault is locked.')).toBeVisible();
  await site.goto(LOGIN_PAGE);
  await expect(site.locator(ICON)).toHaveCount(2);
  const locked = await pageMarkup(site);
  expect(unlockedNoMatch).toBe(unlockedWithMatch);
  expect(locked).toBe(unlockedWithMatch);
  const lockedReply = await fromContentScript({ kind: 'inlineOpen' });
  expect(lockedReply).toEqual(unlockedReply);
  expect(lockedReply).toEqual({ reply: null });
  await closeActionPopups();
  await unlock(MASTER);

  // ---- The user's click on the icon opens the toolbar popup; nothing is filled ----
  await site.goto(LOGIN_PAGE);
  await site.bringToFront();
  await expect(site.locator(ICON)).toHaveCount(2);
  const icon = await site.locator(ICON).nth(1).boundingBox();
  if (!icon) throw new Error('the icon has no box');
  await site.mouse.click(icon.x + icon.width / 2, icon.y + icon.height / 2);
  await expect.poll(actionPopups).toBe(1);
  await site.waitForTimeout(1000);
  await expect(site.locator('#user')).toHaveValue('');
  await expect(site.locator('#pw')).toHaveValue('');
  await closeActionPopups();

  // ---- Clicks the page makes do nothing ----
  await site.waitForTimeout(1100);
  await site.evaluate((tag) => {
    for (const host of document.querySelectorAll<HTMLElement>(tag)) {
      host.click();
      host.dispatchEvent(new MouseEvent('click', { bubbles: true, composed: true }));
    }
  }, ICON);
  await site.waitForTimeout(1500);
  expect(await actionPopups()).toBe(0);

  // ---- E-10: a page that makes everything transparent gets a popup, never a fill ----
  await site.evaluate(() => {
    document.documentElement.style.opacity = '0';
  });
  await site.mouse.click(icon.x + icon.width / 2, icon.y + icon.height / 2);
  await expect.poll(actionPopups).toBe(1);
  await site.waitForTimeout(1000);
  await expect(site.locator('#pw')).toHaveValue('');
  await closeActionPopups();

  // ---- E-20: a content script can only ask for the popup; everything else is dropped ----
  const itemId = await firstItemId(popup, siteTab);
  for (const forged of [
    { kind: 'fill', tabId: siteTab, itemId },
    { kind: 'candidates', tabId: siteTab },
    { kind: 'vault', method: 'phase' },
    { kind: 'status' },
    { kind: 'setInline', enabled: false },
    { kind: 'inlineOpen', tabId: siteTab },
  ])
    expect(await fromContentScript(forged), JSON.stringify(forged)).toEqual({ reply: 'no reply' });
  await site.goto(LOGIN_PAGE);
  await expect(site.locator('#pw')).toHaveValue('');
  expect(await actionPopups()).toBe(0);

  // ---- E-15: no icon in a frame of another origin, and none in the top frame without fields ----
  await site.goto(FRAMED_PAGE);
  await expect(site.frameLocator('iframe').locator('#pw')).toBeVisible();
  await site.waitForTimeout(1000);
  await expect(site.locator(ICON)).toHaveCount(0);
  await expect(site.frameLocator('iframe').locator(ICON)).toHaveCount(0);

  // ---- Turned off: the script is unregistered ----
  await options.bringToFront();
  await options.getByRole('button', { name: 'Turn off' }).click();
  await expect(options.getByText(/^Off\./)).toBeVisible();
  await options.close();
  expect(
    await worker.evaluate(
      async () => (await chrome.scripting.getRegisteredContentScripts()).length,
    ),
  ).toBe(0);
  await site.goto(LOGIN_PAGE);
  await site.waitForTimeout(1000);
  await expect(site.locator(ICON)).toHaveCount(0);
});

/** What the worker holds for a tab after a sign-in: origin and username, or null. */
async function pendingFor(tab: number): Promise<unknown> {
  return popup.evaluate(async (tabId) => {
    const reply = (await chrome.runtime.sendMessage({ kind: 'pendingSave', tabId })) as {
      ok: boolean;
      result?: unknown;
    };
    return reply.ok ? reply.result : 'error';
  }, tab);
}

const badgeOf = (tab: number) =>
  worker.evaluate((tabId) => chrome.action.getBadgeText({ tabId }), tab);

/** The user signs in on the sign-in page: typed values, their own click; the tab navigates. */
async function signIn(username: string, password: string): Promise<void> {
  await site.goto(SIGNIN_PAGE);
  await site.locator('#user').fill(username);
  await site.locator('#pw').fill(password);
  await site.locator('#go').click();
  await site.waitForURL(`${new URL(OTHER_PORT).origin}/welcome`);
}

async function lockFromPopup(): Promise<void> {
  await popup.evaluate(() => chrome.runtime.sendMessage({ kind: 'lock' }));
  expect(await sessionKeys(worker)).not.toContain('ak');
}

/** Unlocks with the tab on the saved origin (the helper expects its login listed). */
async function unlockAgain(): Promise<void> {
  await site.goto(LOGIN_PAGE);
  await unlock(MASTER);
}

test('save a new login (phase B): offered in the popup only, for the form’s origin, never faked', async () => {
  const options = await context.newPage();
  await options.goto(`chrome-extension://${EXTENSION_ID}/options.html`);
  await options.getByRole('button', { name: 'Turn on' }).click();
  await expect(options.getByText(/^On\./)).toBeVisible();
  const formOrigin = new URL(LOGIN_PAGE).origin;

  // ---- A page that submits by itself gets nothing: click(), requestSubmit() ----
  for (const how of ['click', 'requestSubmit'] as const) {
    await site.goto(SIGNIN_PAGE);
    await site.evaluate(
      ([mode, user, pw]) => {
        (document.getElementById('user') as HTMLInputElement).value = user;
        (document.getElementById('pw') as HTMLInputElement).value = pw;
        if (mode === 'click') document.getElementById('go')?.click();
        else document.querySelector('form')?.requestSubmit();
      },
      [how, 'planted@portal.example', 'planted-secret'] as const,
    );
    await site.waitForURL(/\/welcome$/);
    await site.waitForTimeout(500);
    expect(await pendingFor(siteTab), how).toBeNull();
    expect(await badgeOf(siteTab), how).toBe('');
  }

  // ---- Locked when the user signs in: nothing is kept for later ----
  await lockFromPopup();
  await signIn(SAVED_USER, SAVED_PASSWORD);
  await site.waitForTimeout(500);
  expect(await badgeOf(siteTab)).toBe('');
  await unlockAgain();
  expect(await pendingFor(siteTab)).toBeNull();

  // ---- The user signs in: a badge, and the offer in the popup for the form's origin ----
  await signIn(SAVED_USER, SAVED_PASSWORD);
  await expect.poll(() => badgeOf(siteTab)).toBe('+');
  expect(await pendingFor(siteTab)).toEqual({ origin: formOrigin, username: SAVED_USER });
  // Memory only (E-19): not in chrome.storage while it waits.
  const waiting = await worker.evaluate(async () =>
    JSON.stringify([
      await chrome.storage.local.get(null as never),
      await chrome.storage.session.get(null as never),
    ]),
  );
  expect(waiting).not.toContain(SAVED_PASSWORD);
  // Nothing was shown in the page (§5.2): the welcome page is untouched.
  expect(await site.locator('body').innerText()).toBe('Signed in.');

  await popup.goto(popupUrl(siteTab));
  // The tab is now on another origin; the offer is still for the form's own (E-18).
  await expect(popup.getByText(`Logins for ${new URL(OTHER_PORT).origin}`)).toBeVisible();
  await expect(popup.getByText(`Save this login for ${formOrigin}?`)).toBeVisible();
  await expect(popup.getByText(`Username: ${SAVED_USER}`)).toBeVisible();
  expect(await popup.content()).not.toContain(SAVED_PASSWORD);
  await popup.getByRole('button', { name: 'Save login' }).click();
  await expect(popup.getByText('Saved to your vault.')).toBeVisible();
  expect(await badgeOf(siteTab)).toBe('');
  expect(await pendingFor(siteTab)).toBeNull();
  // Not offered on the tab's new origin: the item is for exactly the form's.
  await expect(popup.getByText('No login is saved for exactly this address.')).toBeVisible();

  // ---- The saved login fills on its origin, like any other ----
  await site.goto(LOGIN_PAGE);
  await popup.goto(popupUrl(siteTab));
  const savedTitle = new URL(LOGIN_PAGE).host;
  await popup.getByRole('button', { name: `Fill ${savedTitle}` }).click();
  await expect(popup.getByText(/^Filled\./)).toBeVisible();
  await expect(site.locator('#user')).toHaveValue(SAVED_USER);
  await expect(site.locator('#pw')).toHaveValue(SAVED_PASSWORD);

  // ---- Known usernames are not offered again (a duplicate; a new password is phase C) ----
  await signIn(SAVED_USER, SAVED_PASSWORD);
  await signIn('owner@portal.example', 'a-changed-password-for-phase-c');
  await site.waitForTimeout(500);
  expect(await pendingFor(siteTab)).toBeNull();
  expect(await badgeOf(siteTab)).toBe('');

  // ---- "Not now" drops it ----
  await signIn('second-user@portal.example', 'synthetic-second-secret');
  await expect.poll(() => pendingFor(siteTab)).not.toBeNull();
  await popup.goto(popupUrl(siteTab));
  await popup.getByRole('button', { name: 'Not now' }).click();
  await expect(popup.getByText(/Save this login/)).toHaveCount(0);
  expect(await pendingFor(siteTab)).toBeNull();
  expect(await badgeOf(siteTab)).toBe('');

  // ---- A lock drops it, and so does a worker restart (memory only) ----
  await signIn('third-user@portal.example', 'synthetic-third-secret');
  await expect.poll(() => pendingFor(siteTab)).not.toBeNull();
  await lockFromPopup();
  expect(await badgeOf(siteTab)).toBe('');
  await unlockAgain();
  expect(await pendingFor(siteTab)).toBeNull();
  await signIn('fourth-user@portal.example', 'synthetic-fourth-secret');
  await expect.poll(() => pendingFor(siteTab)).not.toBeNull();
  await stopWorker();
  expect(await pendingFor(siteTab)).toBeNull();

  // ---- E-17: a content script cannot name the origin; E-15: nor capture from a frame ----
  await site.goto(LOGIN_PAGE);
  for (const forged of [
    { kind: 'inlineCapture', username: 'x', password: 'y', origin: 'https://bank.example' },
    { kind: 'inlineCapture', username: 'x', password: 'y', tabId: siteTab },
    { kind: 'savePending', tabId: siteTab },
    { kind: 'pendingSave', tabId: siteTab },
  ])
    expect(await fromContentScript(forged), JSON.stringify(forged)).toEqual({ reply: 'no reply' });
  await site.goto(FRAMED_PAGE);
  await expect(site.frameLocator('iframe').locator('#pw')).toBeVisible();
  const fromFrame = await worker.evaluate(async (tabId) => {
    const results = await chrome.scripting.executeScript({
      target: { tabId, allFrames: true } as never,
      world: 'ISOLATED',
      args: [],
      func: async () => {
        if (window.top === window) return 'top';
        const reply: unknown = await chrome.runtime.sendMessage({
          kind: 'inlineCapture',
          username: 'framed-user',
          password: 'framed-secret',
        });
        return reply === undefined ? 'no reply' : JSON.stringify(reply);
      },
    });
    return results.map((r) => r.result);
  }, siteTab);
  expect(fromFrame.sort()).toEqual(['no reply', 'top']);
  expect(await pendingFor(siteTab)).toBeNull();
  // The same capture from the top frame is answered exactly like everything else: null.
  await site.goto(LOGIN_PAGE);
  expect(
    await fromContentScript({
      kind: 'inlineCapture',
      username: 'top-user',
      password: 'top-secret',
    }),
  ).toEqual({ reply: null });
  await popup.evaluate(
    (tabId) => chrome.runtime.sendMessage({ kind: 'dismissPending', tabId }),
    siteTab,
  );

  await options.bringToFront();
  await options.getByRole('button', { name: 'Turn off' }).click();
  await expect(options.getByText(/^Off\./)).toBeVisible();
  await options.close();
});

test('save offer after a sign-in that goes on to a second same-origin page (two-factor)', async () => {
  const options = await context.newPage();
  await options.goto(`chrome-extension://${EXTENSION_ID}/options.html`);
  await options.getByRole('button', { name: 'Turn on' }).click();
  await expect(options.getByText(/^On\./)).toBeVisible();
  const origin = new URL(LOGIN_PAGE).origin;

  await site.goto(`${origin}/signin-2fa`);
  await site.bringToFront();
  await site.locator('#user').fill('two-step-user');
  await site.locator('#pw').fill('synthetic-two-step-secret');
  await site.locator('#go').click();
  await site.waitForURL(`${origin}/two-factor/mobile`);
  await expect.poll(() => badgeOf(siteTab)).toBe('+');

  // The popup opened on the second page: the offer, the (empty) list, and no error.
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByText(`Logins for ${origin}`)).toBeVisible();
  await expect(popup.getByText(`Save this login for ${origin}?`)).toBeVisible();
  await expect(popup.getByText('Username: two-step-user')).toBeVisible();
  await popup.waitForTimeout(1500);
  await expect(popup.getByRole('alert')).toHaveCount(0);
  await popup.getByRole('button', { name: 'Not now' }).click();

  await options.bringToFront();
  await options.getByRole('button', { name: 'Turn off' }).click();
  await expect(options.getByText(/^Off\./)).toBeVisible();
  await options.close();
});

/** Adds a login for the test page's origin in the web app and waits until it is synced. */
async function addLoginInWeb(title: string, password: string): Promise<void> {
  await web.bringToFront();
  await web.getByRole('button', { name: 'Add item' }).click();
  await web.getByLabel('Title (required)').fill(title);
  await web.getByLabel('Website').fill(new URL(LOGIN_PAGE).origin);
  await web
    .getByLabel('Username or email')
    .fill(`${title.toLowerCase().replace(/ /g, '-')}@portal.example`);
  await web.getByRole('textbox', { name: 'Password', exact: true }).fill(password);
  await web.getByRole('button', { name: 'Save', exact: true }).click();
  await expect(web.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });
}

/** The web app's section navigation (its buttons' names carry item counts). */
const webNav = () => web.getByRole('navigation', { name: 'Vault navigation' });

/** Moves a login to Trash in the web app, deletes it permanently there, and waits for the sync. */
async function purgeInWeb(title: string): Promise<void> {
  await web.bringToFront();
  await webNav()
    .getByRole('button', { name: /^All items/ })
    .click();
  await web
    .getByRole('button', { name: new RegExp(title) })
    .first()
    .click();
  await web.getByRole('button', { name: 'Move to Trash' }).click();
  await webNav()
    .getByRole('button', { name: /^Trash/ })
    .click();
  await web
    .getByRole('button', { name: new RegExp(title) })
    .first()
    .click();
  await web.getByRole('button', { name: 'Delete permanently' }).click();
  await web.getByRole('button', { name: 'Delete permanently' }).click();
  await expect(web.getByRole('button', { name: new RegExp(title) })).toHaveCount(0);
  await web.waitForTimeout(1_000);
  await expect(web.getByRole('status').filter({ hasText: 'Synced' })).toBeVisible({
    timeout: 15_000,
  });
  await webNav()
    .getByRole('button', { name: /^All items/ })
    .click();
}

test('a login deleted permanently in the web app leaves the extension; a fill of it says so', async () => {
  await site.goto(LOGIN_PAGE);
  await addLoginInWeb('Purge Seen', 'synthetic-purge-seen');
  await addLoginInWeb('Purge Stale', 'synthetic-purge-stale');
  // One opening of the popup is enough: it syncs, then lists again (before the fix, the list it
  // showed was read before its own sync).
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByRole('button', { name: 'Fill Purge Seen' })).toBeVisible({
    timeout: 15_000,
  });
  await expect(popup.getByRole('button', { name: 'Fill Purge Stale' })).toBeVisible();

  // ---- Purged on the web: gone from the extension after its sync, no error ----
  await purgeInWeb('Purge Seen');
  // The extension's sync accepts the purge (it was never the failing call)...
  const afterPurge = await popup.evaluate(async (tabId) => {
    const synced = (await chrome.runtime.sendMessage({ kind: 'vault', method: 'sync' })) as {
      ok: boolean;
      result?: { state: string };
    };
    const listed = (await chrome.runtime.sendMessage({ kind: 'candidates', tabId })) as {
      result: { items: { title: string }[] };
    };
    return { state: synced.result?.state, titles: listed.result.items.map((i) => i.title) };
  }, siteTab);
  expect(afterPurge.state).toBe('synced');
  expect(afterPurge.titles).not.toContain('Purge Seen');
  expect(afterPurge.titles).toContain('Purge Stale');
  // ...and the popup, opened once, no longer offers it.
  await addLoginInWeb('Purge Later', 'synthetic-purge-later');
  await purgeInWeb('Purge Later');
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByRole('button', { name: 'Fill Purge Stale' })).toBeVisible();
  await expect(popup.getByRole('button', { name: 'Fill Purge Later' })).toHaveCount(0, {
    timeout: 15_000,
  });
  await expect(popup.getByRole('button', { name: 'Fill Purge Seen' })).toHaveCount(0);
  await expect(popup.getByRole('button', { name: 'Fill Synthetic Portal' })).toBeVisible();
  await expect(popup.getByRole('alert')).toHaveCount(0);

  // ---- Purged while the popup still lists it: the fill says so and fills nothing ----
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByRole('button', { name: 'Fill Purge Stale' })).toBeVisible();
  await purgeInWeb('Purge Stale');
  // The extension learns of it with its next sync (here: the worker's, on the fill itself or a
  // reopen); the click below uses the list shown before the purge.
  await popup.evaluate(() => chrome.runtime.sendMessage({ kind: 'vault', method: 'sync' }));
  await popup.getByRole('button', { name: 'Fill Purge Stale' }).click();
  await expect(popup.getByText(/no longer in your vault/)).toBeVisible();
  await expect(popup.getByText(/Something went wrong/)).toHaveCount(0);
  await expect(site.locator('#pw')).toHaveValue('');
  await expect(popup.getByRole('button', { name: 'Fill Purge Stale' })).toHaveCount(0);
});

test('the popup stays usable when its sync cannot reach the server', async () => {
  await site.goto(LOGIN_PAGE);
  const block = (route: { abort: () => Promise<void> }) => route.abort();
  await context.route(`${WEB_ORIGIN}/api/**`, block);
  try {
    await popup.goto(popupUrl(siteTab));
    await expect(popup.getByRole('button', { name: 'Fill Synthetic Portal' })).toBeVisible();
    // The server really is out of reach for the worker's sync.
    const offline = await popup.evaluate(
      () =>
        chrome.runtime.sendMessage({ kind: 'vault', method: 'sync' }) as Promise<{
          result?: { state: string };
        }>,
    );
    expect(offline.result?.state).toBe('offline');
    await expect(popup.getByText(/Something went wrong/)).toHaveCount(0);
    await popup.getByRole('button', { name: 'Fill Synthetic Portal' }).click();
    await expect(popup.getByText(/^Filled\./)).toBeVisible();
    await expect(site.locator('#pw')).toHaveValue(ITEM_PASSWORD);
  } finally {
    await context.unroute(`${WEB_ORIGIN}/api/**`, block);
  }
});

test('R19: a lock that arrives while an unlock is still running wins', async () => {
  await popup.goto(popupUrl(siteTab));
  await popup.getByRole('button', { name: 'Lock' }).click();
  await expect(popup.getByText('Your vault is locked.')).toBeVisible();
  // The lock is sent after the unlock, at several delays, so some land while it still runs.
  const rounds = await popup.evaluate(async (password) => {
    const send = <T>(m: unknown) => chrome.runtime.sendMessage(m) as Promise<T>;
    const results: { unlock: { ok: boolean; code: string | undefined }; unlocked: boolean }[] = [];
    for (const delay of [0, 10, 25, 50, 100, 150, 200, 300]) {
      const unlocking = send<{ ok: boolean; code?: string }>({
        kind: 'vault',
        method: 'unlock',
        params: { password },
      });
      await new Promise((resolve) => setTimeout(resolve, delay));
      await send({ kind: 'lock' });
      const reply = await unlocking;
      const status = await send<{ result: { unlocked: boolean } }>({ kind: 'status' });
      results.push({
        unlock: { ok: reply.ok, code: reply.code },
        unlocked: status.result.unlocked,
      });
    }
    return results;
  }, MASTER);
  // Whatever the order, a lock sent after the unlock leaves the extension locked. Before: an
  // unlock the lock overtook finished afterwards and stored AK back.
  for (const round of rounds) expect(round.unlocked).toBe(false);
  expect(await sessionKeys(worker)).not.toContain('ak');
  // And the race was really exercised: at least one unlock was overtaken and reported it.
  expect(rounds.some((r) => !r.unlock.ok && r.unlock.code === 'locked')).toBe(true);
  await unlock(MASTER);
});

test('service worker stopped mid-operation: an unlock completes once or not at all; a fill is never replayed', async () => {
  const extensionDevice = async () =>
    (
      await sql<{ id: string }>(
        `SELECT id FROM devices WHERE platform = 'extension' AND status = 'active'`,
      )
    )[0]?.id ?? '';
  const liveSessions = async () =>
    sql<{ proven: boolean }>(
      `SELECT proven_at IS NOT NULL AS proven FROM sessions
         WHERE device_id = '${await extensionDevice()}' AND revoked_at IS NULL AND kind = 'token'`,
    );

  // ---- An unlock, stopped while it runs ----
  await popup.goto(popupUrl(siteTab));
  await popup.getByRole('button', { name: 'Lock' }).click();
  await expect(popup.getByText('Your vault is locked.')).toBeVisible();
  await popup.evaluate((password) => {
    void chrome.runtime
      .sendMessage({ kind: 'vault', method: 'unlock', params: { password } })
      .catch(() => undefined);
  }, MASTER);
  await popup.waitForTimeout(400);
  await stopWorker();
  await popup.goto(popupUrl(siteTab));
  const status = await popup.evaluate(
    async () =>
      ((await chrome.runtime.sendMessage({ kind: 'status' })) as { result: { unlocked: boolean } })
        .result,
  );
  // Either it finished before the stop (and is fully unlocked) or it left nothing behind.
  expect((await sessionKeys(worker)).includes('ak')).toBe(status.unlocked);
  if (!status.unlocked) await unlock(MASTER);
  else
    await expect(popup.getByRole('button', { name: 'Fill Synthetic Portal' })).toBeVisible({
      timeout: 30_000,
    });
  // However the stop fell, the extension ends with one live session, and it is proven.
  expect(await liveSessions()).toEqual([{ proven: true }]);

  // ---- A fill, stopped while it runs; the tab then navigates away ----
  await site.goto(LOGIN_PAGE);
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByRole('button', { name: 'Fill Synthetic Portal' })).toBeVisible();
  const itemId = await firstItemId(popup, siteTab);
  await popup.evaluate(
    ([tabId, id]) => {
      void chrome.runtime.sendMessage({ kind: 'fill', tabId, itemId: id }).catch(() => undefined);
    },
    [siteTab, itemId] as const,
  );
  await stopWorker();
  const filled = await site.locator('#pw').inputValue();
  // Filled once, completely, or not at all.
  expect([ITEM_PASSWORD, '']).toContain(filled);
  await site.goto(OTHER_PORT);
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByText('No login is saved for exactly this address.')).toBeVisible({
    timeout: 30_000,
  });
  await popup.waitForTimeout(1_500);
  // The restarted worker kept no pending fill: nothing reaches the new page, or a reload.
  await expect(site.locator('#pw')).toHaveValue('');
  await site.goto(LOGIN_PAGE);
  await popup.waitForTimeout(1_000);
  await expect(site.locator('#pw')).toHaveValue('');
  // Nothing but the unlock state and the access token survives in session storage.
  expect((await sessionKeys(worker)).sort()).toEqual(['accessToken', 'ak', 'lastActivityMs']);
});

test('a password reaches only the page field it fills: no popup reply, page message or markup', async () => {
  await site.goto(LOGIN_PAGE);
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByRole('button', { name: 'Fill Synthetic Portal' })).toBeVisible();
  // Every reply the popup receives from the worker, and every message the page sees.
  await popup.evaluate(() => {
    const replies: string[] = [];
    (globalThis as { ruveeReplies?: string[] }).ruveeReplies = replies;
    const original: (m: unknown) => Promise<unknown> = chrome.runtime.sendMessage;
    const send = (m: unknown) => original.call(chrome.runtime, m);
    (chrome.runtime as { sendMessage: unknown }).sendMessage = async (m: unknown) => {
      const reply = await send(m);
      replies.push(JSON.stringify(reply));
      return reply;
    };
  });
  await site.evaluate(() => {
    const seen: string[] = [];
    (globalThis as { ruveeSeen?: string[] }).ruveeSeen = seen;
    addEventListener('message', (e) => seen.push(JSON.stringify(e.data)));
  });
  await popup.getByRole('button', { name: 'Fill Synthetic Portal' }).click();
  await expect(popup.getByText(/^Filled\./)).toBeVisible();
  await expect(site.locator('#pw')).toHaveValue(ITEM_PASSWORD);
  const replies = await popup.evaluate(
    () => (globalThis as { ruveeReplies?: string[] }).ruveeReplies ?? [],
  );
  expect(replies.length).toBeGreaterThan(0);
  for (const reply of replies) expect(reply).not.toContain(ITEM_PASSWORD);
  const page = await site.evaluate(() => ({
    seen: (globalThis as { ruveeSeen?: string[] }).ruveeSeen ?? [],
    markup: document.documentElement.outerHTML,
  }));
  expect(page.seen.join('\n')).not.toContain(ITEM_PASSWORD);
  expect(page.markup).not.toContain(ITEM_PASSWORD);
  expect(await popup.content()).not.toContain(ITEM_PASSWORD);
});

test('previous-password unlock after the password and SK both changed elsewhere', async () => {
  // The extension is locked (as if offline) while the web app replaces SK and the password.
  await popup.getByRole('button', { name: 'Lock' }).click();
  await expect(popup.getByText('Your vault is locked.')).toBeVisible();
  await web.bringToFront();
  await web.getByRole('button', { name: 'Security', exact: true }).click();
  const skSection = web.getByRole('region', { name: 'Secret Key' });
  await skSection.getByRole('textbox', { name: 'Master password', exact: true }).fill(MASTER);
  await skSection.getByRole('button', { name: 'Replace Secret Key' }).click();
  await expect(skSection.getByText('Your Secret Key was replaced.')).toBeVisible({
    timeout: 30_000,
  });
  await web.getByRole('textbox', { name: 'Current master password', exact: true }).fill(MASTER);
  await web.getByRole('textbox', { name: 'New master password', exact: true }).fill(NEW_MASTER);
  await web
    .getByRole('textbox', { name: 'Type the new password again', exact: true })
    .fill(NEW_MASTER);
  await web.getByRole('button', { name: 'Change password' }).click();
  await expect(web.getByText('Your master password was changed.')).toBeVisible({
    timeout: 30_000,
  });

  await popup.bringToFront();
  await popup.goto(popupUrl(siteTab));
  await popup.getByLabel('Master password', { exact: true }).fill(NEW_MASTER);
  await popup.getByRole('button', { name: 'Unlock' }).click();
  await expect(popup.getByText(/both changed on another device/)).toBeVisible({ timeout: 30_000 });
  await popup.getByLabel('Previous master password').fill('synthetic wrong previous 22');
  await popup.getByRole('button', { name: 'Unlock' }).click();
  await expect(popup.getByText("That's not the right master password.")).toBeVisible({
    timeout: 30_000,
  });
  await popup.getByLabel('Previous master password').fill(MASTER);
  await popup.getByRole('button', { name: 'Unlock' }).click();
  await expect(popup.getByRole('button', { name: 'Fill Synthetic Portal' })).toBeVisible({
    timeout: 30_000,
  });
  // The browser moved over: the new password alone opens it now, the old one no longer does.
  await popup.getByRole('button', { name: 'Lock' }).click();
  await popup.getByLabel('Master password', { exact: true }).fill(MASTER);
  await popup.getByRole('button', { name: 'Unlock' }).click();
  await expect(popup.getByText("That's not the right master password.")).toBeVisible({
    timeout: 30_000,
  });
  await unlock(NEW_MASTER);
});

test('a reused refresh token ends the session for the extension too', async () => {
  const stolen = await refreshTokenOf(worker);
  expect(stolen).toMatch(/^[A-Za-z0-9_-]{43}$/);
  // Expire the access token on the server; the extension's next request refreshes it.
  await sql(
    `UPDATE sessions SET access_expires_at = now() - interval '1 second'
     WHERE kind = 'token' AND revoked_at IS NULL`,
  );
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByRole('button', { name: 'Fill Synthetic Portal' })).toBeVisible();
  await expect.poll(() => refreshTokenOf(worker), { timeout: 15_000 }).not.toBe(stolen);

  // Someone who copied the old refresh token presents it after the rotation.
  const reuse = await fetch(`${API_ORIGIN}/api/v1/auth/refresh`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Ruvee-Request': '1',
      Origin: `chrome-extension://${EXTENSION_ID}`,
    },
    body: JSON.stringify({ refreshToken: stolen }),
  });
  expect(reuse.status).toBe(401);
  // The whole family is revoked: the extension's next sync finds its session gone and locks.
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByText('Your vault is locked.')).toBeVisible({ timeout: 30_000 });
  expect(await sessionKeys(worker)).not.toContain('ak');
  const reuses = await sql<{ n: string }>(
    `SELECT count(*) AS n FROM security_events WHERE type = 'refresh_reuse'`,
  );
  expect(reuses[0]?.n).toBe('1');
  // Unlocking signs in again, with a new session.
  await unlock(NEW_MASTER);
});

test('logout ends the session and removes AK and both tokens', async () => {
  await popup.getByRole('button', { name: 'Log out' }).click();
  await expect(popup.getByText('Your vault is locked.')).toBeVisible({ timeout: 30_000 });
  const keys = await sessionKeys(worker);
  expect(keys).not.toContain('ak');
  expect(keys).not.toContain('accessToken');
  expect(await refreshTokenOf(worker)).toBeUndefined();
  const live = await sql<{ n: string }>(
    `SELECT count(*) AS n FROM sessions WHERE kind = 'token' AND revoked_at IS NULL`,
  );
  expect(live[0]?.n).toBe('0');
  await unlock(NEW_MASTER);
});

test('a revoked extension loses access when it reconnects, and must be paired again', async () => {
  // Locked, as a lost browser would be, when the web app removes it.
  await popup.getByRole('button', { name: 'Lock' }).click();
  await expect(popup.getByText('Your vault is locked.')).toBeVisible();
  await web.bringToFront();
  await web.getByRole('button', { name: 'Devices' }).click();
  await web
    .getByRole('listitem')
    .filter({ hasText: 'Browser extension' })
    .getByRole('button', { name: /^Remove/ })
    .click();
  await web.getByRole('textbox', { name: 'Master password', exact: true }).fill(NEW_MASTER);
  await web.getByRole('button', { name: 'Remove device' }).click();
  // Every login in this suite comes from 127.0.0.1, so the per-IP limit (20 a minute) can be
  // reached here; that is the limiter working. Wait out the window it names, then retry once.
  const limited = web.getByText(/Too many attempts\. Wait (\d+) seconds/);
  const outcome = await Promise.race([
    limited.waitFor({ timeout: 30_000 }).then(() => 'limited' as const),
    web
      .getByText(/^Removed/)
      .waitFor({ timeout: 30_000 })
      .then(() => 'removed' as const),
  ]);
  if (outcome === 'limited') {
    const seconds = Number(/Wait (\d+) seconds/.exec(await limited.innerText())?.[1] ?? '60');
    await web.waitForTimeout((seconds + 1) * 1000);
    await web.getByRole('button', { name: 'Remove device' }).click();
  }
  await expect(web.getByText(/^Removed/)).toBeVisible({ timeout: 30_000 });

  // The local password still opens the local copy, but the first server contact wipes it.
  await popup.bringToFront();
  await popup.goto(popupUrl(siteTab));
  await popup.getByLabel('Master password', { exact: true }).fill(NEW_MASTER);
  await popup.getByRole('button', { name: 'Unlock' }).click();
  await expect(popup.getByText(/removed from your account/)).toBeVisible({ timeout: 30_000 });
  const keys = await sessionKeys(worker);
  expect(keys).not.toContain('ak');
  expect(keys).not.toContain('accessToken');
  expect(await refreshTokenOf(worker)).toBeUndefined();
  expect(await deviceRecords(worker)).toBe(0);
  // Logging in again makes a new pending device; nothing opens until it is paired again.
  await popup.goto(popupUrl(siteTab));
  await popup.getByLabel('Username').fill(USERNAME);
  await popup.getByLabel('Master password').fill(NEW_MASTER);
  await popup.getByRole('button', { name: 'Log in' }).click();
  await expect(popup.getByLabel('Pairing code')).toBeVisible({ timeout: 30_000 });
});

test('A-07: a join survives the popup closing and the worker restarting; then only the password is asked', async () => {
  // Continues from the pending browser of the previous test (logged in with NEW_MASTER).
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
  // The join's secrets wait in memory-only session storage; the password is not among them.
  expect(await sessionKeys(worker)).toContain('pairingJoin');
  await stopWorker();
  await popup.close();

  await web.bringToFront();
  await expect(web.getByText(/Approve a new\s+browser extension/)).toBeVisible({ timeout: 15_000 });
  await web.getByRole('button', { name: 'Approve' }).click();
  await expect(web.getByText('The new device was added.')).toBeVisible();

  // The restarted worker kept the join but not the password: the reopened popup asks for it
  // alone, with no code form, and that finishes the enrollment.
  popup = await context.newPage();
  await popup.goto(popupUrl(siteTab));
  await expect(popup.getByText('Waiting for approval')).toBeVisible({ timeout: 30_000 });
  await expect(popup.getByLabel('Pairing code')).toHaveCount(0);
  await popup.getByLabel('Master password').fill(NEW_MASTER);
  await popup.getByRole('button', { name: 'Finish adding this browser' }).click();
  await expect(popup.getByRole('button', { name: 'Fill Synthetic Portal' })).toBeVisible({
    timeout: 30_000,
  });
  const keys = await sessionKeys(worker);
  expect(keys).toContain('ak');
  expect(keys).not.toContain('pairingJoin');
});

test('capture: nothing secret on the wire, in the extension stores, or sent with a cookie', async () => {
  // ---- Capture: nothing secret on the wire, in the extension's stores, or with a cookie ----
  expect(cookiesToApi).toEqual([]);
  const forbidden = [
    MASTER,
    NEW_MASTER,
    ITEM_PASSWORD,
    kit,
    kit.replace(/-/g, ''),
    'Synthetic Portal',
  ];
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
  // Phase B: the password saved from a sign-in reaches the server and the stores only encrypted.
  expect(toServer.join('\n')).not.toContain(SAVED_PASSWORD);
  expect(stored).not.toContain(SAVED_PASSWORD);
});

async function sessionKeys(w: Worker): Promise<string[]> {
  return w.evaluate(async () => Object.keys(await chrome.storage.session.get(null as never)));
}

/** The id of the suite's own login ("Synthetic Portal"); phase B saves a second one there. */
async function firstItemId(popup: Page, tab: number): Promise<string> {
  return popup.evaluate(async (tabId) => {
    const reply = (await chrome.runtime.sendMessage({ kind: 'candidates', tabId })) as {
      result: { items: { id: string; title: string }[] };
    };
    return reply.result.items.find((i) => i.title === 'Synthetic Portal')?.id ?? '';
  }, tab);
}

async function refreshTokenOf(w: Worker): Promise<string | undefined> {
  return w.evaluate(
    () =>
      new Promise<string | undefined>((resolve, reject) => {
        const req = indexedDB.open('ruvee-extension');
        req.onerror = () => {
          reject(new Error('open failed'));
        };
        req.onsuccess = () => {
          const db = req.result;
          const get = db.transaction('tokens').objectStore('tokens').get('refresh');
          get.onsuccess = () => {
            db.close();
            resolve(typeof get.result === 'string' ? get.result : undefined);
          };
        };
      }),
  );
}

async function deviceRecords(w: Worker): Promise<number> {
  return w.evaluate(
    () =>
      new Promise<number>((resolve, reject) => {
        const req = indexedDB.open('ruvee');
        req.onerror = () => {
          reject(new Error('open failed'));
        };
        req.onsuccess = () => {
          const db = req.result;
          const count = db.transaction('device').objectStore('device').count();
          count.onsuccess = () => {
            db.close();
            resolve(count.result);
          };
        };
      }),
  );
}

/** SQL against this run's throwaway database (named in the stack's state file). */
async function sql<T = Record<string, unknown>>(text: string): Promise<T[]> {
  const { database } = JSON.parse(readFileSync(STATE_FILE, 'utf8')) as { database: string };
  const url = new URL(process.env.RUVEE_E2E_ADMIN_DATABASE_URL ?? '');
  url.pathname = `/${database}`;
  const client = new pg.Client({ connectionString: url.toString() });
  await client.connect();
  try {
    return (await client.query(text)).rows as T[];
  } finally {
    await client.end();
  }
}
