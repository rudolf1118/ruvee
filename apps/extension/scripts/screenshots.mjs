// Screenshots of the popup and the settings page for design review, from a built dist/ (run the
// build first). The pages run against a stub of the `chrome` API with synthetic data: no server,
// no worker, no real site. Usage: node scripts/screenshots.mjs <output dir>
import { mkdir, readFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';

const dist = new URL('../dist/', import.meta.url);
const outDir = process.argv[2];
if (!outDir) throw new Error('usage: node scripts/screenshots.mjs <output dir>');
await mkdir(outDir, { recursive: true });

// The worker compares its build id with the page's; the stub answers with the page's own.
const popupJs = await readFile(new URL('popup.js', dist), 'utf8');
const build = /"(\d{4}-\d\d-\d\dT[\d:.]+Z)"/.exec(popupJs)?.[1];
if (!build) throw new Error('no build id in popup.js');

const SERVER = 'https://vault.synthetic.example';
const SITE = 'https://portal.synthetic.example';
const LOGINS = [
  { id: 'a', title: 'Synthetic Portal', username: 'ada@synthetic.example' },
  { id: 'b', title: 'Portal (work)', username: 'ada.work@synthetic.example' },
  { id: 'c', title: 'Billing', username: 'billing-admin' },
];

const STATES = {
  locked: { unlocked: false, phase: 'enrolled' },
  unlocked: { unlocked: true, items: LOGINS },
  'no-logins': { unlocked: true, items: [] },
  'save-offer': {
    unlocked: true,
    items: LOGINS.slice(0, 1),
    pending: { origin: SITE, username: 'new-user@synthetic.example' },
  },
  unpaired: { unlocked: false, phase: 'new' },
  'no-server': { server: null },
};

/** Installed in the page before its script runs. */
function stub({ state, build, server, site }) {
  const reply = (result) => Promise.resolve({ ok: true, result });
  const answers = {
    status: () =>
      reply({
        serverOrigin: state.server === undefined ? server : state.server,
        unlocked: state.unlocked,
        build,
      }),
    vault: (req) =>
      req.method === 'phase'
        ? reply({ phase: state.phase })
        : req.method === 'sync'
          ? reply({ state: 'synced', pendingCount: 0, lastSyncedAtMs: 0, lastChange: null })
          : reply(true),
    candidates: () => reply({ origin: site, items: state.items ?? [] }),
    pendingSave: () => reply(state.pending ?? null),
    inlineSettings: () => reply({ enabled: true, autoOpenSave: false }),
    pairing: () => reply({ state: 'idle', problem: null, needsPassword: false }),
  };
  const noop = () => Promise.resolve();
  globalThis.chrome = {
    runtime: {
      id: 'synthetic',
      sendMessage: (req) => (answers[req.kind] ?? (() => reply(true)))(req),
      openOptionsPage: noop,
      reload: () => undefined,
      getURL: (p) => p,
    },
    tabs: {
      query: () => Promise.resolve([{ id: 7, windowId: 1 }]),
      create: noop,
      update: noop,
    },
    windows: { update: noop },
    permissions: { request: () => Promise.resolve(true), contains: () => Promise.resolve(true) },
    storage: { session: { get: () => Promise.resolve({}) } },
  };
}

const browser = await chromium.launch({ channel: 'chromium' });
const shots = [];
for (const scheme of ['light', 'dark'])
  for (const [name, state] of Object.entries(STATES)) {
    const page = await browser.newPage({
      viewport: { width: 400, height: 600 },
      deviceScaleFactor: 2,
      colorScheme: scheme,
    });
    await page.addInitScript(stub, { state, build, server: SERVER, site: SITE });
    await page.goto(new URL('popup.html', dist).href);
    await page.waitForLoadState('networkidle');
    await page.waitForTimeout(300);
    const file = `${outDir}/popup-${name}-${scheme}.png`;
    // The popup's own size, as the browser would show it.
    await page.locator('main').screenshot({ path: file });
    shots.push(file);
    await page.close();
  }
for (const scheme of ['light', 'dark']) {
  const page = await browser.newPage({
    viewport: { width: 900, height: 900 },
    colorScheme: scheme,
  });
  await page.addInitScript(stub, { state: STATES.unlocked, build, server: SERVER, site: SITE });
  await page.goto(new URL('options.html', dist).href);
  await page.waitForLoadState('networkidle');
  await page.waitForTimeout(300);
  const file = `${outDir}/options-${scheme}.png`;
  await page.screenshot({ path: file, fullPage: true });
  shots.push(file);
  await page.close();
}
await browser.close();
console.log(shots.join('\n'));
