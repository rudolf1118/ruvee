// The mobile vault, end to end, on an Android emulator: the installed app (Hermes, native
// libsodium, the native OPAQUE binding, SQLite and the Android Keystore) against a real API and
// a throwaway PostgreSQL database, with the real web app in Chromium as the other device.
// Synthetic data only. One serial scenario: each step builds on the account state of the last.
//
// Preconditions (docs/mobile/testing.md): a booted emulator (RUVEE_E2E_SERIAL), the debug app
// installed, Metro running on 8081, prior builds of the API and the web export, and
// RUVEE_E2E_ADMIN_DATABASE_URL.

import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { appendFileSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
  adb,
  appFiles,
  clearAppData,
  clearLog,
  contains,
  deviceLog,
  reverse,
  unreverse,
} from '../lib/adb.ts';
import { phoneNetwork, type PhoneNetwork } from '../lib/network.ts';
import { Phone, startAppium } from '../lib/mobile.ts';
import { startStack, type Stack } from '../lib/stack.ts';
import { WebDevice } from '../lib/web.ts';

const SERIAL = process.env.RUVEE_E2E_SERIAL ?? 'emulator-5584';
const WEB_PORT = Number(process.env.RUVEE_E2E_WEB_PORT ?? 3171);
const API_PORT = Number(process.env.RUVEE_E2E_API_PORT ?? 4171);
const APPIUM_PORT = Number(process.env.RUVEE_E2E_APPIUM_PORT ?? 4723);
const PROXY_PORT = Number(process.env.RUVEE_E2E_PROXY_PORT ?? 3181);
const ARTIFACTS = process.env.RUVEE_E2E_ARTIFACTS ?? join(tmpdir(), 'ruvee-mobile-e2e-artifacts');

const USERNAME = 'synthetic-mobile-owner';
// Sentinels: none of these may appear in any log or in the app's files in plain text.
const MASTER = 'synthetic mobile harbor lantern 58';
const CHANGED = 'synthetic mobile changed lantern 27';
const ITEM_PASSWORD = 'synthetic-mobile-item-secret-4c1';
const NOTE_TEXT = 'synthetic mobile note body 7d2';
const MOBILE_SECRET = 'synthetic-mobile-made-secret-9a8';
const SENTINELS = [MASTER, CHANGED, ITEM_PASSWORD, NOTE_TEXT, MOBILE_SECRET];

let stack: Stack;
let web: WebDevice;
let phone: Phone;
let appium: { stop: () => Promise<void> };
let network: PhoneNetwork;
let recoveryKit = '';
let pairingCode = '';

before(async () => {
  mkdirSync(ARTIFACTS, { recursive: true });
  stack = await startStack({ webPort: WEB_PORT, apiPort: API_PORT });
  clearAppData(SERIAL);
  clearLog(SERIAL);
  network = await phoneNetwork({
    listenPort: PROXY_PORT,
    targetPort: WEB_PORT,
    trace: (line) => appendFileSync(join(ARTIFACTS, 'network.log'), `${line}\n`),
  });
  reverse(SERIAL, WEB_PORT, PROXY_PORT);
  reverse(SERIAL, 8081, 8081);
  appium = await startAppium(APPIUM_PORT);
  phone = await Phone.connect({ appiumPort: APPIUM_PORT, serial: SERIAL, artifacts: ARTIFACTS });
  web = await WebDevice.open(stack.origin);
});

after(async () => {
  await phone?.close();
  await appium?.stop();
  await web?.close();
  unreverse(SERIAL, WEB_PORT);
  await network?.close();
  await stack?.stop();
});

let broken: string | undefined;

/** Runs one step; after a failure the later steps are skipped, since each builds on the last. */
async function step(
  name: string,
  run: () => Promise<void>,
  t?: { skip(message: string): void },
): Promise<void> {
  if (broken) {
    t?.skip(`skipped: ${broken} failed`);
    return;
  }
  try {
    await run();
  } catch (error) {
    broken = name;
    await phone.screenshot(`failed-${name}`).catch(() => undefined);
    await web.page
      .screenshot({ path: join(ARTIFACTS, `failed-${name}-web.png`) })
      .catch(() => undefined);
    throw error;
  }
}

test(
  'mobile vault against the real API, with the web app as the other device',
  { timeout: 1_800_000 },
  async (t) => {
    await t.test('web: account setup and two items', (st) =>
      step(
        'web-setup',
        async () => {
          recoveryKit = await web.createAccount({
            bootstrapToken: stack.bootstrapToken,
            username: USERNAME,
            password: MASTER,
          });
          assert.match(recoveryKit, /^RK1-/);
          await web.addLogin({
            title: 'Synthetic Mail',
            url: 'https://mail.example',
            username: 'owner@mail.example',
            password: ITEM_PASSWORD,
          });
          await web.addNote({ title: 'Synthetic Wi-Fi', text: NOTE_TEXT });
          await web.waitSynced();
        },
        st,
      ),
    );

    await t.test(
      'phone: server address, wrong password, then login as a new pending device',
      (st) =>
        step(
          'phone-login',
          async () => {
            await phone.type('server-url', 'http://10.0.2.2:1'); // plain HTTP elsewhere than loopback
            await phone.tap('server-continue');
            await phone.waitFor('server-error');
            await phone.type('server-url', stack.origin);
            await phone.tap('server-continue');
            await phone.type('signin-username', USERNAME);
            await phone.type('signin-password', `${MASTER} wrong`);
            await phone.tap('signin-submit');
            assert.match(await phone.text('signin-error', 60_000), /not correct/);
            await phone.type('signin-password', MASTER);
            await phone.tap('signin-submit');
            await phone.waitFor('pair-code', 60_000);
          },
          st,
        ),
    );

    await t.test(
      'pairing: web shows the code, phone joins, web approves an Android device (D-21, D-31)',
      (st) =>
        step(
          'pairing',
          async () => {
            pairingCode = await web.startPairing();
            await phone.type('pair-code', pairingCode);
            await phone.tap('pair-submit');
            await phone.waitFor('pair-waiting', 30_000);
            await web.approvePairing('Android device');
            await phone.waitUntilText('item-count', (s) => s === '2 items', 90_000);
            await phone.waitUntilText('sync-status', (s) => s.startsWith('Synced'), 60_000);
          },
          st,
        ),
    );

    await t.test(
      'web → phone: the phone shows what the web created, and reveals only on request',
      (st) =>
        step(
          'web-to-phone',
          async () => {
            await phone.tap('item-Synthetic Mail');
            assert.equal(await phone.text('detail-username'), 'owner@mail.example');
            assert.notEqual(await phone.text('detail-password'), ITEM_PASSWORD);
            await phone.tap('reveal-password');
            await phone.waitUntilText('detail-password', (s) => s === ITEM_PASSWORD);
            await phone.tap('hide-password');
            await phone.tap('item-back');
            await phone.tap('item-Synthetic Wi-Fi');
            assert.equal(await phone.text('detail-note'), NOTE_TEXT);
            await phone.tap('item-back');
          },
          st,
        ),
    );

    await t.test(
      'phone → web: an item made on the phone and an edit made on the phone reach the web',
      (st) =>
        step(
          'phone-to-web',
          async () => {
            await phone.tap('add-login');
            await phone.type('edit-title', 'Phone Bank');
            await phone.type('edit-url', 'https://bank.example');
            await phone.type('edit-username', 'phone@bank.example');
            await phone.type('edit-password', MOBILE_SECRET);
            await phone.tap('edit-save');
            await phone.tap('item-back');
            await phone.tap('item-Synthetic Wi-Fi');
            await phone.tap('item-edit');
            await phone.type('edit-title', 'Synthetic Wi-Fi (phone)');
            await phone.tap('edit-save');
            await phone.tap('item-back');
            await phone.waitUntilText('sync-status', (s) => s.startsWith('Synced'), 60_000);
            await web.syncNow();
            await web.row(/Phone Bank/).waitFor({ timeout: 30_000 });
            await web.row(/Synthetic Wi-Fi \(phone\)/).waitFor({ timeout: 30_000 });
            await web.row(/Phone Bank/).click();
            await web.page.getByRole('button', { name: 'Reveal password' }).click();
            await web.page.getByText(MOBILE_SECRET).waitFor();
            await web.page.getByRole('button', { name: 'Hide password' }).click();
          },
          st,
        ),
    );

    await t.test('lock: the lock button, a wrong password, then the right one', (st) =>
      step(
        'lock',
        async () => {
          await phone.tap('vault-lock');
          await phone.waitFor('unlock-password');
          assert.equal(await phone.isShown('item-count'), false);
          await phone.type('unlock-password', `${MASTER}!`);
          await phone.tap('unlock-submit');
          assert.match(await phone.text('unlock-error', 30_000), /not the right master password/);
          await phone.type('unlock-password', MASTER);
          await phone.tap('unlock-submit');
          assert.equal(await phone.text('item-count', 60_000), '3 items');
        },
        st,
      ),
    );

    await t.test('lifecycle: leaving the app locks it; killing the process loses every key', (st) =>
      step(
        'lifecycle',
        async () => {
          await phone.background(2);
          await phone.waitFor('unlock-password');
          assert.match(await phone.text('lock-reason'), /left the screen/);
          await phone.type('unlock-password', MASTER);
          await phone.tap('unlock-submit');
          await phone.waitFor('item-count', 60_000);
          await phone.restart();
          await phone.waitFor('unlock-password', 60_000);
          await phone.type('unlock-password', MASTER);
          await phone.tap('unlock-submit');
          assert.equal(await phone.text('item-count', 60_000), '3 items');
        },
        st,
      ),
    );

    await t.test(
      'offline: an edit made offline survives a process restart and syncs on reconnect',
      (st) =>
        step(
          'offline',
          async () => {
            network.cut();
            await phone.tap('item-Phone Bank');
            await phone.tap('item-edit');
            await phone.type('edit-title', 'Phone Bank (offline)');
            await phone.tap('edit-save');
            await phone.tap('item-back');
            await phone.waitUntilText('sync-status', (s) => /Offline|waiting/.test(s), 60_000);
            await phone.restart();
            await phone.type('unlock-password', MASTER);
            await phone.tap('unlock-submit');
            await phone.waitFor('item-count', 60_000);
            await phone.waitForText('Phone Bank (offline)');
            await phone.waitUntilText('sync-status', (s) => /pending/.test(s), 30_000);
            network.restore();
            await phone.tap('vault-sync');
            await phone.waitUntilText(
              'sync-status',
              (s) => s.startsWith('Synced') && !/pending/.test(s),
              60_000,
            );
            await web.syncNow();
            await web.row(/Phone Bank \(offline\)/).waitFor({ timeout: 30_000 });
          },
          st,
        ),
    );

    await t.test(
      'conflict: phone and web change the same item; the phone keeps its version',
      (st) =>
        step(
          'conflict',
          async () => {
            network.cut();
            await phone.tap('item-Synthetic Mail');
            await phone.tap('item-edit');
            await phone.type('edit-title', 'Synthetic Mail (phone)');
            await phone.tap('edit-save');
            await phone.tap('item-back');
            await web.renameItem(/^Synthetic Mail/, 'Synthetic Mail (web)');
            network.restore();
            await phone.tap('vault-sync');
            await phone.waitFor('conflict-banner', 60_000);
            await phone.tap('item-Synthetic Mail (web)');
            await phone.waitFor('conflict-panel', 30_000);
            await phone.tap('conflict-mine');
            await phone.tap('item-back');
            await phone.waitUntilText(
              'sync-status',
              (s) => s.startsWith('Synced') && !/pending/.test(s),
              60_000,
            );
            assert.equal(await phone.isShown('conflict-banner'), false);
            await web.syncNow();
            await web.row(/Synthetic Mail \(phone\)/).waitFor({ timeout: 30_000 });
          },
          st,
        ),
    );

    await t.test(
      'password changed on the web while the phone holds an unsynced edit: the edit is kept',
      (st) =>
        step(
          'password-change',
          async () => {
            network.cut();
            await phone.tap('item-Synthetic Wi-Fi (phone)');
            await phone.tap('item-edit');
            await phone.type('edit-title', 'Synthetic Wi-Fi (pending)');
            await phone.tap('edit-save');
            await phone.tap('item-back');
            await phone.tap('vault-lock');
            await web.changePassword(MASTER, CHANGED);
            network.restore();
            // The local wrap still opens with the old password, but the server no longer accepts it.
            await phone.type('unlock-password', MASTER);
            await phone.tap('unlock-submit');
            await phone.waitFor('item-count', 60_000);
            await phone.waitFor('session-notice', 30_000);
            await phone.tap('vault-lock');
            // The new password: the server wrap opens with this device's own Secret Key.
            await phone.type('unlock-password', CHANGED);
            await phone.tap('unlock-submit');
            await phone.waitFor('item-count', 60_000);
            await phone.waitForText('Synthetic Wi-Fi (pending)');
            await phone.tap('vault-sync');
            await phone.waitUntilText(
              'sync-status',
              (s) => s.startsWith('Synced') && !/pending/.test(s),
              60_000,
            );
            await web.syncNow();
            await web.row(/Synthetic Wi-Fi \(pending\)/).waitFor({ timeout: 30_000 });
          },
          st,
        ),
    );

    await t.test(
      'no sentinel in the device log, the app files, or the server logs; no Secret Key in SQLite',
      (st) =>
        step(
          'sentinels',
          async () => {
            const { text, excludedLines } = deviceLog(SERIAL);
            assert.ok(excludedLines > 0, 'the instrumentation filter matched nothing');
            const log = Buffer.from(text, 'utf8');
            for (const s of [...SENTINELS, recoveryKit, pairingCode])
              assert.equal(
                contains(log, s),
                false,
                `device log holds a sentinel (${s.slice(0, 12)}…)`,
              );
            const files = appFiles(SERIAL);
            assert.ok(
              [...files.keys()].some((f) => f.includes('ruvee-device.sqlite')),
              'the vault database exists',
            );
            for (const [path, bytes] of files)
              for (const s of [
                ...SENTINELS,
                recoveryKit,
                pairingCode,
                'Synthetic Mail',
                'owner@mail.example',
              ])
                assert.equal(
                  contains(bytes, s),
                  false,
                  `${path} holds plaintext (${s.slice(0, 12)}…)`,
                );
            const db = [...files.entries()]
              .filter(([f]) => f.includes('ruvee-device.sqlite'))
              .map(([, b]) => b);
            for (const b of db)
              assert.equal(contains(b, '"secretKey":'), false, 'SK is in the database');
            const server = Buffer.from(stack.logs(), 'utf8');
            for (const s of [...SENTINELS, recoveryKit, pairingCode])
              assert.equal(
                contains(server, s),
                false,
                `server log holds a sentinel (${s.slice(0, 12)}…)`,
              );
          },
          st,
        ),
    );

    await t.test(
      'revocation: the web removes the phone; the phone erases its copy at its next request',
      (st) =>
        step(
          'revocation',
          async () => {
            await web.removePairedDevice(CHANGED);
            await phone.tap('vault-sync');
            await phone.waitFor('revoked-start-again', 60_000);
            const files = appFiles(SERIAL);
            const db = [...files.entries()]
              .filter(([f]) => f.includes('ruvee-device.sqlite'))
              .map(([, b]) => b);
            for (const b of db) {
              assert.equal(
                contains(b, '"deviceId"'),
                false,
                'the device record survived revocation',
              );
            }
            await phone.restart();
            await phone.waitFor('signin-username', 60_000);
          },
          st,
        ),
    );
  },
);
