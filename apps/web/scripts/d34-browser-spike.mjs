// D-34 §8 spike (docs/security/web-reload-unlock.md §8): the browser facts behind the web reload
// ticket, in Chromium, Firefox and WebKit. Not a test; it prints what each engine does.
//   node apps/web/scripts/d34-browser-spike.mjs apps/web
/* global window, indexedDB -- callbacks passed to page.evaluate run in the browser */
import http from 'node:http';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(path.resolve(process.argv[2] ?? 'apps/web') + '/');
const pw = require('@playwright/test');

const PAGE = `<!doctype html><meta charset=utf-8><title>spike</title><body>
<script>
window.workerValue = () => new Promise((r) => { w.onmessage = (e) => r(e.data); w.postMessage('get'); });
const w = new Worker('/w.js'); window.w = w;
window.addEventListener('pageshow', (e) => { window.persisted = e.persisted; });
window.addEventListener('pagehide', (e) => { sessionStorage.setItem('pagehide', String(e.persisted)); });
</script>`;
const OTHER = `<!doctype html><meta charset=utf-8><title>other</title><body>other`;
const WORKER = `let v = crypto.getRandomValues(new Uint32Array(1))[0]; onmessage = () => postMessage(v);`;

const server = http.createServer((req, res) => {
  const body = req.url.startsWith('/w.js') ? WORKER : req.url.startsWith('/other') ? OTHER : PAGE;
  res.writeHead(200, {
    'content-type': req.url.startsWith('/w.js') ? 'text/javascript' : 'text/html',
  });
  res.end(body);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://127.0.0.1:${server.address().port}`;

function scan(dir, needles) {
  const hits = Object.fromEntries(Object.keys(needles).map((k) => [k, []]));
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) {
        let buf;
        try {
          buf = fs.readFileSync(p);
        } catch {
          continue;
        }
        for (const [k, n] of Object.entries(needles))
          if (n.some((x) => buf.includes(x))) hits[k].push(path.relative(dir, p));
      }
    }
  };
  walk(dir);
  return hits;
}

const results = {};
for (const name of ['chromium', 'firefox', 'webkit']) {
  const r = (results[name] = {});
  const engine = pw[name];
  try {
    // --- non-persistent context: reload, new tab, window.open, bfcache, worker ---
    // Playwright turns bfcache off in Chromium by default; turn it back on for the bfcache check.
    const browser = await engine.launch(
      name === 'chromium' ? { ignoreDefaultArgs: ['--disable-back-forward-cache'] } : {},
    );
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    await page.goto(ORIGIN + '/');
    await page.evaluate(() => sessionStorage.setItem('m', 'tab-secret'));
    const w1 = await page.evaluate(() => window.workerValue());
    await page.reload();
    r.reload_keeps_sessionStorage =
      (await page.evaluate(() => sessionStorage.getItem('m'))) === 'tab-secret';
    r.reload_pagehide_persisted = await page.evaluate(() => sessionStorage.getItem('pagehide'));
    r.reload_worker_state_lost = (await page.evaluate(() => window.workerValue())) !== w1;

    const p2 = await ctx.newPage();
    await p2.goto(ORIGIN + '/');
    r.new_tab_sessionStorage_empty =
      (await p2.evaluate(() => sessionStorage.getItem('m'))) === null;

    const [popup] = await Promise.all([
      ctx.waitForEvent('page'),
      page.evaluate((o) => {
        window.open(o + '/', '_blank');
      }, ORIGIN),
    ]);
    await popup.waitForLoadState();
    r.window_open_copies_sessionStorage =
      (await popup.evaluate(() => sessionStorage.getItem('m'))) === 'tab-secret';
    const [popup2] = await Promise.all([
      ctx.waitForEvent('page'),
      page.evaluate((o) => {
        window.open(o + '/', '_blank', 'noopener');
      }, ORIGIN),
    ]);
    await popup2.waitForLoadState();
    r.window_open_noopener_copies_sessionStorage =
      (await popup2.evaluate(() => sessionStorage.getItem('m'))) === 'tab-secret';

    // bfcache: away and back, without and with a held Web Lock
    for (const withLock of [false, true]) {
      const p = await ctx.newPage();
      await p.goto(ORIGIN + '/');
      if (withLock)
        await p.evaluate(
          () =>
            new Promise((res) => {
              navigator.locks.request('ruvee-vault', () => {
                res();
                return new Promise(() => undefined);
              });
            }),
        );
      const before = await p.evaluate(() => window.workerValue());
      await p.goto(ORIGIN + '/other');
      await p.goBack();
      await p.waitForFunction(() => typeof window.workerValue === 'function');
      const persisted = await p.evaluate(() => window.persisted);
      const after = await p.evaluate(() => window.workerValue());
      r[`bfcache${withLock ? '_with_weblock' : ''}`] = {
        restored_from_bfcache: persisted === true,
        worker_state_kept: after === before,
      };
      await p.close();
    }
    await browser.close();

    // --- persistent profile: what reaches disk ---
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), `spike-${name}-`));
    const keyBytes = Buffer.from(Array.from({ length: 32 }, (_, i) => (i * 37 + 11) & 0xff));
    const marker = 'RUVEE-SPIKE-SESSIONSTORAGE-7f3a9c';
    const pc = await engine.launchPersistentContext(dir);
    const pp = pc.pages()[0] ?? (await pc.newPage());
    await pp.goto(ORIGIN + '/');
    r.nonextractable = await pp.evaluate(
      async ({ kb, marker }) => {
        sessionStorage.setItem('ticket', marker);
        const key = await crypto.subtle.importKey('raw', new Uint8Array(kb), 'AES-GCM', false, [
          'encrypt',
          'decrypt',
        ]);
        let exportRefused = false;
        try {
          await crypto.subtle.exportKey('raw', key);
        } catch {
          exportRefused = true;
        }
        const iv = new Uint8Array(12);
        const ct = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          key,
          new TextEncoder().encode('hello'),
        );
        const db = await new Promise((res, rej) => {
          const o = indexedDB.open('spike', 1);
          o.onupgradeneeded = () => o.result.createObjectStore('k');
          o.onsuccess = () => res(o.result);
          o.onerror = () => rej(o.error);
        });
        await new Promise((res, rej) => {
          const t = db.transaction('k', 'readwrite');
          t.objectStore('k').put(key, 'key');
          t.oncomplete = res;
          t.onerror = () => rej(t.error);
        });
        const back = await new Promise((res) => {
          const g = db.transaction('k').objectStore('k').get('key');
          g.onsuccess = () => res(g.result);
        });
        const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, back, ct);
        return {
          exportRefused,
          storedKeyStillUsable: new TextDecoder().decode(pt) === 'hello',
          storedKeyExtractable: back.extractable,
        };
      },
      { kb: [...keyBytes], marker },
    );
    await pp.reload();
    r.persistent_reload_keeps_sessionStorage =
      (await pp.evaluate(() => sessionStorage.getItem('ticket'))) === marker;
    await new Promise((res) => setTimeout(res, 2000));
    await pc.close();
    const hits = scan(dir, {
      sessionStorage_marker: [Buffer.from(marker, 'latin1'), Buffer.from(marker, 'utf16le')],
      cryptokey_raw_bytes: [keyBytes],
    });
    r.on_disk_after_close = hits;
    // a new launch of the same profile (Playwright starts without session restore)
    const pc2 = await engine.launchPersistentContext(dir);
    const pp2 = pc2.pages()[0] ?? (await pc2.newPage());
    await pp2.goto(ORIGIN + '/');
    r.relaunch_new_page_sessionStorage = await pp2.evaluate(() => sessionStorage.getItem('ticket'));
    await pc2.close();
    fs.rmSync(dir, { recursive: true, force: true });
  } catch (e) {
    r.error = String(e?.stack ?? e);
  }
}
server.close();
console.log(JSON.stringify(results, null, 2));
