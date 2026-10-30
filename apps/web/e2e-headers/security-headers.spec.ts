import { expect, test, type Page } from '@playwright/test';
import {
  CACHE_HASHED_STATIC,
  CACHE_HTML,
  DIAGNOSTICS_EXPORT_PORT,
  FORBIDDEN_SCRIPT_TOKENS,
  STATIC_SECURITY_HEADERS,
} from '../security-headers';

const diagnosticsOrigin = `http://127.0.0.1:${Number(
  process.env.RUVEE_DIAGNOSTICS_PORT ?? DIAGNOSTICS_EXPORT_PORT,
)}`;

/** Collects CSP violations as each engine reports them on the console. */
function watchCspViolations(page: Page): string[] {
  const violations: string[] = [];
  page.on('console', (msg) => {
    if (/content.security.policy|refused to (execute|load|apply|evaluate)/i.test(msg.text())) {
      violations.push(msg.text());
    }
  });
  return violations;
}

const withoutHashes = (csp: string) => csp.replace(/ 'sha256-[A-Za-z0-9+/=]+'/g, '');

test.describe('production export headers', () => {
  test('HTML responses send every documented header and a hash-based CSP', async ({ request }) => {
    const res = await request.get('/');
    expect(res.ok()).toBe(true);
    const headers = res.headers();
    for (const [name, value] of Object.entries(STATIC_SECURITY_HEADERS)) {
      expect(headers[name.toLowerCase()], name).toBe(value);
    }
    expect(headers['cache-control']).toBe(CACHE_HTML);
    const csp = headers['content-security-policy'];
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(csp).toMatch(/'sha256-[A-Za-z0-9+/=]+'/);
    for (const token of FORBIDDEN_SCRIPT_TOKENS) expect(csp).not.toContain(token);
    expect(headers['strict-transport-security']).toBeUndefined();
  });

  test('hashed static assets may be cached as immutable', async ({ page, request }) => {
    await page.goto('/');
    const scriptSrc = await page
      .locator('script[src^="/_next/static/"]')
      .first()
      .getAttribute('src');
    expect(scriptSrc).toBeTruthy();
    const res = await request.get(scriptSrc ?? '');
    expect(res.ok()).toBe(true);
    expect(res.headers()['cache-control']).toBe(CACHE_HASHED_STATIC);
    expect(res.headers()['content-security-policy']).toContain("default-src 'none'");
  });

  test('the ordinary export contains no diagnostic route or worker', async ({ request }) => {
    for (const path of [
      '/csp-probe',
      '/csp-probe.html',
      '/diagnostics/crypto-worker.js',
      '/diagnostics/opaque-worker.js',
      '/csp-probe-worker.js',
    ]) {
      const res = await request.get(path);
      expect(res.status(), path).toBe(404);
    }
  });

  test('the diagnostics export uses the same policy apart from its own hashes', async ({
    request,
  }) => {
    const ordinary = (await request.get('/')).headers()['content-security-policy'] ?? '';
    const diagnostics =
      (await request.get(`${diagnosticsOrigin}/csp-probe`)).headers()['content-security-policy'] ??
      '';
    expect(diagnostics).not.toBe('');
    expect(withoutHashes(diagnostics)).toBe(withoutHashes(ordinary));
  });
});

test.describe('CSP behaviour', () => {
  for (const [label, origin] of [
    ['ordinary export', ''],
    ['diagnostics export', diagnosticsOrigin],
  ] as const) {
    test(`blocks an injected inline script (${label})`, async ({ page }) => {
      await page.goto(`${origin}/`);
      const ran = await page.evaluate(() => {
        const marker = '__ruveeInjectedInline';
        (globalThis as unknown as Record<string, boolean>)[marker] = false;
        const script = document.createElement('script');
        script.textContent = `globalThis.${marker} = true`;
        document.body.appendChild(script);
        return (globalThis as unknown as Record<string, boolean>)[marker] === true;
      });
      expect(ran).toBe(false);
    });
  }

  test('loads @ruvee/crypto in a worker under the production CSP', async ({ page }) => {
    const violations = watchCspViolations(page);
    await page.goto(`${diagnosticsOrigin}/csp-probe`);
    const result = page.locator('#probe-crypto');
    await expect(result).not.toHaveText('pending', { timeout: 60_000 });
    const text = await result.innerText();
    expect(text, text).toMatch(/"ok":true/);
    expect(text).toMatch(/"evalBlocked":true/);
    expect(violations).toEqual([]);
  });

  test('runs @serenity-kit/opaque registration and login in a worker under the production CSP', async ({
    page,
  }) => {
    test.setTimeout(120_000);
    const violations = watchCspViolations(page);
    await page.goto(`${diagnosticsOrigin}/csp-probe`);
    const result = page.locator('#probe-opaque');
    await expect(result).not.toHaveText('pending', { timeout: 100_000 });
    const parsed = JSON.parse(await result.innerText()) as {
      ok: boolean;
      evalBlocked: boolean;
      error?: string;
      details?: Record<string, { clientAccepted: boolean; sessionKeysMatch: boolean }>;
    };
    expect(parsed.error).toBeUndefined();
    expect(parsed.evalBlocked).toBe(true);
    const details = parsed.details ?? {};
    expect(details.correctPassword?.sessionKeysMatch).toBe(true);
    expect(details.nfdTypedPassword?.sessionKeysMatch).toBe(true);
    expect(details.wrongPassword?.clientAccepted).toBe(false);
    expect(details.unknownUser?.clientAccepted).toBe(false);
    expect(details.substitutedServerSetup?.clientAccepted).toBe(false);
    expect(parsed.ok).toBe(true);
    expect(violations).toEqual([]);
  });

  test('negative control: without wasm-unsafe-eval the OPAQUE worker cannot start', async ({
    page,
  }) => {
    // Rewrites the CSP on every diagnostics response, worker script included, so the passing
    // probe above is known to run under the policy rather than despite it.
    await page.route(`${diagnosticsOrigin}/**`, async (route) => {
      const response = await route.fetch();
      const headers = response.headers();
      headers['content-security-policy'] = (headers['content-security-policy'] ?? '').replace(
        " 'wasm-unsafe-eval'",
        '',
      );
      await route.fulfill({ response, headers });
    });
    await page.goto(`${diagnosticsOrigin}/csp-probe`);
    const result = page.locator('#probe-opaque');
    await expect(result).not.toHaveText('pending', { timeout: 60_000 });
    expect(await result.innerText()).not.toMatch(/"ok":true/);
    // A diagnostics request can still be inside the handler when the probe has answered; it must
    // not outlive the test.
    await page.unrouteAll({ behavior: 'ignoreErrors' });
  });

  test('home page renders under the hashed CSP', async ({ page }) => {
    const violations = watchCspViolations(page);
    await page.goto('/');
    await expect(
      page.getByRole('heading', { name: 'Keep every password in one calm, safe place.' }),
    ).toBeVisible();
    // The vault worker (libsodium.js and OPAQUE) started under the policy: the welcome screen
    // appears only after the worker answered.
    expect(violations).toEqual([]);
  });

  test('loads its fonts from this origin only, with no request to any other host', async ({
    page,
    baseURL,
  }) => {
    const elsewhere: string[] = [];
    const fonts: string[] = [];
    page.on('request', (request) => {
      if (!request.url().startsWith(baseURL ?? '')) elsewhere.push(request.url());
      if (request.resourceType() === 'font') fonts.push(new URL(request.url()).pathname);
    });
    await page.goto('/');
    await expect(
      page.getByRole('heading', { name: 'Keep every password in one calm, safe place.' }),
    ).toBeVisible();
    await page.evaluate(() => document.fonts.ready);
    expect(elsewhere).toEqual([]);
    expect(fonts.length).toBeGreaterThan(0);
    for (const path of fonts) expect(path).toMatch(/^\/_next\/static\/media\/[\w.-]+\.woff2$/);
    expect(await page.evaluate(() => document.fonts.check('600 16px "Hanken Grotesk"'))).toBe(true);
  });
});
