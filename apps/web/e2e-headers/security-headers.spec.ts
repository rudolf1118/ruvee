import { expect, test } from '@playwright/test';
import {
  CACHE_HASHED_STATIC,
  CACHE_HTML,
  FORBIDDEN_SCRIPT_TOKENS,
  STATIC_SECURITY_HEADERS,
} from '../security-headers';

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
});

test.describe('CSP behaviour', () => {
  test('blocks an injected inline script', async ({ page }) => {
    await page.goto('/');
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

  test('loads @ruvee/crypto in a worker under the production CSP', async ({ page }) => {
    const cspErrors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error' && /content security policy/i.test(msg.text())) {
        cspErrors.push(msg.text());
      }
    });
    await page.goto('/csp-probe');
    const result = page.locator('#csp-probe-result');
    await expect(result).not.toHaveText('pending', { timeout: 60_000 });
    const text = await result.innerText();
    expect(text, text).toMatch(/"ok":true/);
    expect(text).toMatch(/"evalBlocked":true/);
    expect(cspErrors).toEqual([]);
  });

  test('home page renders under the hashed CSP', async ({ page }) => {
    const cspErrors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error' && /content security policy/i.test(msg.text())) {
        cspErrors.push(msg.text());
      }
    });
    await page.goto('/');
    await expect(
      page.getByRole('heading', { name: 'Ruvee is in early development' }),
    ).toBeVisible();
    expect(cspErrors).toEqual([]);
  });
});
