import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { join } from 'node:path';
import {
  CACHE_HASHED_STATIC,
  CACHE_HTML,
  FORBIDDEN_SCRIPT_TOKENS,
  HSTS_PUBLIC,
  PERMISSIONS_POLICY,
  STATIC_SECURITY_HEADERS,
  contentSecurityPolicy,
  cspProblems,
  inlineScriptBodies,
  isHashedStaticPath,
  sha256SourceHash,
} from '../../security-headers';

function sha256(bytes: Uint8Array): Uint8Array {
  return createHash('sha256').update(bytes).digest();
}

describe('production security headers', () => {
  it('builds a CSP without unsafe-inline or unsafe-eval', () => {
    const body = 'self.__next_f.push([0])';
    const hash = sha256SourceHash(body, sha256);
    const csp = contentSecurityPolicy([hash]);
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self' 'wasm-unsafe-eval'");
    expect(csp).toContain(hash);
    expect(csp).toContain("style-src 'self'");
    expect(csp).toContain("worker-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    for (const token of FORBIDDEN_SCRIPT_TOKENS) expect(csp).not.toContain(token);
    expect(csp).not.toContain('require-trusted-types-for');
  });

  it('hashes only executable inline scripts', () => {
    const html = [
      '<script src="/a.js"></script>',
      '<script>alpha()</script>',
      '<script type="application/json">{"x":1}</script>',
      '<script type="module">beta()</script>',
      '<script></script>',
    ].join('');
    expect(inlineScriptBodies(html)).toEqual(['alpha()', 'beta()']);
  });

  it('lists camera=(self) and disables the other features', () => {
    expect(PERMISSIONS_POLICY.startsWith('camera=(self), ')).toBe(true);
    expect(PERMISSIONS_POLICY).toContain('geolocation=()');
    expect(PERMISSIONS_POLICY).toContain('microphone=()');
    expect(PERMISSIONS_POLICY).not.toContain('camera=()');
  });

  it('keeps HSTS out of the local header set', () => {
    expect(STATIC_SECURITY_HEADERS).not.toHaveProperty('Strict-Transport-Security');
    expect(HSTS_PUBLIC).toBe('max-age=31536000; includeSubDomains');
  });

  it('treats hashed Next assets as immutable and HTML as no-store', () => {
    expect(isHashedStaticPath('/_next/static/chunks/app.js')).toBe(true);
    expect(isHashedStaticPath('/index.html')).toBe(false);
    expect(CACHE_HTML).toBe('no-store');
    expect(CACHE_HASHED_STATIC).toContain('immutable');
  });
});

describe('Caddyfile matches the header module', () => {
  const caddy = readFileSync(join(process.cwd(), '../../deploy/Caddyfile'), 'utf8');

  // The values themselves come from the generated snippet; apps/api/scripts/check-caddy.mjs
  // compares what real Caddy serves with this module and this build's CSP (review R10).
  it('takes every header from the generated snippet, with no environment fallback', () => {
    const imports =
      caddy.match(/^\s*import \S+\/out-caddy\/security-headers\.caddy (\w+)$/gm) ?? [];
    expect(imports).toHaveLength(2);
    expect(caddy).toMatch(/handle_errors \{\s*import \S+security-headers\.caddy errors/);
    expect(caddy).not.toMatch(/RUVEE_CSP|Content-Security-Policy|Cache-Control/);
    for (const name of Object.keys(STATIC_SECURITY_HEADERS)) expect(caddy).not.toContain(name);
  });

  it('does not enable HSTS, unsafe-inline or unsafe-eval', () => {
    expect(caddy).not.toMatch(/^\s*header .*Strict-Transport-Security/m);
    expect(caddy).not.toContain("'unsafe-inline'");
    expect(caddy).not.toContain("'unsafe-eval'");
  });
});

describe('the CSP the Caddy snippet may carry (review R10)', () => {
  const good = contentSecurityPolicy([sha256SourceHash('self.__next_f.push([0])', sha256)]);

  it('accepts the policy built from an export', () => {
    expect(cspProblems(good)).toEqual([]);
  });

  it.each([
    ['empty', ''],
    ['whitespace', '  '],
    ['without script hashes', contentSecurityPolicy([])],
    ['without default-src none', good.replace("default-src 'none'", "default-src 'self'")],
    ['without frame-ancestors', good.replace("frame-ancestors 'none'", '')],
    ['with unsafe-inline', good.replace("script-src 'self'", "script-src 'self' 'unsafe-inline'")],
    ['with unsafe-eval', good.replace("script-src 'self'", "script-src 'self' 'unsafe-eval'")],
    ['with a quote that would end the Caddy string', `${good}; report-uri "x`],
    ['with a brace Caddy would parse', `${good}; report-uri {x}`],
  ])('refuses a policy %s', (_label, csp) => {
    expect(cspProblems(csp)).not.toEqual([]);
  });
});
