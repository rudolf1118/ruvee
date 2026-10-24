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

  it('sets every static production header from the shared module', () => {
    expect(caddy).toContain('Content-Security-Policy {$RUVEE_CSP}');
    for (const [name, value] of Object.entries(STATIC_SECURITY_HEADERS)) {
      if (name === 'Permissions-Policy') {
        expect(caddy).toContain(`Permissions-Policy "${value}"`);
        continue;
      }
      expect(caddy).toContain(`${name} ${value}`);
    }
    expect(caddy).toContain('Cache-Control no-store');
    expect(caddy).toContain(`Cache-Control "${CACHE_HASHED_STATIC}"`);
  });

  it('does not enable HSTS, unsafe-inline or unsafe-eval', () => {
    expect(caddy).not.toMatch(/^\s*header .*Strict-Transport-Security/m);
    expect(caddy).not.toContain("'unsafe-inline'");
    expect(caddy).not.toContain("'unsafe-eval'");
  });
});
