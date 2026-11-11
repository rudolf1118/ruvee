/**
 * Production security headers for the static export (P2-04 / D-16).
 *
 * Next.js `headers()` is unsupported with `output: 'export'`. `next dev` keeps the small
 * Phase 1 set only: React Fast Refresh needs `'unsafe-eval'`, so the production CSP is never
 * applied there. Caddy and `scripts/serve-export.mjs` apply this module.
 */

export const EXPORT_PORT = 3101;
/** Port for the test-only diagnostics export (`out-diagnostics/`). */
export const DIAGNOSTICS_EXPORT_PORT = 3102;

/** Phase 1 headers still sent by `next dev`. Production adds the rest via the static server. */
export const NEXT_DEV_HEADERS: readonly { key: string; value: string }[] = [
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'no-referrer' },
  { key: 'X-Frame-Options', value: 'DENY' },
];

/**
 * Features disabled in Permissions-Policy. `camera=(self)` is the documented exception for
 * pairing QR codes (P2-12). Pairing itself is not implemented in this spike.
 */
export const PERMISSIONS_POLICY_DISABLED = [
  'accelerometer',
  'attribution-reporting',
  'autoplay',
  'bluetooth',
  'browsing-topics',
  'compute-pressure',
  'display-capture',
  'encrypted-media',
  'fullscreen',
  'geolocation',
  'gyroscope',
  'hid',
  'identity-credentials-get',
  'idle-detection',
  'local-fonts',
  'magnetometer',
  'microphone',
  'midi',
  'otp-credentials',
  'payment',
  'picture-in-picture',
  'publickey-credentials-create',
  'publickey-credentials-get',
  'screen-wake-lock',
  'serial',
  'storage-access',
  'usb',
  'web-share',
  'window-management',
  'xr-spatial-tracking',
] as const;

export const PERMISSIONS_POLICY = [
  'camera=(self)',
  ...PERMISSIONS_POLICY_DISABLED.map((name) => `${name}=()`),
].join(', ');

/**
 * HSTS is public-mode HTTPS only. Sending it on local HTTP would pin HTTPS for this host.
 */
export const HSTS_PUBLIC = 'max-age=31536000; includeSubDomains';

export const CACHE_HTML = 'no-store';
export const CACHE_HASHED_STATIC = 'public, max-age=31536000, immutable';

/**
 * CSP template. Script hashes are filled in from the export. `'unsafe-inline'` and
 * `'unsafe-eval'` are never added. `'wasm-unsafe-eval'` is required to instantiate libsodium.js
 * (ADR-0002); it does not allow JavaScript `eval`.
 *
 * Trusted Types (`require-trusted-types-for 'script'` / `trusted-types ruvee`) are omitted:
 * Next.js 16.4.2's static export creates script elements from the RSC payload at runtime and
 * does not go through a named policy. See api-design.md.
 */
export function contentSecurityPolicy(scriptHashes: readonly string[]): string {
  const hashes = [...new Set(scriptHashes)].sort();
  const scriptSrc = ["'self'", "'wasm-unsafe-eval'", ...hashes].join(' ');
  return [
    "default-src 'none'",
    `script-src ${scriptSrc}`,
    "style-src 'self'",
    "img-src 'self' data: blob:",
    "font-src 'self'",
    "connect-src 'self'",
    "worker-src 'self'",
    "manifest-src 'self'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "object-src 'none'",
  ].join('; ');
}

export const STATIC_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'X-Frame-Options': 'DENY',
  'Permissions-Policy': PERMISSIONS_POLICY,
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
};

const EXECUTABLE_SCRIPT_TYPES = new Set([
  '',
  'text/javascript',
  'application/javascript',
  'application/ecmascript',
  'module',
]);

/**
 * Inline executable `<script>` bodies. Scripts with `src`, non-JS `type`, or empty bodies are
 * skipped. The browser hashes the decoded text; this parser uses the raw file bytes as UTF-8,
 * which matches the export (no HTML entities inside these scripts).
 */
export function inlineScriptBodies(html: string): string[] {
  const bodies: string[] = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let match: RegExpExecArray | null;
  while ((match = re.exec(html)) !== null) {
    const attrs = match[1] ?? '';
    if (/\bsrc\s*=/i.test(attrs)) continue;
    const typeMatch = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(attrs);
    const type = (typeMatch?.[1] ?? typeMatch?.[2] ?? typeMatch?.[3] ?? '').trim().toLowerCase();
    if (!EXECUTABLE_SCRIPT_TYPES.has(type)) continue;
    const body = match[2] ?? '';
    if (body.length === 0) continue;
    bodies.push(body);
  }
  return bodies;
}

export function sha256SourceHash(body: string, sha256: (bytes: Uint8Array) => Uint8Array): string {
  const digest = sha256(Buffer.from(body, 'utf8'));
  return `'sha256-${Buffer.from(digest).toString('base64')}'`;
}

export function isHashedStaticPath(pathname: string): boolean {
  return pathname.startsWith('/_next/static/');
}

export const FORBIDDEN_SCRIPT_TOKENS = ["'unsafe-inline'", "'unsafe-eval'"] as const;

/**
 * Why a CSP must not be served (empty when it may). The Caddy header snippet is written only for
 * a policy with no problems, so a missing, empty or weakened policy stops the build instead of
 * reaching a browser (predeployment-review R10).
 */
export function cspProblems(csp: string): string[] {
  const problems: string[] = [];
  if (!csp.trim()) problems.push('it is empty');
  if (!/(^|;)\s*default-src 'none'/.test(csp)) problems.push("default-src is not 'none'");
  if (!/(^|;)\s*script-src [^;]*'sha256-[A-Za-z0-9+/=]{44}'/.test(csp))
    problems.push('script-src has no script hash');
  if (!/(^|;)\s*frame-ancestors 'none'/.test(csp)) problems.push("frame-ancestors is not 'none'");
  for (const token of FORBIDDEN_SCRIPT_TOKENS)
    if (csp.includes(token)) problems.push(`${token} is in it`);
  if (/["\n\r{}]/.test(csp)) problems.push('it contains a character the Caddyfile cannot quote');
  return problems;
}
