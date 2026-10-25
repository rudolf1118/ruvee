import type { NextConfig } from 'next';

/**
 * The development preview lives in `page.dev.tsx` files. Those only count as
 * routes when the `dev.tsx` extension is registered, which happens outside
 * production builds, so the preview and its fixtures never ship.
 */
const includeDevPreview = process.env.NODE_ENV !== 'production';

/**
 * Diagnostic routes (`page.diag.tsx`, the P2-04 CSP probes) only exist in the test-only build
 * from `scripts/build-diagnostics.mjs`. It exports to `out-diagnostics/` (a custom `distDir` names
 * the export directory with `output: 'export'`), so the ordinary `out/` never contains them.
 */
const includeDiagnostics = process.env.RUVEE_DIAGNOSTICS === '1';

const pageExtensions = [
  ...(includeDevPreview ? ['dev.tsx'] : []),
  ...(includeDiagnostics ? ['diag.tsx'] : []),
  'tsx',
  'ts',
];

/**
 * `next dev` only: the API is same-origin in deployment (Caddy, scripts/serve-export.mjs), so the
 * development server forwards /api/* to it. Rewrites do not exist in the static export.
 */
const devApiOrigin = process.env.RUVEE_DEV_API_ORIGIN ?? 'http://127.0.0.1:4000';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // D-16: static export so production CSP can list build-time script hashes. `headers()`
  // is ignored for the export; Caddy / scripts/serve-export.mjs apply the production set.
  output: 'export',
  ...(includeDiagnostics ? { distDir: 'out-diagnostics' } : {}),
  poweredByHeader: false,
  // Keeps the dev-only Next.js badge clear of the sidebar's bottom-left status box.
  devIndicators: { position: 'bottom-right' },
  pageExtensions,
  ...(includeDevPreview
    ? {
        rewrites: () =>
          Promise.resolve([{ source: '/api/:path*', destination: `${devApiOrigin}/api/:path*` }]),
      }
    : {}),
  headers() {
    // Phase 1 headers for `next dev` only. Production CSP cannot be applied here:
    // Fast Refresh needs `'unsafe-eval'`, and hashes are not known until after the export.
    return Promise.resolve([
      {
        source: '/:path*',
        headers: [
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'no-referrer' },
          { key: 'X-Frame-Options', value: 'DENY' },
        ],
      },
    ]);
  },
};

export default nextConfig;
