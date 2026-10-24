import type { NextConfig } from 'next';

/**
 * The development preview lives in `page.dev.tsx` files. Those only count as
 * routes when the `dev.tsx` extension is registered, which happens outside
 * production builds, so the preview and its fixtures never ship.
 */
const includeDevPreview = process.env.NODE_ENV !== 'production';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  // D-16: static export so production CSP can list build-time script hashes. `headers()`
  // is ignored for the export; Caddy / scripts/serve-export.mjs apply the production set.
  output: 'export',
  poweredByHeader: false,
  // Keeps the dev-only Next.js badge clear of the sidebar's bottom-left status box.
  devIndicators: { position: 'bottom-right' },
  pageExtensions: includeDevPreview ? ['dev.tsx', 'tsx', 'ts'] : ['tsx', 'ts'],
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
