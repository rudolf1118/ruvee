import type { NextConfig } from 'next';

/**
 * The development preview lives in `page.dev.tsx` files. Those only count as
 * routes when the `dev.tsx` extension is registered, which happens outside
 * production builds, so the preview and its fixtures never ship.
 */
const includeDevPreview = process.env.NODE_ENV !== 'production';

const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // Keeps the dev-only Next.js badge clear of the sidebar's bottom-left status box.
  devIndicators: { position: 'bottom-right' },
  pageExtensions: includeDevPreview ? ['dev.tsx', 'tsx', 'ts'] : ['tsx', 'ts'],
  headers() {
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
