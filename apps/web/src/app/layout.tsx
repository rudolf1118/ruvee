import type { Metadata, Viewport } from 'next';
import type { ReactNode } from 'react';
import './fonts.css';
import './globals.css';

export const metadata: Metadata = {
  title: { default: 'Ruvee', template: '%s · Ruvee' },
  description: 'Ruvee password manager (development build).',
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  themeColor: '#f8f7f4',
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
