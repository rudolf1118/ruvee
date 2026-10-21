import type { Metadata } from 'next';
import { VaultShell } from '@/components/vault/vault-shell';
import { previewItems, previewVaults } from '@/preview/fixtures';
import { PreviewRibbon } from '@/preview/preview-ribbon';

// Development-only route: `.dev.tsx` pages are not registered in production builds.

export const metadata: Metadata = {
  title: 'Interface preview',
  robots: { index: false, follow: false },
};

export default function PreviewPage() {
  return (
    <VaultShell
      items={previewItems}
      vaults={previewVaults}
      initialSelectedId="i1"
      banner={<PreviewRibbon />}
    />
  );
}
