import { VaultApp } from '@/components/app/vault-app';

/** The whole vault UI is client-rendered; the static export carries no vault data. */
export default function HomePage() {
  return <VaultApp />;
}
