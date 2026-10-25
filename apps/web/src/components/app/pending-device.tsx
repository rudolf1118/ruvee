'use client';

import type { UnlockedVault } from '@/vault/protocol';
import type { VaultClient } from '@/vault/client';
import { AuthCard } from './auth-layout';

/**
 * A device that has logged in but holds no keys yet. Under D-04 it needs the Secret Key from an
 * enrolled device (pairing) or the Recovery Kit; the password alone never unlocks it.
 */
export function PendingDeviceScreen({
  username,
}: {
  client: VaultClient;
  username: string;
  onEnrolled: (vault: UnlockedVault) => void;
}) {
  return (
    <AuthCard title="Add this device">
      <p className="text-body text-ink-muted">
        You are logged in as <strong className="text-ink">{username}</strong>, but this device
        can&apos;t open your vault yet. Your password alone is not enough: the keys have to come
        from a device that is already set up.
      </p>
      <p className="text-body text-ink-muted">
        Pairing with another device is not available in this build yet.
      </p>
    </AuthCard>
  );
}
