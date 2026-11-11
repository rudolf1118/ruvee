'use client';

import type { UnlockedVault } from '@ruvee/vault';
import type { VaultClient } from '@/vault/client';
import { JoinWithCode } from './pairing';

/**
 * A device that has logged in but holds no keys yet. Under D-04 it needs the Secret Key from an
 * enrolled device (pairing) or the Recovery Kit; the password alone never unlocks it.
 */
export function PendingDeviceScreen(props: {
  client: VaultClient;
  username: string;
  onEnrolled: (vault: UnlockedVault) => void;
}) {
  return <JoinWithCode {...props} />;
}
