import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateX25519Identity, identityToRecipient } from 'age-encryption';

/**
 * A disposable, synthetic age X25519 key pair for one test file (D-29). It protects nothing
 * real: it lives in a fresh temporary directory, owner-only, and is removed by `drop()`. A real
 * owner's identity is never generated or stored by the tests or the tools.
 */
export interface TestBackupKey {
  readonly recipient: string;
  readonly identityPath: string;
  readonly dir: string;
  /** Another identity's file, for "wrong key" tests. */
  readonly otherIdentityPath: string;
  drop(): void;
}

export async function testBackupKey(): Promise<TestBackupKey> {
  const dir = mkdtempSync(join(tmpdir(), 'ruvee-age-test-'));
  const identity = await generateX25519Identity();
  const other = await generateX25519Identity();
  const identityPath = join(dir, 'synthetic-identity.txt');
  const otherIdentityPath = join(dir, 'other-identity.txt');
  writeFileSync(identityPath, `# synthetic test identity\n${identity}\n`, { mode: 0o600 });
  writeFileSync(otherIdentityPath, `${other}\n`, { mode: 0o600 });
  return {
    recipient: await identityToRecipient(identity),
    identityPath,
    otherIdentityPath,
    dir,
    drop: () => {
      rmSync(dir, { recursive: true, force: true });
    },
  };
}
