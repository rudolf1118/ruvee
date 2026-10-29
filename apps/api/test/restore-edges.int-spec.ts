import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { API_ERRORS, errorResponseSchema } from '@ruvee/contracts';
import type request from 'supertest';
import { pgToolsFromEnv } from '../src/admin/pg-tools.js';
import {
  completeRestore,
  createBackup,
  type BackupResult,
  knownMigrations,
  restoreBackup,
  reviewRestore,
  revokeDeviceInReview,
} from '../src/admin/server-restore.js';
import { startHarness, type Harness } from './support/api-harness.js';
import { startRegistration } from './support/synthetic-client.js';
import { testBackupKey, type TestBackupKey } from './support/backup-keys.js';
import { createTempDatabase, migrate, query, type TempDatabase } from './support/temp-database.js';

/**
 * Restore edge cases (backup-restore.md §3.5, §3.6): a snapshot taken before the account existed,
 * and a restore that stopped part-way. Synthetic data only.
 */

const MIGRATIONS = knownMigrations(new URL('../prisma/migrations', import.meta.url).pathname);
const tools = pgToolsFromEnv();
const config = {
  publicOrigin: 'http://127.0.0.1:3100',
  sessionCookieSecure: 'true' as const,
  extensionOrigins: '',
};

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

describe('restore edge cases (real database, real dumps)', () => {
  let source: Harness;
  let setupToken: string;
  let outDir: string;
  let key: TestBackupKey;
  let backup: BackupResult;
  const restoreArgs = (target: TempDatabase) => ({
    manifestPath: backup.manifestPath,
    identityPath: key.identityPath,
    trustedDigest: backup.digest,
    targetDatabaseUrl: target.operator.url,
    runtimeRole: target.runtime.name,
    tools,
    migrate,
    knownMigrations: MIGRATIONS,
  });
  const targets: TempDatabase[] = [];

  async function target() {
    const db = await createTempDatabase();
    targets.push(db);
    return db;
  }

  beforeAll(async () => {
    // A fresh installation with an unused setup token, as `ruvee-admin bootstrap-token` leaves it.
    source = await startHarness();
    setupToken = await source.bootstrapToken();
    outDir = mkdtempSync(join(tmpdir(), 'ruvee-restore-edges-it-'));
    key = await testBackupKey();
    backup = await createBackup({
      databaseUrl: source.db.operator.url,
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
    });
  }, 120_000);

  afterAll(async () => {
    // Before the source: these were created through its database's connection URL.
    for (const db of targets) await db.drop();
    await source.close();
    rmSync(outDir, { recursive: true, force: true });
    (key as TestBackupKey | undefined)?.drop();
  });

  it.each(['prepare', 'load', 'migrate'] as const)(
    'stays closed when the restore stops after %s, and cannot be completed',
    async (stopAfter) => {
      const db = await target();
      const result = await restoreBackup({
        ...restoreArgs(db),
        stopAfter,
      });
      expect(result).toMatchObject({ stoppedAfter: stopAfter });
      const [guard] = await query<{ state: string }>(
        db.url,
        'SELECT state FROM ruvee_control.restore_guard',
      );
      expect(guard).toEqual({ state: 'restoring' });
      await expect(
        completeRestore(db.operator.url, {
          restoreId: result.restoreId,
          devicesReviewed: true,
          acceptRestoredCredentials: true,
        }),
      ).rejects.toMatchObject({ stage: 'complete' });
      await expect(
        revokeDeviceInReview(db.operator.url, '00000000-0000-4000-8000-000000000000', 'lost'),
      ).rejects.toMatchObject({ stage: 'review' });
      // And a second restore refuses this half-restored database: it is not empty.
      await expect(
        restoreBackup({
          ...restoreArgs(db),
        }),
      ).rejects.toMatchObject({ stage: 'prepare' });
    },
    120_000,
  );

  it('does not reopen registration from a snapshot taken before the account existed', async () => {
    // The restored harness owns this database and drops it on close.
    const db = await createTempDatabase();
    const result = await restoreBackup({
      ...restoreArgs(db),
    });
    if (!('removed' in result)) throw new Error('restore stopped');
    expect(result.removed.setupTokens).toBe(1);
    expect(await query(db.url, 'SELECT id FROM bootstrap_tokens')).toEqual([]);
    expect((await reviewRestore(db.operator.url)).account).toBeNull();

    vi.resetModules();
    const restored = await startHarness({ database: db });
    try {
      const register = () =>
        restored.post('/api/v1/auth/register/start', {
          bootstrapToken: setupToken,
          username: 'synthetic-restore-late',
          registrationRequest: startRegistration().registrationRequest,
        });
      expectError(await register(), 'maintenance');
      await completeRestore(db.operator.url, {
        restoreId: result.restoreId,
        devicesReviewed: true,
        acceptRestoredCredentials: true,
      });
      // Open, but the snapshot's setup token is gone: setting up needs a new one from the host.
      expectError(await register(), 'bootstrap_failed');
    } finally {
      await restored.close();
    }
  }, 120_000);
});
