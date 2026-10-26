import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  sessionResponseSchema,
  tokenPairSchema,
} from '@ruvee/contracts';
import type request from 'supertest';
import { pgToolsFromEnv } from '../src/admin/pg-tools.js';
import {
  completeRestore,
  createBackup,
  type BackupResult,
  knownMigrations,
  restoreBackup,
  RestoreError,
  reviewRestore,
  revokeDeviceInReview,
} from '../src/admin/server-restore.js';
import { ThrottleService } from '../src/auth/throttle.service.js';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  type Harness,
} from './support/api-harness.js';
import {
  finishLogin,
  startLogin,
  startRegistration,
  SYNTHETIC_PASSWORD,
  syntheticAccount,
  type SyntheticAccount,
} from './support/synthetic-client.js';
import { testBackupKey, type TestBackupKey } from './support/backup-keys.js';
import {
  reopenCompleteBody,
  reopenCookie,
  reopenMaterial,
  reopenWithPassword,
  unwrapReopenMaterial,
} from './support/reopen-client.js';
import { createTempDatabase, migrate, query, type TempDatabase } from './support/temp-database.js';

/**
 * Server restore (backup-restore.md §3.5, §3.6, §3.6a) with real pg_dump and pg_restore (the
 * server's major version; see RUVEE_PG_TOOLS_PREFIX in src/admin/pg-tools.ts). Synthetic data
 * only: the source is this suite's own throwaway database.
 */

const NEW_PASSWORD = 'synthetic reopened passphrase 81d0';
const EXT = {
  Origin: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop',
  'X-Ruvee-Request': '1',
};
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

/** Every row of every table, in a stable order: "unchanged" means this hash is unchanged. */
async function fingerprint(url: string): Promise<string> {
  const tables = await query<{ table_name: string }>(
    url,
    `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' ORDER BY 1`,
  );
  const hash = createHash('sha256');
  for (const { table_name: t } of tables) {
    const rows = await query<{ r: string }>(
      url,
      `SELECT row_to_json(x)::text AS r FROM "${t}" x ORDER BY 1`,
    );
    hash.update(t);
    for (const { r } of rows) hash.update(r);
  }
  return hash.digest('hex');
}

const sha = (path: string) => createHash('sha256').update(readFileSync(path)).digest('hex');

describe('server restore into a maintenance-mode installation (real database, real dumps)', () => {
  let source: Harness;
  let account: SyntheticAccount;
  let owner: string;
  let extensionTokens: { refreshToken: string };
  let recoveryCookie: string;
  let otherDevice: { id: string; cookie: string };
  let pairingId: string;
  let outDir: string;
  let key: TestBackupKey;
  let backup: BackupResult;
  let sourceBefore: string;
  let target: TempDatabase;
  let restoreId: string;
  let reopenCode: string;
  let restored: Harness;
  let clearRestoredThrottle: () => void;

  async function login(h: Harness, deviceId?: string, password = SYNTHETIC_PASSWORD) {
    const client = startLogin(password);
    const start = await h.post('/api/v1/auth/login/start', {
      username: account.username,
      startLoginRequest: client.startLoginRequest,
      platform: 'web',
      ...(deviceId ? { deviceId } : {}),
    });
    if (start.status !== 200) return start;
    const parsed = loginStartResponseSchema.parse(start.body);
    const finished = finishLogin(client.clientLoginState, parsed.loginResponse, password);
    if (!finished) throw new Error('login rejected');
    return h.post('/api/v1/auth/login/finish', {
      loginId: parsed.loginId,
      finishLoginRequest: finished.finishLoginRequest,
    });
  }

  beforeAll(async () => {
    source = await startHarness();
    account = await syntheticAccount('synthetic-restore-source');
    owner = await registerAccount(source, account);

    // Live state at snapshot time: an extension token family, a recovery session, another
    // device's session and an open pairing.
    const client = startLogin(SYNTHETIC_PASSWORD);
    const start = loginStartResponseSchema.parse(
      (
        await source
          .http()
          .post('/api/v1/auth/login/start')
          .set(EXT)
          .send({
            username: account.username,
            startLoginRequest: client.startLoginRequest,
            platform: 'extension',
          })
          .expect(200)
      ).body,
    );
    const finished = finishLogin(client.clientLoginState, start.loginResponse);
    if (!finished) throw new Error('login rejected');
    extensionTokens = tokenPairSchema.parse(
      sessionResponseSchema.parse(
        (
          await source
            .http()
            .post('/api/v1/auth/login/finish')
            .set(EXT)
            .send({ loginId: start.loginId, finishLoginRequest: finished.finishLoginRequest })
            .expect(200)
        ).body,
      ).tokens,
    );
    const rk = account.crypto.deriveRecoveryKeys(
      account.crypto.parseRecoveryKey(account.recoveryKeyText),
    );
    const started = await source
      .post('/api/v1/recovery/start', {
        username: account.username,
        recoveryAuthKey: Buffer.from(rk.recoveryAuthKey).toString('base64url'),
        device: { id: account.crypto.generateUuid(), platform: 'web' },
      })
      .expect(200);
    recoveryCookie =
      (started.headers['set-cookie'] as unknown as string[])
        .find((c) => c.startsWith('__Host-ruvee_recovery='))
        ?.split(';')[0] ?? '';
    source.app.get(ThrottleService).clearIpWindows();
    const other = await login(source);
    otherDevice = {
      id: sessionResponseSchema.parse(other.body).device.id,
      cookie: sessionCookie(other),
    };
    pairingId = randomBytes(16).toString('base64url');
    await source.post('/api/v1/pairings', { pairingId }, owner).expect(201);

    outDir = mkdtempSync(join(tmpdir(), 'ruvee-restore-it-'));
    key = await testBackupKey();
    backup = await createBackup({
      databaseUrl: source.db.url,
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
    });
    sourceBefore = await fingerprint(source.db.url);

    target = await createTempDatabase();
    const result = await restoreBackup(restoreArgs(backup, target.url));
    if (!('removed' in result)) throw new Error('restore stopped');
    restoreId = result.restoreId;
    expect(result.provenance).toBe('trusted-digest');
    expect(result.removed.pairings).toBe(1);
    expect(result.removed.sessions).toBeGreaterThanOrEqual(4);

    vi.resetModules();
    restored = await startHarness({ database: target });
    // The restored app was built from freshly imported modules: its classes are new objects.
    const fresh = await import('../src/auth/throttle.service.js');
    clearRestoredThrottle = () => {
      restored.app.get(fresh.ThrottleService).clearIpWindows();
    };
  }, 180_000);

  afterAll(async () => {
    // Undefined when setup failed part-way; the real error is reported by beforeAll.
    await (restored as Harness | undefined)?.close();
    await (source as Harness | undefined)?.close();
    rmSync(outDir, { recursive: true, force: true });
    (key as TestBackupKey | undefined)?.drop();
  });

  function restoreArgs(b: BackupResult, targetDatabaseUrl: string) {
    return {
      manifestPath: b.manifestPath,
      identityPath: key.identityPath,
      trustedDigest: b.digest,
      targetDatabaseUrl,
      tools,
      migrate,
      knownMigrations: MIGRATIONS,
    };
  }

  beforeEach(() => {
    clearRestoredThrottle();
  });

  it('refuses to take a backup of anything but a synthetic database', async () => {
    const base = { outDir, tools, recipient: key.recipient, config };
    await expect(
      createBackup({ ...base, databaseUrl: source.db.url, syntheticTestOnly: false }),
    ).rejects.toThrow(/synthetic-test-only/);
    const other = new URL(source.db.url);
    other.pathname = '/ruvee';
    await expect(
      createBackup({ ...base, databaseUrl: other.toString(), syntheticTestOnly: true }),
    ).rejects.toThrow(/synthetic/);
  });

  it('never restores into a database that is not empty', async () => {
    await expect(restoreBackup(restoreArgs(backup, source.db.url))).rejects.toBeInstanceOf(
      RestoreError,
    );
    expect(await fingerprint(source.db.url)).toBe(sourceBefore);
  });

  it('serves nothing in review: not old cookies or tokens, not login, recovery, registration or pairing', async () => {
    const closed = [
      await restored.get('/api/v1/account/keys', owner),
      await restored.get('/api/v1/devices/current', otherDevice.cookie),
      await restored
        .http()
        .post('/api/v1/auth/refresh')
        .set(EXT)
        .send({ refreshToken: extensionTokens.refreshToken }),
      await restored.get('/api/v1/recovery/material', recoveryCookie),
      await restored.get(`/api/v1/pairings/${pairingId}`, owner),
      await restored.post('/api/v1/auth/login/start', {
        username: account.username,
        startLoginRequest: startLogin().startLoginRequest,
        platform: 'web',
      }),
      await restored.post('/api/v1/auth/register/start', {
        bootstrapToken: await restored.bootstrapToken(),
        username: 'synthetic-restore-intruder',
        registrationRequest: startRegistration().registrationRequest,
      }),
      await restored.post('/api/v1/recovery/start', {
        username: account.username,
        recoveryAuthKey: Buffer.alloc(32, 1).toString('base64url'),
        device: { id: account.crypto.generateUuid(), platform: 'web' },
      }),
    ];
    for (const res of closed) expectError(res, 'maintenance');
    await restored.http().get('/health/live').expect(200);
  });

  it('reviews the snapshot without secrets, revokes a device again, and ends the review only when told', async () => {
    const review = await reviewRestore(target.url);
    expect(review).toMatchObject({
      state: 'review',
      restoreId,
      account: { username: account.username },
    });
    expect(review.devices.map((d) => d.id)).toContain(otherDevice.id);
    expect(review.validAgain.keysetVersion).toBe(1);
    expect(JSON.stringify(review)).not.toMatch(/wrapped|verifier|secret_hash|token_hash/i);

    await revokeDeviceInReview(target.url, otherDevice.id, 'lost');
    await expect(
      completeRestore(target.url, {
        restoreId,
        devicesReviewed: true,
        acceptRestoredCredentials: false,
      }),
    ).rejects.toMatchObject({ stage: 'complete' });
    await expect(
      completeRestore(target.url, {
        restoreId: account.crypto.generateUuid(),
        devicesReviewed: true,
        acceptRestoredCredentials: true,
      }),
    ).rejects.toMatchObject({ stage: 'complete' });
    // Still closed.
    expectError(await restored.get('/api/v1/account/keys', owner), 'maintenance');

    const ended = await completeRestore(target.url, {
      restoreId,
      devicesReviewed: true,
      acceptRestoredCredentials: true,
    });
    if (ended.state !== 'reopening') throw new Error('expected reopening');
    expect(ended.reopen.code).toMatch(/^RC1-[A-Za-z0-9_-]{43}$/);
    reopenCode = ended.reopen.code;
    const events = await query<{ type: string }>(
      target.url,
      `SELECT type FROM security_events WHERE type IN ('server_restored', 'restore_review_completed', 'device_revoked') ORDER BY created_at`,
    );
    expect(events.map((e) => e.type)).toEqual([
      'server_restored',
      'device_revoked',
      'restore_review_completed',
    ]);
  });

  it('after the review, nothing restored works until the owner reopens, and nothing old after', async () => {
    const refresh = () =>
      restored
        .http()
        .post('/api/v1/auth/refresh')
        .set(EXT)
        .send({ refreshToken: extensionTokens.refreshToken });
    // Reopening: only /reopen/* answers, whatever the credentials.
    expectError(await restored.get('/api/v1/account/keys', owner), 'reopening');
    expectError(await refresh(), 'reopening');
    expectError(await restored.get('/api/v1/recovery/material', recoveryCookie), 'reopening');
    expectError(await login(restored, account.deviceId), 'reopening');
    // The device revoked in the review cannot reopen, even with the code and the password.
    expectError(
      (await reopenWithPassword(restored, account, reopenCode, { deviceId: otherDevice.id }))
        .finish as request.Response,
      'reopen_failed',
    );
    // The owner reopens from their own device and replaces the password and the kit.
    const started = await reopenWithPassword(restored, account, reopenCode);
    expect(started.finish?.status, started.finish?.text).toBe(200);
    const reopen = reopenCookie(started.finish as request.Response);
    const material = await reopenMaterial(restored, reopen);
    const { body } = await reopenCompleteBody(
      restored,
      account,
      reopen,
      material,
      unwrapReopenMaterial(account, material, {}),
      NEW_PASSWORD,
    );
    const done = await restored.post('/api/v1/reopen/complete', body, reopen);
    expect(done.status, done.text).toBe(200);

    expectError(await restored.get('/api/v1/account/keys', owner), 'unauthenticated');
    expectError(await refresh(), 'unauthenticated');
    expectError(await restored.get('/api/v1/recovery/material', recoveryCookie), 'unauthenticated');
    expectError(
      await restored.get('/api/v1/devices/current', otherDevice.cookie),
      'device_revoked',
    );
    expectError(await login(restored, otherDevice.id, NEW_PASSWORD), 'device_revoked');
    // The snapshot-time password no longer works; the new one does. The pairing is gone.
    await expect(login(restored, account.deviceId)).rejects.toThrow(/login rejected/);
    const fresh = await login(restored, account.deviceId, NEW_PASSWORD);
    expect(fresh.status, fresh.text).toBe(200);
    const cookie = sessionCookie(fresh);
    expectError(await restored.get(`/api/v1/pairings/${pairingId}`, cookie), 'not_found');
    const accountView = await restored.get('/api/v1/account', cookie).expect(200);
    expect(accountView.body).toMatchObject({ lastRestore: { restoreId } });
  });

  it('leaves the original installation and the backup unchanged', async () => {
    expect(await fingerprint(source.db.url)).toBe(sourceBefore);
    // The backup set is as written: the same digest, the same ciphertexts, owner-only files.
    expect(sha(backup.manifestPath)).toBe(backup.digest);
    expect(sha(backup.dumpPath)).toBe(backup.manifest.files.dump.sha256);
    expect(sha(backup.metaPath)).toBe(backup.manifest.files.meta.sha256);
    for (const path of [backup.manifestPath, backup.dumpPath, backup.metaPath])
      expect(statSync(path).mode & 0o777).toBe(0o600);
  });

  it('never carries the restore guard into a backup, so a restored server can be backed up and restored again', async () => {
    const second = await createBackup({
      databaseUrl: target.url,
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
      now: () => new Date(Date.now() + 1000),
    });
    const again = await createTempDatabase();
    try {
      const result = await restoreBackup(restoreArgs(second, again.url));
      expect('removed' in result).toBe(true);
      const state = await query<{ state: string }>(
        again.url,
        'SELECT state FROM ruvee_control.restore_guard',
      );
      expect(state).toEqual([{ state: 'review' }]);
    } finally {
      await again.drop();
    }
  });
});
