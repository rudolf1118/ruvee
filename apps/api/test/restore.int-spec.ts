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
import { createTempDatabase, migrate, query, type TempDatabase } from './support/temp-database.js';

/**
 * Server restore (backup-restore.md §3.5, §3.6, §3.6a) with real pg_dump and pg_restore (the
 * server's major version; see RUVEE_PG_TOOLS_PREFIX in src/admin/pg-tools.ts). Synthetic data
 * only: the source is this suite's own throwaway database.
 */

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
  let sidecarPath: string;
  let dumpPath: string;
  let sourceBefore: string;
  let target: TempDatabase;
  let restoreId: string;
  let restored: Harness;
  let clearRestoredThrottle: () => void;

  async function login(h: Harness, deviceId?: string) {
    const client = startLogin(SYNTHETIC_PASSWORD);
    const start = await h.post('/api/v1/auth/login/start', {
      username: account.username,
      startLoginRequest: client.startLoginRequest,
      platform: 'web',
      ...(deviceId ? { deviceId } : {}),
    });
    if (start.status !== 200) return start;
    const parsed = loginStartResponseSchema.parse(start.body);
    const finished = finishLogin(client.clientLoginState, parsed.loginResponse);
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
    const backup = await createBackup({
      databaseUrl: source.db.url,
      outDir,
      tools,
      syntheticTestOnly: true,
      config,
    });
    sidecarPath = backup.sidecarPath;
    dumpPath = backup.dumpPath;
    sourceBefore = await fingerprint(source.db.url);

    target = await createTempDatabase();
    const result = await restoreBackup({
      sidecarPath,
      targetDatabaseUrl: target.url,
      tools,
      migrate,
      knownMigrations: MIGRATIONS,
    });
    if (!('removed' in result)) throw new Error('restore stopped');
    restoreId = result.restoreId;
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
  });

  beforeEach(() => {
    clearRestoredThrottle();
  });

  it('refuses to take a backup of anything but a synthetic database, or without D-29', async () => {
    await expect(
      createBackup({ databaseUrl: source.db.url, outDir, tools, syntheticTestOnly: false, config }),
    ).rejects.toThrow(/D-29/);
    const other = new URL(source.db.url);
    other.pathname = '/ruvee';
    await expect(
      createBackup({
        databaseUrl: other.toString(),
        outDir,
        tools,
        syntheticTestOnly: true,
        config,
      }),
    ).rejects.toThrow(/synthetic/);
  });

  it('never restores into a database that is not empty', async () => {
    await expect(
      restoreBackup({
        sidecarPath,
        targetDatabaseUrl: source.db.url,
        tools,
        migrate,
        knownMigrations: MIGRATIONS,
      }),
    ).rejects.toBeInstanceOf(RestoreError);
    expect(await fingerprint(source.db.url)).toBe(sourceBefore);
  });

  it('refuses a dump that does not match its sidecar, or a newer schema, before creating anything', async () => {
    const empty = await createTempDatabase();
    try {
      const wrong = JSON.parse(readFileSync(sidecarPath, 'utf8')) as {
        dump: { sha256: string };
        schema: { migration: string };
      };
      const bad = join(outDir, 'tampered.json');
      for (const variant of [
        { ...wrong, dump: { ...wrong.dump, sha256: '0'.repeat(64) } },
        { ...wrong, schema: { migration: '29991231000000_from_the_future' } },
      ]) {
        rmSync(bad, { force: true });
        await import('node:fs').then((fs) => {
          fs.writeFileSync(bad, JSON.stringify(variant));
        });
        await expect(
          restoreBackup({
            sidecarPath: bad,
            targetDatabaseUrl: empty.url,
            tools,
            migrate,
            knownMigrations: MIGRATIONS,
          }),
        ).rejects.toMatchObject({ stage: 'verify' });
      }
      const tables = await query<{ n: string }>(
        empty.url,
        `SELECT count(*) AS n FROM pg_tables WHERE schemaname = 'public'`,
      );
      expect(tables[0]?.n).toBe('0');
    } finally {
      await empty.drop();
    }
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

  it('reviews the snapshot without secrets, revokes a device again, and opens only when told', async () => {
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

    await completeRestore(target.url, {
      restoreId,
      devicesReviewed: true,
      acceptRestoredCredentials: true,
    });
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

  it('after the review, no restored session, token, recovery session or pairing works', async () => {
    expectError(await restored.get('/api/v1/account/keys', owner), 'unauthenticated');
    expectError(
      await restored
        .http()
        .post('/api/v1/auth/refresh')
        .set(EXT)
        .send({ refreshToken: extensionTokens.refreshToken }),
      'unauthenticated',
    );
    expectError(await restored.get('/api/v1/recovery/material', recoveryCookie), 'unauthenticated');
    // The device revoked in the review stays out, even with the snapshot-time password.
    expectError(
      await restored.get('/api/v1/devices/current', otherDevice.cookie),
      'device_revoked',
    );
    expectError(await login(restored, otherDevice.id), 'device_revoked');
    // The owner signs in again with the password as of the snapshot; the pairing is gone.
    const fresh = await login(restored, account.deviceId);
    expect(fresh.status, fresh.text).toBe(200);
    const cookie = sessionCookie(fresh);
    expectError(await restored.get(`/api/v1/pairings/${pairingId}`, cookie), 'not_found');
    const accountView = await restored.get('/api/v1/account', cookie).expect(200);
    expect(accountView.body).toMatchObject({ lastRestore: { restoreId } });
  });

  it('leaves the original installation and the backup unchanged', async () => {
    expect(await fingerprint(source.db.url)).toBe(sourceBefore);
    const sidecar = JSON.parse(readFileSync(sidecarPath, 'utf8')) as { dump: { sha256: string } };
    expect(sha(dumpPath)).toBe(sidecar.dump.sha256);
    // Readable by the owner only, both of them.
    expect(statSync(dumpPath).mode & 0o777).toBe(0o600);
    expect(statSync(sidecarPath).mode & 0o777).toBe(0o600);
  });

  it('never carries the restore guard into a backup, so a restored server can be backed up and restored again', async () => {
    const second = await createBackup({
      databaseUrl: target.url,
      outDir,
      tools,
      syntheticTestOnly: true,
      config,
      now: () => new Date(Date.now() + 1000),
    });
    const again = await createTempDatabase();
    try {
      const result = await restoreBackup({
        sidecarPath: second.sidecarPath,
        targetDatabaseUrl: again.url,
        tools,
        migrate,
        knownMigrations: MIGRATIONS,
      });
      expect('removed' in result).toBe(true);
      const state = await query<{ state: string }>(
        again.url,
        'SELECT state FROM ruvee_restore_guard',
      );
      expect(state).toEqual([{ state: 'review' }]);
    } finally {
      await again.drop();
    }
  });
});
