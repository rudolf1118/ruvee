import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { loginStartResponseSchema, reopenStartResponseSchema } from '@ruvee/contracts';
import * as opaque from '@serenity-kit/opaque';
import { pgToolsFromEnv } from '../src/admin/pg-tools.js';
import { signLogin } from './support/device-proof.js';
import {
  completeRestore,
  createBackup,
  knownMigrations,
  restoreBackup,
  type BackupResult,
} from '../src/admin/server-restore.js';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  type Harness,
} from './support/api-harness.js';
import { testBackupKey, type TestBackupKey } from './support/backup-keys.js';
import {
  reopenCompleteBody,
  reopenCookie,
  reopenMaterial,
  reopenWithKit,
  reopenWithPassword,
  unwrapReopenMaterial,
} from './support/reopen-client.js';
import {
  finishLogin,
  startLogin,
  SYNTHETIC_PASSWORD,
  syntheticAccount,
  type SyntheticAccount,
} from './support/synthetic-client.js';
import { createTempDatabase, migrate, type TempDatabase } from './support/temp-database.js';
import { pullAndVerify, VaultWriter } from './support/vault-writer.js';

/**
 * Restore acceptance tests R1 and R3 (backup-restore.md §6), with real dumps and age.
 * Synthetic data only.
 */

const MIGRATIONS = knownMigrations(new URL('../prisma/migrations', import.meta.url).pathname);
const tools = pgToolsFromEnv();
const config = {
  publicOrigin: 'http://127.0.0.1:3100',
  sessionCookieSecure: 'true' as const,
  extensionOrigins: '',
};
const NEW_PASSWORD = 'synthetic post-restore passphrase 5d1e';
const ORIGINAL_SETUP = process.env.OPAQUE_SERVER_SETUP_FILE ?? '';
/** The test server's URL: each harness points DATABASE_URL at its own database. */
const SERVER_URL = process.env.DATABASE_URL ?? '';

async function startLoginFor(h: Harness, account: SyntheticAccount, password: string) {
  const client = startLogin(password);
  const res = await h.post('/api/v1/auth/login/start', {
    username: account.username,
    startLoginRequest: client.startLoginRequest,
    platform: 'web',
    deviceId: account.deviceId,
  });
  return { client, res };
}

async function login(h: Harness, account: SyntheticAccount, password = SYNTHETIC_PASSWORD) {
  const { client, res } = await startLoginFor(h, account, password);
  const parsed = loginStartResponseSchema.parse(res.body);
  const finished = finishLogin(client.clientLoginState, parsed.loginResponse, password);
  if (!finished) return undefined;
  const done = await h.post('/api/v1/auth/login/finish', {
    loginId: parsed.loginId,
    finishLoginRequest: finished.finishLoginRequest,
    deviceProof: signLogin(account, parsed, finished.finishLoginRequest),
  });
  return done.status === 200 ? sessionCookie(done) : undefined;
}

/** Restores `backup` into a new database, completes the review, and serves it. */
async function restoredServer(backup: BackupResult, key: TestBackupKey) {
  const db = await createTempDatabase();
  const result = await restoreBackup({
    manifestPath: backup.manifestPath,
    identityPath: key.identityPath,
    trustedDigest: backup.digest,
    targetDatabaseUrl: db.url,
    tools,
    migrate,
    knownMigrations: MIGRATIONS,
  });
  if (!('removed' in result)) throw new Error('restore stopped');
  const ended = await completeRestore(db.url, {
    restoreId: result.restoreId,
    devicesReviewed: true,
    acceptRestoredCredentials: true,
  });
  if (ended.state !== 'reopening') throw new Error('expected reopening');
  return { db, code: ended.reopen.code };
}

/** The reopening of §3.13 on either path; returns the normal session cookie it ends with. */
async function reopen(
  h: Harness,
  account: SyntheticAccount,
  code: string,
  via: 'password' | 'recovery',
): Promise<string> {
  const res =
    via === 'password'
      ? (await reopenWithPassword(h, account, code)).finish
      : await reopenWithKit(h, account, code);
  if (res?.status !== 200) throw new Error(`reopening failed: ${String(res?.status)}`);
  const cookie = reopenCookie(res);
  const material = await reopenMaterial(h, cookie);
  const { body } = await reopenCompleteBody(
    h,
    account,
    cookie,
    material,
    unwrapReopenMaterial(account, material, {}),
    NEW_PASSWORD,
    via === 'recovery'
      ? {
          device: {
            key: account.crypto.generateDeviceKey(),
            id: reopenStartResponseSchema.parse(res.body).deviceId,
          },
        }
      : {},
  );
  const done = await h.post('/api/v1/reopen/complete', body, cookie);
  if (done.status !== 200) throw new Error(`complete failed: ${String(done.status)} ${done.text}`);
  return sessionCookie(done);
}

describe('R1: a backup taken during concurrent commits is a coherent, restorable snapshot', () => {
  let source: Harness;
  let restored: Harness | undefined;
  let key: TestBackupKey;
  let outDir: string;

  beforeAll(async () => {
    source = await startHarness();
    key = await testBackupKey();
    outDir = mkdtempSync(join(tmpdir(), 'ruvee-r1-it-'));
  }, 60_000);

  afterAll(async () => {
    await restored?.close();
    await source.close();
    rmSync(outDir, { recursive: true, force: true });
    key.drop();
  });

  it('restores a verifiable chain at a seq between the commits before and after the dump', async () => {
    const account = await syntheticAccount('synthetic-r1-owner');
    const cookie = await registerAccount(source, account);
    const writer = new VaultWriter(source, account, cookie);
    await writer.add();
    for (let i = 0; i < 5; i++) await writer.add({ v: 1, type: 'note', title: `Before ${i}` });

    // A client commits in a loop for as long as the backup runs.
    const state = { running: true };
    const loop = (async () => {
      let i = 0;
      while (state.running) await writer.add({ v: 1, type: 'note', title: `During ${i++}` });
    })();
    const seqAtStart = writer.seq;
    const backup = await createBackup({
      databaseUrl: source.db.url,
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
    });
    state.running = false;
    await loop;
    const seqAtEnd = writer.seq;
    expect(seqAtEnd).toBeGreaterThan(seqAtStart);

    const { db, code } = await restoredServer(backup, key);
    vi.resetModules();
    restored = await startHarness({ database: db });
    const fresh = await reopen(restored, account, code, 'password');
    const pulled = await pullAndVerify(restored, account, fresh);
    // One snapshot: some prefix of the history, chained and complete, never a half commit.
    expect(pulled.seq).toBeGreaterThanOrEqual(seqAtStart);
    expect(pulled.seq).toBeLessThanOrEqual(seqAtEnd);
    expect(pulled.digestMatches).toBe(true);
    expect(pulled.latest.size).toBe(pulled.seq - 1);
  }, 120_000);
});

describe('R3: missing or mismatched OPAQUE setup material fails safely', () => {
  let source: Harness;
  let account: SyntheticAccount;
  let key: TestBackupKey;
  let outDir: string;
  let db: TempDatabase;
  let code: string;
  let restored: Harness | undefined;

  beforeAll(async () => {
    process.env.DATABASE_URL = SERVER_URL;
    vi.resetModules();
    source = await startHarness();
    account = await syntheticAccount('synthetic-r3-owner');
    await registerAccount(source, account);
    key = await testBackupKey();
    outDir = mkdtempSync(join(tmpdir(), 'ruvee-r3-it-'));
    const backup = await createBackup({
      databaseUrl: source.db.url,
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
    });
    ({ db, code } = await restoredServer(backup, key));
  }, 120_000);

  afterAll(async () => {
    process.env.OPAQUE_SERVER_SETUP_FILE = ORIGINAL_SETUP;
    // The restored harness drops `db`; without one, drop it here.
    if (restored) await restored.close();
    else await (db as TempDatabase | undefined)?.drop();
    await (source as Harness | undefined)?.close();
    rmSync(outDir, { recursive: true, force: true });
    key.drop();
  });

  it('does not start without the setup file', async () => {
    process.env.OPAQUE_SERVER_SETUP_FILE = join(outDir, 'missing-opaque-setup');
    vi.resetModules();
    await expect(startHarness({ database: db })).rejects.toThrow(/OPAQUE|setup/i);
  });

  it('with another setup, no login succeeds; the code and the snapshot-time kit reopen and re-register', async () => {
    await opaque.ready;
    const otherSetup = join(outDir, 'other-opaque-setup');
    writeFileSync(otherSetup, `${opaque.server.createSetup()}\n`, { mode: 0o600 });
    process.env.OPAQUE_SERVER_SETUP_FILE = otherSetup;
    vi.resetModules();
    restored = await startHarness({ database: db });
    const h = restored;

    // Ordinary login is closed while reopening, whatever the setup.
    expect((await startLoginFor(h, account, SYNTHETIC_PASSWORD)).res.status).toBe(503);
    // The password path of the reopening fails: the client rejects the OPAQUE response made
    // with another setup, so the password is never accepted and no session is created.
    expect((await reopenWithPassword(h, account, code)).finish).toBeUndefined();
    // The Recovery Kit path does not use OPAQUE to authenticate: with the code and the
    // snapshot-time kit, the owner reopens and registers a new password under the new setup.
    await reopen(h, account, code, 'recovery');
    h.app.get((await import('../src/auth/throttle.service.js')).ThrottleService).clearIpWindows();
    expect(await login(h, account, NEW_PASSWORD)).toBeDefined();
    expect(await login(h, account)).toBeUndefined();
  }, 120_000);
});
