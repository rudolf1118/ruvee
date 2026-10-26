import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { uuidToBytes } from '@ruvee/crypto';
import {
  loginStartResponseSchema,
  recoveryMaterialResponseSchema,
  registerStartResponseSchema,
} from '@ruvee/contracts';
import * as opaque from '@serenity-kit/opaque';
import type request from 'supertest';
import { pgToolsFromEnv } from '../src/admin/pg-tools.js';
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
  finishLogin,
  finishRegistration,
  startLogin,
  startRegistration,
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
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));
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
  await completeRestore(db.url, {
    restoreId: result.restoreId,
    devicesReviewed: true,
    acceptRestoredCredentials: true,
  });
  return db;
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

    const db = await restoredServer(backup, key);
    vi.resetModules();
    restored = await startHarness({ database: db });
    const fresh = await login(restored, account);
    expect(fresh).toBeDefined();
    const pulled = await pullAndVerify(restored, account, fresh ?? '');
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
    db = await restoredServer(backup, key);
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

  it('with another setup, no login succeeds; the snapshot-time kit recovers and re-registers', async () => {
    await opaque.ready;
    const otherSetup = join(outDir, 'other-opaque-setup');
    writeFileSync(otherSetup, `${opaque.server.createSetup()}\n`, { mode: 0o600 });
    process.env.OPAQUE_SERVER_SETUP_FILE = otherSetup;
    vi.resetModules();
    restored = await startHarness({ database: db });
    const h = restored;

    // The server answers login/start as usual, but the client rejects its response: the
    // password is never accepted and no session is created.
    const { client, res } = await startLoginFor(h, account, SYNTHETIC_PASSWORD);
    expect(res.status, res.text).toBe(200);
    const parsed = loginStartResponseSchema.parse(res.body);
    expect(
      finishLogin(client.clientLoginState, parsed.loginResponse, SYNTHETIC_PASSWORD),
    ).toBeUndefined();
    expect(await login(h, account)).toBeUndefined();

    // Recovery with the Recovery Kit as of the snapshot, then a new password under the new setup.
    const { crypto } = account;
    const keys = crypto.deriveRecoveryKeys(crypto.parseRecoveryKey(account.recoveryKeyText));
    const started: request.Response = await h.post('/api/v1/recovery/start', {
      username: account.username,
      recoveryAuthKey: b64(keys.recoveryAuthKey),
      device: { id: crypto.generateUuid(), platform: 'web' },
    });
    expect(started.status, started.text).toBe(200);
    const recoveryCookie =
      (started.headers['set-cookie'] as unknown as string[])
        .find((c) => c.startsWith('__Host-ruvee_recovery='))
        ?.split(';')[0] ?? '';
    const material = recoveryMaterialResponseSchema.parse(
      (await h.get('/api/v1/recovery/material', recoveryCookie).expect(200)).body,
    );
    const accountId = uuidToBytes(account.accountId);
    const ak = crypto.unwrapAccountKeyForRecovery({
      recoveryWrapKey: keys.recoveryWrapKey,
      recoveryKeyId: unb64(material.recoveryKeyId),
      accountId,
      accountKeyId: unb64(material.akId),
      accountKeyEpoch: material.akEpoch,
      envelope: unb64(material.wrappedAkRecovery),
    });
    const keyset = crypto.openKeyset({
      accountKey: ak,
      accountKeyId: unb64(material.akId),
      accountId,
      keysetVersion: material.keysetVersion,
      envelope: unb64(material.keyset),
    });
    const reg = startRegistration(NEW_PASSWORD);
    const regStart = await h
      .post(
        '/api/v1/recovery/password/start',
        { registrationRequest: reg.registrationRequest },
        recoveryCookie,
      )
      .expect(200);
    const record = finishRegistration(
      reg.clientRegistrationState,
      registerStartResponseSchema.parse(regStart.body).registrationResponse,
      NEW_PASSWORD,
    );
    const saltPw = crypto.generatePasswordSalt();
    const auk = crypto.deriveAccountUnlockKey({
      password: NEW_PASSWORD,
      passwordSalt: saltPw,
      profile: 1,
      secretKey: keyset.secretKey,
      accountId,
    });
    const rotated = crypto.generateRecoveryKey();
    const rotatedKeys = crypto.deriveRecoveryKeys(rotated.recoveryKey);
    const done = await h.post(
      '/api/v1/recovery/complete',
      {
        registrationRecord: record,
        kdfProfile: 1,
        saltPw: b64(saltPw),
        wrappedAkPassword: b64(
          crypto.wrapAccountKey({
            accountUnlockKey: auk,
            accountKey: ak,
            accountId,
            accountKeyId: unb64(material.akId),
            accountKeyEpoch: material.akEpoch,
            profile: 1,
            passwordSalt: saltPw,
          }),
        ),
        recoveryKeyId: b64(rotated.recoveryKeyId),
        wrappedAkRecovery: b64(
          crypto.wrapAccountKeyForRecovery({
            recoveryWrapKey: rotatedKeys.recoveryWrapKey,
            recoveryKeyId: rotated.recoveryKeyId,
            accountId,
            accountKeyId: unb64(material.akId),
            accountKeyEpoch: material.akEpoch,
            accountKey: ak,
          }),
        ),
        recoveryVerifier: b64(crypto.recoveryVerifier(rotatedKeys.recoveryAuthKey)),
        expectedRowVersion: material.rowVersion,
      },
      recoveryCookie,
    );
    expect(done.status, done.text).toBe(200);
    // The new password now works under the new setup; the old one still does not.
    h.app.get((await import('../src/auth/throttle.service.js')).ThrottleService).clearIpWindows();
    expect(await login(h, account, NEW_PASSWORD)).toBeDefined();
    expect(await login(h, account)).toBeUndefined();
  }, 120_000);
});
