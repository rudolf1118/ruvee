import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  recoveryCompleteRequestSchema,
  reopenStartResponseSchema,
  syncChangesResponseSchema,
} from '@ruvee/contracts';
import type request from 'supertest';
import { pgToolsFromEnv } from '../src/admin/pg-tools.js';
import {
  completeRestore,
  createBackup,
  issueReopenCode,
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
  startRegistration,
  SYNTHETIC_PASSWORD,
  syntheticAccount,
  type SyntheticAccount,
} from './support/synthetic-client.js';
import { createTempDatabase, migrate, query } from './support/temp-database.js';
import { VaultWriter } from './support/vault-writer.js';

/**
 * Reopening a restored installation (backup-restore.md §3.13, D-30 option B) with real dumps,
 * real OPAQUE and real envelopes. Each path gets its own restore of the same backup.
 * Synthetic data only.
 */

const MIGRATIONS = knownMigrations(new URL('../prisma/migrations', import.meta.url).pathname);
const tools = pgToolsFromEnv();
const config = {
  publicOrigin: 'http://127.0.0.1:3100',
  sessionCookieSecure: 'true' as const,
  extensionOrigins: '',
};
const SERVER_URL = process.env.DATABASE_URL ?? '';
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const NEW_PASSWORD = 'synthetic reopened passphrase 3c7a';

function expectError(res: request.Response | undefined, code: keyof typeof API_ERRORS) {
  if (!res) throw new Error('no response');
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

async function login(h: Harness, account: SyntheticAccount, password = SYNTHETIC_PASSWORD) {
  const client = startLogin(password);
  const start = await h.post('/api/v1/auth/login/start', {
    username: account.username,
    startLoginRequest: client.startLoginRequest,
    platform: 'web',
    deviceId: account.deviceId,
  });
  if (start.status !== 200) return start;
  const parsed = loginStartResponseSchema.parse(start.body);
  const finished = finishLogin(client.clientLoginState, parsed.loginResponse, password);
  if (!finished) return undefined;
  return h.post('/api/v1/auth/login/finish', {
    loginId: parsed.loginId,
    finishLoginRequest: finished.finishLoginRequest,
  });
}

const codes = (url: string) =>
  query<{ failed_attempts: number; revoked: boolean; consumed: boolean }>(
    url,
    `SELECT failed_attempts, revoked_at IS NOT NULL AS revoked, consumed_at IS NOT NULL AS consumed
     FROM ruvee_control.reopen_codes ORDER BY created_at`,
  );
const guardState = async (url: string) =>
  (await query<{ state: string }>(url, 'SELECT state FROM ruvee_control.restore_guard'))[0]?.state;

describe('reopening a restored installation (real database, real dumps)', () => {
  let source: Harness;
  let account: SyntheticAccount;
  let ownerCookie: string;
  let itemIds: string[];
  let key: TestBackupKey;
  let outDir: string;
  let backup: BackupResult;

  /** A new restore of `backup`, reviewed: `reopening`, with its first code. */
  async function restoredAndReviewed() {
    // On the test server itself: each harness points DATABASE_URL at its own database.
    process.env.DATABASE_URL = SERVER_URL;
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
    const done = await completeRestore(db.url, {
      restoreId: result.restoreId,
      devicesReviewed: true,
      acceptRestoredCredentials: true,
    });
    if (done.state !== 'reopening') throw new Error('expected reopening');
    vi.resetModules();
    const h = await startHarness({ database: db });
    const throttle = (await import('../src/auth/throttle.service.js')).ThrottleService;
    return {
      db,
      h,
      restoreId: result.restoreId,
      code: done.reopen.code,
      clearThrottle: () => {
        h.app.get(throttle).clearIpWindows();
      },
    };
  }

  beforeAll(async () => {
    process.env.DATABASE_URL = SERVER_URL;
    vi.resetModules();
    source = await startHarness();
    account = await syntheticAccount('synthetic-reopen-owner');
    ownerCookie = await registerAccount(source, account);
    const writer = new VaultWriter(source, account, ownerCookie);
    await writer.add();
    itemIds = [
      (await writer.add({ v: 1, type: 'note', title: 'Kept 1' })) ?? '',
      (await writer.add({ v: 1, type: 'note', title: 'Kept 2' })) ?? '',
    ];
    key = await testBackupKey();
    outDir = mkdtempSync(join(tmpdir(), 'ruvee-reopen-it-'));
    backup = await createBackup({
      databaseUrl: source.db.url,
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
    });
  }, 120_000);

  afterAll(async () => {
    await (source as Harness | undefined)?.close();
    rmSync(outDir, { recursive: true, force: true });
    (key as TestBackupKey | undefined)?.drop();
  });

  describe('password path (a device active in the snapshot, with its own Secret Key)', () => {
    let r: Awaited<ReturnType<typeof restoredAndReviewed>>;

    beforeAll(async () => {
      r = await restoredAndReviewed();
    }, 120_000);
    afterAll(async () => {
      await (r as typeof r | undefined)?.h.close();
    });
    beforeEach(() => {
      r.clearThrottle();
    });

    it('keeps everything but /reopen/* closed, and old credentials alone open nothing', async () => {
      expect(await guardState(r.db.url)).toBe('reopening');
      expectError(await r.h.get('/api/v1/account/keys', ownerCookie), 'reopening');
      expectError(await r.h.get('/api/v1/sync/changes?since=0', ownerCookie), 'reopening');
      expectError(await login(r.h, account), 'reopening');
      expectError(
        await r.h.post('/api/v1/recovery/start', {
          username: account.username,
          recoveryAuthKey: Buffer.alloc(32, 1).toString('base64url'),
          device: { id: account.crypto.generateUuid(), platform: 'web' },
        }),
        'reopening',
      );
      expectError(
        await r.h.post('/api/v1/auth/register/start', {
          bootstrapToken: await r.h.bootstrapToken(),
          username: 'synthetic-intruder',
          registrationRequest: startRegistration().registrationRequest,
        }),
        'reopening',
      );
      expectError(
        await r.h.post(
          '/api/v1/pairings',
          { pairingId: randomBytes(16).toString('base64url') },
          ownerCookie,
        ),
        'reopening',
      );
      await r.h.http().get('/health/live').expect(200);
      // The snapshot-time password without the code: refused at the door.
      const noCode = await reopenWithPassword(r.h, account, `RC1-${'A'.repeat(43)}`);
      expectError(noCode.start, 'reopen_failed');
      expectError(
        await r.h.post('/api/v1/reopen/login/start', {
          username: account.username,
          startLoginRequest: startLogin().startLoginRequest,
          deviceId: account.deviceId,
        }),
        'invalid_request',
      );
    });

    it('does not let the code authenticate alone, or another account, device or password use it', async () => {
      expectError(await r.h.get('/api/v1/reopen/material'), 'unauthenticated');
      // Right code, wrong password: refused, counted, and the code is not consumed.
      const wrong = await reopenWithPassword(r.h, account, r.code, {
        password: 'synthetic wrong guess 9',
      });
      expect(wrong.finish).toBeUndefined();
      // The client rejected OPAQUE, so the server only saw the start; finish with garbage:
      const parsed = loginStartResponseSchema.parse(wrong.start.body);
      expectError(
        await r.h.post('/api/v1/reopen/login/finish', {
          loginId: parsed.loginId,
          finishLoginRequest: Buffer.alloc(64, 7).toString('base64url'),
        }),
        'reopen_failed',
      );
      // An unknown device: no Secret Key, no password path.
      expectError(
        (
          await reopenWithPassword(r.h, account, r.code, {
            deviceId: account.crypto.generateUuid(),
          })
        ).finish,
        'reopen_failed',
      );
      // Another username.
      expectError(
        (await reopenWithPassword(r.h, account, r.code, { username: 'someone-else' })).start,
        'reopen_failed',
      );
      // Three failures, all with the usable code. The wrong code of the previous test is not
      // among them: it proved nothing about this code (review R11).
      expect(await codes(r.db.url)).toEqual([
        { failed_attempts: 3, revoked: false, consumed: false },
      ]);
      expect(await guardState(r.db.url)).toBe('reopening');
    });

    it('revokes a code after five failed credentials with it, and the host issues a new one', async () => {
      for (let i = 0; i < 2; i++)
        // The right code with another username: the fourth and fifth failures on this code.
        expectError(
          (await reopenWithPassword(r.h, account, r.code, { username: 'someone-else' })).start,
          'reopen_failed',
        );
      expect(await codes(r.db.url)).toEqual([
        { failed_attempts: 5, revoked: true, consumed: false },
      ]);
      expectError((await reopenWithPassword(r.h, account, r.code)).start, 'reopen_failed');
      const fresh = await issueReopenCode(r.db.url, { restoreId: r.restoreId });
      r.code = fresh.code;
      expect(await guardState(r.db.url)).toBe('reopening');
    });

    it('fails an expired code, and keeps a lost reopen session recoverable only from the host', async () => {
      await query(
        r.db.url,
        `UPDATE ruvee_control.reopen_codes SET expires_at = now() - interval '1 second' WHERE revoked_at IS NULL`,
      );
      expectError((await reopenWithPassword(r.h, account, r.code)).start, 'reopen_failed');
      r.code = (await issueReopenCode(r.db.url, { restoreId: r.restoreId })).code;
      // A reopening that starts, then is abandoned (tab closed): the session is lost.
      const started = await reopenWithPassword(r.h, account, r.code);
      expect(started.finish?.status, started.finish?.text).toBe(200);
      const lost = reopenCookie(started.finish as request.Response);
      expect(await codes(r.db.url)).toContainEqual({
        failed_attempts: 0,
        revoked: false,
        consumed: true,
      });
      // Replayed code: consumed.
      expectError((await reopenWithPassword(r.h, account, r.code)).start, 'reopen_failed');
      // Still closed, the restricted session reaches nothing else.
      expectError(await r.h.get('/api/v1/account/keys', lost), 'reopening');
      expect(await guardState(r.db.url)).toBe('reopening');
      // The host retry ends that session and issues a new code.
      r.code = (await issueReopenCode(r.db.url, { restoreId: r.restoreId })).code;
      expectError(await r.h.get('/api/v1/reopen/material', lost), 'unauthenticated');
    });

    it('serves only the reset workflow to a reopen session, and refuses an incomplete completion', async () => {
      const started = await reopenWithPassword(r.h, account, r.code);
      const cookie = reopenCookie(started.finish as request.Response);
      // Not a normal cookie, not a bearer token.
      expect(started.finish?.headers['set-cookie']?.toString()).not.toMatch(/ruvee_session=/);
      const token = cookie.slice(cookie.indexOf('=') + 1);
      expectError(
        await r.h.http().get('/api/v1/reopen/material').set('Authorization', `Bearer ${token}`),
        'unauthenticated',
      );
      for (const path of [
        '/api/v1/vault',
        '/api/v1/devices',
        '/api/v1/account',
        '/api/v1/sync/changes?since=0',
      ])
        expectError(await r.h.get(path, cookie), 'reopening');
      expectError(
        await r.h.post(
          '/api/v1/recovery/password/start',
          { registrationRequest: startRegistration().registrationRequest },
          cookie,
        ),
        'reopening',
      );
      const material = await reopenMaterial(r.h, cookie);
      expect(material.via).toBe('password');
      expect(material.wrappedAkRecovery).toBeUndefined();
      const unwrapped = unwrapReopenMaterial(account, material, {});
      // Keeping the old Recovery Kit: refused; nothing changed.
      const kept = await reopenCompleteBody(
        r.h,
        account,
        cookie,
        material,
        unwrapped,
        NEW_PASSWORD,
        { keepKit: true },
      );
      expectError(await r.h.post('/api/v1/reopen/complete', kept.body, cookie), 'invalid_request');
      // A stale row version: refused; nothing changed.
      const stale = await reopenCompleteBody(
        r.h,
        account,
        cookie,
        material,
        unwrapped,
        NEW_PASSWORD,
        { rowVersion: material.rowVersion + 3 },
      );
      expectError(
        await r.h.post('/api/v1/reopen/complete', stale.body, cookie),
        'row_version_conflict',
      );
      expect(await guardState(r.db.url)).toBe('reopening');
      // The old password still works for reopening only (a new password was never installed).
      r.code = (await issueReopenCode(r.db.url, { restoreId: r.restoreId })).code;
      expectError(await r.h.get('/api/v1/reopen/material', cookie), 'unauthenticated');
    });

    it('completes once: new password and kit together, then everything old fails and data is intact', async () => {
      const started = await reopenWithPassword(r.h, account, r.code);
      const cookie = reopenCookie(started.finish as request.Response);
      const material = await reopenMaterial(r.h, cookie);
      const { body } = await reopenCompleteBody(
        r.h,
        account,
        cookie,
        material,
        unwrapReopenMaterial(account, material, {}),
        NEW_PASSWORD,
      );
      const done = await r.h.post('/api/v1/reopen/complete', body, cookie);
      expect(done.status, done.text).toBe(200);
      const fresh = sessionCookie(done);
      expect(String(done.headers['set-cookie'])).toMatch(/ruvee_reopen=;/);
      expect(await guardState(r.db.url)).toBe('open');
      expect(await codes(r.db.url)).not.toContainEqual(expect.objectContaining({ revoked: false }));

      // The new session works; the vault is exactly as restored.
      const pulled = syncChangesResponseSchema.parse(
        (await r.h.get('/api/v1/sync/changes?since=0', fresh).expect(200)).body,
      );
      expect(pulled.items.map((i) => i.itemId).sort()).toEqual([...itemIds].sort());
      // Old: the restored cookie, the reopen session, the code, the password, the kit.
      expectError(await r.h.get('/api/v1/account', ownerCookie), 'unauthenticated');
      expectError(await r.h.post('/api/v1/reopen/complete', body, cookie), 'unauthenticated');
      expectError((await reopenWithPassword(r.h, account, r.code)).start, 'reopen_failed');
      expect(await login(r.h, account)).toBeUndefined();
      const keys = account.crypto.deriveRecoveryKeys(
        account.crypto.parseRecoveryKey(account.recoveryKeyText),
      );
      expectError(
        await r.h.post('/api/v1/recovery/start', {
          username: account.username,
          recoveryAuthKey: Buffer.from(keys.recoveryAuthKey).toString('base64url'),
          device: { id: account.crypto.generateUuid(), platform: 'web' },
        }),
        'recovery_failed',
      );
      const again = await login(r.h, account, NEW_PASSWORD);
      expect(again?.status).toBe(200);
      const events = await query<{ type: string }>(
        r.db.url,
        `SELECT type FROM security_events WHERE type::text LIKE 're%open%' OR type = 'restore_review_completed' ORDER BY created_at`,
      );
      expect(events.map((e) => e.type)).toEqual(
        expect.arrayContaining([
          'restore_review_completed',
          'reopen_code_issued',
          'reopen_started',
          'reopen_failed',
          'restore_reopened',
        ]),
      );
    });
  });

  describe('Recovery Kit path (a browser with no keys)', () => {
    let r: Awaited<ReturnType<typeof restoredAndReviewed>>;

    beforeAll(async () => {
      r = await restoredAndReviewed();
    }, 120_000);
    afterAll(async () => {
      await (r as typeof r | undefined)?.h.close();
    });
    beforeEach(() => {
      r.clearThrottle();
    });

    it('needs the code and the snapshot-time kit; a wrong kit counts and consumes nothing', async () => {
      const wrongKit = account.crypto.formatRecoveryKey(
        account.crypto.generateRecoveryKey().recoveryKey,
      );
      expectError(
        await reopenWithKit(r.h, account, r.code, { recoveryKeyText: wrongKit }),
        'reopen_failed',
      );
      expectError(await reopenWithKit(r.h, account, `RC1-${'B'.repeat(43)}`), 'reopen_failed');
      // Only the wrong kit, presented with the right code, counts on it.
      expect(await codes(r.db.url)).toEqual([
        { failed_attempts: 1, revoked: false, consumed: false },
      ]);
    });

    it('lets exactly one of two concurrent submissions of the code through', async () => {
      const results = await Promise.all([
        reopenWithKit(r.h, account, r.code),
        reopenWithKit(r.h, account, r.code),
      ]);
      expect(results.map((x) => x.status).sort()).toEqual([200, 401]);
      const sessions = await query<{ n: string }>(
        r.db.url,
        `SELECT count(*) AS n FROM sessions WHERE kind = 'reopen'`,
      );
      expect(sessions[0]?.n).toBe('1');
      // The losing device row stays pending and can do nothing.
      expect(await guardState(r.db.url)).toBe('reopening');
      r.code = (await issueReopenCode(r.db.url, { restoreId: r.restoreId })).code;
    });

    it('opens with a new password and kit; the new device is enrolled by recovery', async () => {
      const deviceId = account.crypto.generateUuid();
      const started = await reopenWithKit(r.h, account, r.code, { deviceId });
      expect(started.status, started.text).toBe(200);
      const cookie = reopenCookie(started);
      const material = await reopenMaterial(r.h, cookie);
      expect(material.via).toBe('recovery');
      expect(material.password).toBeUndefined();
      // A new browser: it enrolls a new device key with the completion (device-proof.md §8).
      const deviceKey = account.crypto.generateDeviceKey();
      const { body, newKitText } = await reopenCompleteBody(
        r.h,
        account,
        cookie,
        material,
        unwrapReopenMaterial(account, material, {}),
        NEW_PASSWORD,
        { device: { key: deviceKey, id: deviceId } },
      );
      const done = await r.h.post('/api/v1/reopen/complete', body, cookie);
      expect(done.status, done.text).toBe(200);
      expect(await guardState(r.db.url)).toBe('open');
      const [device] = await query<{ status: string; enrolled_via: string }>(
        r.db.url,
        'SELECT status, enrolled_via FROM devices WHERE id = $1',
        [deviceId],
      );
      expect(device).toEqual({ status: 'active', enrolled_via: 'recovery' });
      // D-31 §8: the new browser's own key is the one enrolled; AK's verification key and the
      // snapshot device's key are unchanged (the old device's private key was never needed).
      const keysAfter = await query<{ id: string; public_key: Buffer | null }>(
        r.db.url,
        'SELECT id, public_key FROM devices WHERE id = ANY($1::uuid[])',
        [[deviceId, account.deviceId]],
      );
      const keyOf = (id: string) =>
        b64(keysAfter.find((d) => d.id === id)?.public_key ?? new Uint8Array());
      expect(keyOf(deviceId)).toBe(b64(deviceKey.publicKey));
      expect(keyOf(account.deviceId)).toBe(b64(account.deviceKey.publicKey));
      const [avpk] = await query<{ ak_verify_key: Buffer }>(
        r.db.url,
        'SELECT ak_verify_key FROM account_keys',
      );
      expect(b64(avpk?.ak_verify_key ?? new Uint8Array())).toBe(b64(account.akVerifyKey));
      // The old kit is retired, the new one recovers.
      const kit = (text: string) =>
        account.crypto.deriveRecoveryKeys(account.crypto.parseRecoveryKey(text)).recoveryAuthKey;
      const recover = (rak: Uint8Array) =>
        r.h.post('/api/v1/recovery/start', {
          username: account.username,
          recoveryAuthKey: Buffer.from(rak).toString('base64url'),
          device: { id: account.crypto.generateUuid(), platform: 'web' },
        });
      expectError(await recover(kit(account.recoveryKeyText)), 'recovery_failed');
      expect((await recover(kit(newKitText))).status).toBe(200);
    });
  });

  describe('REVIEW R11 (regression): wrong codes cannot keep the installation closed', () => {
    let r: Awaited<ReturnType<typeof restoredAndReviewed>>;

    beforeAll(async () => {
      r = await restoredAndReviewed();
    }, 120_000);
    afterAll(async () => {
      await (r as typeof r | undefined)?.h.close();
    });
    beforeEach(() => {
      r.clearThrottle();
    });

    const wrongCode = () => `RC1-${randomBytes(32).toString('base64url')}`;

    it('never charges the usable code for wrong ones; one address is limited instead', async () => {
      // Twenty wrong codes from one address, the review's reproduction (anyone who reaches the
      // API). Twenty stay within the general 20-a-minute window, so every 429 here comes from
      // the wrong-code limit; under the old code, the fifth one revoked the owner's code.
      const statuses: number[] = [];
      for (let i = 0; i < 20; i++)
        statuses.push((await reopenWithPassword(r.h, account, wrongCode())).start.status);
      expect(statuses.slice(0, 10)).toEqual(Array(10).fill(401));
      expect(statuses.slice(10)).toEqual(Array(10).fill(429));
      expect(await codes(r.db.url)).toEqual([
        { failed_attempts: 0, revoked: false, consumed: false },
      ]);
      // A malformed code is refused by the contract before anything is looked up.
      expectError((await reopenWithPassword(r.h, account, 'RC1-short')).start, 'invalid_request');
      // From another address (a restart forgets the windows too), the owner still reopens.
      r.clearThrottle();
      const owner = await reopenWithPassword(r.h, account, r.code);
      expect(owner.finish?.status, owner.finish?.text).toBe(200);
      r.code = (await issueReopenCode(r.db.url, { restoreId: r.restoreId })).code;
    });

    it('charges the recovery budget only once the code is right', async () => {
      // Eight wrong codes on the Recovery Kit path, from as many addresses: more than the
      // owner's five recovery attempts an hour, and none of them counts.
      for (let i = 0; i < 8; i++) {
        r.clearThrottle();
        expectError(await reopenWithKit(r.h, account, wrongCode()), 'reopen_failed');
      }
      r.clearThrottle();
      const owner = await reopenWithKit(r.h, account, r.code);
      expect(owner.status, owner.text).toBe(200);
      expect(await codes(r.db.url)).toContainEqual({
        failed_attempts: 0,
        revoked: false,
        consumed: true,
      });
    });

    it('records why each attempt failed, without the code', async () => {
      const events = await query<{ reason: string | null; n: string }>(
        r.db.url,
        `SELECT details->>'reason' AS reason, count(*) AS n FROM security_events
         WHERE type = 'reopen_failed' GROUP BY 1 ORDER BY 1`,
      );
      expect(events.map((e) => e.reason)).toContain('code');
      const text = JSON.stringify(
        await query(r.db.url, `SELECT details FROM security_events WHERE type = 'reopen_failed'`),
      );
      expect(text).not.toContain('RC1-');
    });
  });

  describe('REVIEW R13 (regression): a host revocation and a completion never both win', () => {
    let r: Awaited<ReturnType<typeof restoredAndReviewed>>;

    beforeEach(async () => {
      r = await restoredAndReviewed();
    }, 120_000);
    afterEach(async () => {
      await (r as typeof r | undefined)?.h.close();
    });

    /** A reopen session authenticated, and its completion body prepared, before anything else. */
    async function readyToComplete() {
      const started = await reopenWithKit(r.h, account, r.code);
      expect(started.status, started.text).toBe(200);
      const cookie = reopenCookie(started);
      const material = await reopenMaterial(r.h, cookie);
      const { body } = await reopenCompleteBody(
        r.h,
        account,
        cookie,
        material,
        unwrapReopenMaterial(account, material, {}),
        NEW_PASSWORD,
        {
          device: {
            key: account.crypto.generateDeviceKey(),
            id: reopenStartResponseSchema.parse(started.body).deviceId,
          },
        },
      );
      const { SessionService } = await import('../src/sessions/session.service.js');
      const { ReopenService } = await import('../src/reopen/reopen.service.js');
      const session = await r.h.app
        .get(SessionService)
        .authenticateReopen(cookie.slice(cookie.indexOf('=') + 1));
      const complete = () =>
        r.h.app.get(ReopenService).complete(session, recoveryCompleteRequestSchema.parse(body), {
          ip: undefined,
          userAgent: undefined,
        });
      return { complete };
    }

    it('refuses a completion whose session the host ended after it was authenticated', async () => {
      const { complete } = await readyToComplete();
      // The request is past authentication; then the host issues a new code (`restore-reopen-code`).
      await issueReopenCode(r.db.url, { restoreId: r.restoreId });
      await expect(complete()).rejects.toMatchObject({ code: 'reopen_failed' });
      expect(await guardState(r.db.url)).toBe('reopening');
      // The consumed code is revoked too, so nothing links that session to the restore any more.
      expect((await codes(r.db.url)).filter((c) => !c.revoked)).toHaveLength(1);
    });

    it('serializes a completion and a new code: exactly one of them takes effect', async () => {
      const { complete } = await readyToComplete();
      const [completed, issued] = await Promise.allSettled([
        complete(),
        issueReopenCode(r.db.url, { restoreId: r.restoreId }),
      ]);
      const state = await guardState(r.db.url);
      if (completed.status === 'fulfilled') {
        // The completion won: open, and the host was told no code exists any more.
        expect(issued.status).toBe('rejected');
        expect(state).toBe('open');
      } else {
        expect(issued.status).toBe('fulfilled');
        expect(state).toBe('reopening');
      }
    });
  });

  describe('REVIEW R12 (regression): reopening needs the device key and AK, not the password alone', () => {
    let r: Awaited<ReturnType<typeof restoredAndReviewed>>;

    beforeAll(async () => {
      r = await restoredAndReviewed();
    }, 120_000);
    afterAll(async () => {
      await (r as typeof r | undefined)?.h.close();
    });
    beforeEach(() => {
      r.clearThrottle();
    });

    it('refuses the code and the snapshot-time password without the device proof', async () => {
      const attempt = await reopenWithPassword(r.h, account, r.code, { prove: false });
      expectError(attempt.finish, 'reopen_failed');
      // With another key: the same.
      const other = await reopenWithPassword(r.h, account, r.code, {
        deviceKey: account.crypto.generateDeviceKey(),
      });
      expectError(other.finish, 'reopen_failed');
      expect(await codes(r.db.url)).toEqual([
        { failed_attempts: 2, revoked: false, consumed: false },
      ]);
      expect(await guardState(r.db.url)).toBe('reopening');
    });

    it('refuses a junk password wrap without a valid AK proof, and changes nothing', async () => {
      const started = await reopenWithPassword(r.h, account, r.code);
      expect(started.finish?.status, started.finish?.text).toBe(200);
      const cookie = reopenCookie(started.finish as request.Response);
      const material = await reopenMaterial(r.h, cookie);
      const unwrapped = unwrapReopenMaterial(account, material, {});
      const { body } = await reopenCompleteBody(
        r.h,
        account,
        cookie,
        material,
        unwrapped,
        NEW_PASSWORD,
      );
      // R12: the header-only check accepted any bytes; now the wrap is bound to AK's proof.
      const junk = Buffer.from(body.wrappedAkPassword, 'base64url');
      junk.fill(0x41, 40);
      expectError(
        await r.h.post(
          '/api/v1/reopen/complete',
          { ...body, wrappedAkPassword: junk.toString('base64url') },
          cookie,
        ),
        'device_proof_failed',
      );
      // A proof by any key but AK's: refused as a mismatched account key.
      const forged = await reopenCompleteBody(
        r.h,
        account,
        cookie,
        material,
        {
          ...unwrapped,
          accountKey: account.crypto.generateKey(),
        },
        NEW_PASSWORD,
      );
      expectError(
        await r.h.post('/api/v1/reopen/complete', forged.body, cookie),
        'device_key_mismatch',
      );
      expect(await guardState(r.db.url)).toBe('reopening');
      const [keys] = await query<{ wrapped_ak_password: Buffer }>(
        r.db.url,
        'SELECT wrapped_ak_password FROM account_keys',
      );
      expect(b64(keys?.wrapped_ak_password ?? new Uint8Array())).toBe(
        material.password?.wrappedAkPassword,
      );
    });
  });
});
