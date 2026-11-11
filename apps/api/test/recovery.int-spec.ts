import { uuidToBytes } from '@ruvee/crypto';
import {
  accountResponseSchema,
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  recoveryMaterialResponseSchema,
  recoveryStartResponseSchema,
  registerStartResponseSchema,
  sessionResponseSchema,
} from '@ruvee/contracts';
import type request from 'supertest';
import { ThrottleService } from '../src/auth/throttle.service.js';
import { ProofService } from '../src/sessions/proof.service.js';
import { registerAccount, startHarness, type Harness } from './support/api-harness.js';
import {
  finishLogin,
  finishRegistration,
  startLogin,
  startRegistration,
  SYNTHETIC_PASSWORD,
  syntheticAccount,
  type SyntheticAccount,
} from './support/synthetic-client.js';
import { signCompletion } from './support/device-proof.js';
import { query } from './support/temp-database.js';

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));
const NEW_PASSWORD = 'synthetic recovered passphrase 77ab';

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

function recoveryCookie(res: request.Response): string {
  const header = res.headers['set-cookie'] as unknown as string[] | undefined;
  const cookie = header?.find((c) => c.startsWith('__Host-ruvee_recovery='));
  if (!cookie) throw new Error('no recovery cookie');
  expect(cookie).toContain('HttpOnly');
  expect(cookie).toContain('Secure');
  return cookie.split(';')[0] ?? '';
}

describe('recovery with the Recovery Kit (account-recovery §3, real database)', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let oldCookie: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-recovery-owner');
    oldCookie = await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  beforeEach(async () => {
    await h.app.get(ThrottleService).clearIpWindows();
  });

  const start = (username: string, rak: Uint8Array, deviceId = account.crypto.generateUuid()) =>
    h.post('/api/v1/recovery/start', {
      username,
      recoveryAuthKey: b64(rak),
      device: { id: deviceId, platform: 'web' },
    });

  async function login(password: string) {
    const client = startLogin(password);
    const res = await h
      .post('/api/v1/auth/login/start', {
        username: account.username,
        startLoginRequest: client.startLoginRequest,
        platform: 'web',
      })
      .expect(200);
    const parsed = loginStartResponseSchema.parse(res.body);
    return finishLogin(client.clientLoginState, parsed.loginResponse, password);
  }

  it('fails the same way for a wrong key and an unknown username, and records it', async () => {
    const wrong = account.crypto.deriveRecoveryKeys(
      account.crypto.generateRecoveryKey().recoveryKey,
    );
    const a = await start(account.username, wrong.recoveryAuthKey);
    const b = await start('nobody-at-all', wrong.recoveryAuthKey);
    expectError(a, 'recovery_failed');
    expectError(b, 'recovery_failed');
    expect(Object.keys(a.body as object)).toEqual(Object.keys(b.body as object));
    expect(a.headers['set-cookie']).toBeUndefined();
    const failed = await query(
      h.db.url,
      `SELECT 1 FROM security_events WHERE type = 'recovery_failed'`,
    );
    expect(failed).toHaveLength(2);
  });

  it('recovers: material, new password, mandatory key rotation, other sessions ended', async () => {
    const { crypto } = account;
    const rk = crypto.parseRecoveryKey(account.recoveryKeyText);
    const keys = crypto.deriveRecoveryKeys(rk);
    const started = await start(account.username, keys.recoveryAuthKey);
    expect(started.status, started.text).toBe(200);
    const cookie = recoveryCookie(started);
    // The notice is raised at start, before anything was completed (V-07).
    const notice = accountResponseSchema.parse(
      (await h.get('/api/v1/account', oldCookie).expect(200)).body,
    );
    expect(notice.lastRecoveryAt).not.toBeNull();

    // The recovery session works only on recovery endpoints, and normal sessions not on those.
    expectError(await h.get('/api/v1/account/keys', cookie), 'unauthenticated');
    expectError(await h.get('/api/v1/recovery/material', oldCookie), 'unauthenticated');

    const material = recoveryMaterialResponseSchema.parse(
      (await h.get('/api/v1/recovery/material', cookie).expect(200)).body,
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
    expect(b64(ak)).toBe(b64(account.accountKey));
    const keyset = crypto.openKeyset({
      accountKey: ak,
      accountKeyId: unb64(material.akId),
      accountId,
      keysetVersion: material.keysetVersion,
      envelope: unb64(material.keyset),
    });

    // New password, new wrap with the same SK, new Recovery Key.
    const reg = startRegistration(NEW_PASSWORD);
    const regStart = await h
      .post(
        '/api/v1/recovery/password/start',
        { registrationRequest: reg.registrationRequest },
        cookie,
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
    const body = {
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
    };
    // The recovering device enrolls a new device key, proved with itself and with AK (§8).
    const deviceId = recoveryStartResponseSchema.parse(started.body).deviceId;
    const deviceKey = crypto.generateDeviceKey();
    const complete = (b: typeof body, accountKey?: Uint8Array) =>
      signCompletion(h, account, cookie, 'recovery_complete', b, {
        deviceKey,
        deviceId,
        ...(accountKey ? { accountKey } : {}),
      });
    // Rotation is mandatory: the old recovery key id is refused.
    expectError(
      await h.post(
        '/api/v1/recovery/complete',
        await complete({ ...body, recoveryKeyId: material.recoveryKeyId }),
        cookie,
      ),
      'invalid_request',
    );
    expectError(
      await h.post(
        '/api/v1/recovery/complete',
        await complete({ ...body, expectedRowVersion: material.rowVersion + 5 }),
        cookie,
      ),
      'row_version_conflict',
    );
    // R-08: someone who learned only RAK has no AK. Any other key gives another AVPK...
    const notAk = crypto.generateKey();
    expectError(
      await h.post('/api/v1/recovery/complete', await complete(body, notAk), cookie),
      'device_key_mismatch',
    );
    // ...and a signature that is not made with AK's key does not verify against the account's.
    const forged = await complete(body, notAk);
    expectError(
      await h.post(
        '/api/v1/recovery/complete',
        { ...forged, akVerifyKey: b64(account.akVerifyKey) },
        cookie,
      ),
      'device_proof_failed',
    );
    // Follow-up review F-18: the device is revoked after the request was authenticated but before
    // its transaction. Completion must not make it active again.
    const [before] = await query<{ status: string }>(
      h.db.url,
      'SELECT status::text AS status FROM devices WHERE id = $1',
      [deviceId],
    );
    const proofs = h.app.get(ProofService);
    const consume = proofs.consume.bind(proofs);
    vi.spyOn(proofs, 'consume').mockImplementationOnce(async (...args) => {
      await query(
        h.db.url,
        `UPDATE devices SET status = 'revoked', revoked_at = now() WHERE id = $1`,
        [deviceId],
      );
      return consume(...args);
    });
    expectError(
      await h.post('/api/v1/recovery/complete', await complete(body), cookie),
      'device_revoked',
    );
    const [after] = await query<{ status: string }>(
      h.db.url,
      'SELECT status::text AS status FROM devices WHERE id = $1',
      [deviceId],
    );
    expect(after?.status).toBe('revoked');
    vi.restoreAllMocks();
    // Put it back as it was, and complete for real.
    await query(
      h.db.url,
      `UPDATE devices SET status = $2::device_status, revoked_at = NULL WHERE id = $1`,
      [deviceId, before?.status],
    );

    const signed = await complete(body);
    const done = await h.post('/api/v1/recovery/complete', signed, cookie);
    expect(done.status, done.text).toBe(200);
    expect(String(done.headers['set-cookie'])).toContain('__Host-ruvee_recovery=; Path=/');

    // Every earlier session ended, the recovery session too; the new password logs in.
    expectError(await h.get('/api/v1/account', oldCookie), 'unauthenticated');
    expectError(await h.get('/api/v1/recovery/material', cookie), 'unauthenticated');
    // Completion is single use (INV-23): the same recovery session cannot complete again.
    expectError(await h.post('/api/v1/recovery/complete', signed, cookie), 'unauthenticated');
    // The device now holds the new key, and the new session was proven by it.
    const [enrolled] = await query<{ public_key: Buffer }>(
      h.db.url,
      'SELECT public_key FROM devices WHERE id = $1',
      [deviceId],
    );
    expect(b64(enrolled?.public_key ?? new Uint8Array())).toBe(b64(deviceKey.publicKey));
    expect(sessionResponseSchema.parse(done.body).proven).toBe(true);
    // AK's verification key is the account's own, unchanged: only AK could prove it (§8).
    const [avpk] = await query<{ ak_verify_key: Buffer }>(
      h.db.url,
      'SELECT ak_verify_key FROM account_keys',
    );
    expect(b64(avpk?.ak_verify_key ?? new Uint8Array())).toBe(b64(account.akVerifyKey));
    expect(await login(SYNTHETIC_PASSWORD)).toBeUndefined();
    expect(await login(NEW_PASSWORD)).toBeDefined();
    // The old kit no longer works against this server.
    expectError(await start(account.username, keys.recoveryAuthKey), 'recovery_failed');
    const events = await query<{ type: string }>(
      h.db.url,
      `SELECT type FROM security_events ORDER BY created_at`,
    );
    expect(events.map((e) => e.type)).toEqual(
      expect.arrayContaining(['recovery_started', 'recovery_completed', 'recovery_key_rotated']),
    );
    const device = await query<{ status: string; enrolled_via: string }>(
      h.db.url,
      `SELECT status, enrolled_via FROM devices WHERE enrolled_via = 'recovery'`,
    );
    expect(device).toEqual([{ status: 'active', enrolled_via: 'recovery' }]);
  });

  it('limits recovery starts per username, known or not (5 per hour)', async () => {
    const wrong = account.crypto.deriveRecoveryKeys(
      account.crypto.generateRecoveryKey().recoveryKey,
    );
    for (let i = 0; i < 5; i++)
      expectError(await start('throttled-name', wrong.recoveryAuthKey), 'recovery_failed');
    const limited = await start('throttled-name', wrong.recoveryAuthKey);
    expectError(limited, 'rate_limited');
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
    expectError(
      await h.http().post('/api/v1/recovery/start').set({ 'X-Ruvee-Request': '1' }).send({}),
      'csrf_rejected',
    );
  });
});
