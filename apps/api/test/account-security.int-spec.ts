import { uuidToBytes } from '@ruvee/crypto';
import {
  accountKeysResponseSchema,
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  registerStartResponseSchema,
  sessionResponseSchema,
  securityEventsResponseSchema,
  sessionsResponseSchema,
} from '@ruvee/contracts';
import type request from 'supertest';
import { ThrottleService } from '../src/auth/throttle.service.js';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  type Harness,
} from './support/api-harness.js';
import {
  finishLogin,
  finishRegistration,
  startLogin,
  startRegistration,
  SYNTHETIC_PASSWORD,
  syntheticAccount,
  type SyntheticAccount,
} from './support/synthetic-client.js';
import { query } from './support/temp-database.js';

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));
const NEW_PASSWORD = 'synthetic changed passphrase 5d0c';

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

describe('step-up, sessions, revocation and password change (real database)', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let cookieA: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-security-owner');
    cookieA = await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  beforeEach(() => {
    h.app.get(ThrottleService).clearIpWindows();
  });

  async function login(password = SYNTHETIC_PASSWORD, deviceId?: string) {
    const client = startLogin(password);
    const start = loginStartResponseSchema.parse(
      (
        await h
          .post('/api/v1/auth/login/start', {
            username: account.username,
            startLoginRequest: client.startLoginRequest,
            platform: 'web',
            ...(deviceId ? { deviceId } : {}),
          })
          .expect(200)
      ).body,
    );
    const finished = finishLogin(client.clientLoginState, start.loginResponse, password);
    if (!finished) return undefined;
    return h.post('/api/v1/auth/login/finish', {
      loginId: start.loginId,
      finishLoginRequest: finished.finishLoginRequest,
    });
  }

  async function stepUp(cookie: string, password = SYNTHETIC_PASSWORD) {
    const client = startLogin(password);
    const start = loginStartResponseSchema.parse(
      (
        await h
          .post(
            '/api/v1/auth/reauth/start',
            { startLoginRequest: client.startLoginRequest },
            cookie,
          )
          .expect(200)
      ).body,
    );
    const finished = finishLogin(client.clientLoginState, start.loginResponse, password);
    return { start, finished };
  }

  /** Makes every session's last OPAQUE authentication older than the 5-minute step-up window. */
  async function ageAuth() {
    await query(h.db.url, `UPDATE sessions SET auth_at = now() - interval '10 minutes'`);
  }

  it('refuses step-up endpoints with a stale authentication, and allows them after reauth (INV-14)', async () => {
    await ageAuth();
    const other = account.crypto.generateUuid();
    expectError(
      await h.post(`/api/v1/devices/${other}/revoke`, { reason: 'retired' }, cookieA),
      'step_up_required',
    );
    expectError(
      await h.post(
        '/api/v1/account/password/start',
        { registrationRequest: startRegistration().registrationRequest },
        cookieA,
      ),
      'step_up_required',
    );
    const { start, finished } = await stepUp(cookieA);
    const body = { loginId: start.loginId, finishLoginRequest: finished?.finishLoginRequest };
    // A step-up state can never be turned into a new session through login/finish.
    expectError(await h.post('/api/v1/auth/login/finish', body), 'login_failed');
    const again = await stepUp(cookieA);
    const ok = await h.post(
      '/api/v1/auth/reauth/finish',
      { loginId: again.start.loginId, finishLoginRequest: again.finished?.finishLoginRequest },
      cookieA,
    );
    expect(ok.status, ok.text).toBe(200);
    // Single use (INV-23).
    expectError(
      await h.post(
        '/api/v1/auth/reauth/finish',
        { loginId: again.start.loginId, finishLoginRequest: again.finished?.finishLoginRequest },
        cookieA,
      ),
      'login_failed',
    );
    expectError(
      await h.post(`/api/v1/devices/${other}/revoke`, { reason: 'retired' }, cookieA),
      'not_found',
    );
    // A wrong password cannot step up.
    const wrong = await stepUp(cookieA, 'synthetic wrong guess');
    expect(wrong.finished).toBeUndefined();
  });

  it('revokes a device at once for every one of its sessions, never the caller itself', async () => {
    const first = await login();
    const second = await login(
      SYNTHETIC_PASSWORD,
      sessionResponseSchema.parse(first?.body).device.id,
    );
    if (!first || !second) throw new Error('login failed');
    const deviceId = sessionResponseSchema.parse(first.body).device.id;
    const cookies = [sessionCookie(first), sessionCookie(second)];
    const listed = sessionsResponseSchema.parse(
      (await h.get('/api/v1/sessions', cookieA).expect(200)).body,
    );
    expect(listed.sessions.filter((s) => s.deviceId === deviceId)).toHaveLength(2);
    expect(listed.sessions.filter((s) => s.current)).toHaveLength(1);

    const up = await stepUp(cookieA);
    await h
      .post(
        '/api/v1/auth/reauth/finish',
        { loginId: up.start.loginId, finishLoginRequest: up.finished?.finishLoginRequest },
        cookieA,
      )
      .expect(200);
    expectError(
      await h.post(`/api/v1/devices/${account.deviceId}/revoke`, { reason: 'retired' }, cookieA),
      'forbidden',
    );
    expect(
      (await h.post(`/api/v1/devices/${deviceId}/revoke`, { reason: 'lost' }, cookieA)).status,
    ).toBe(204);
    for (const cookie of cookies)
      expectError(await h.get('/api/v1/devices/current', cookie), 'device_revoked');
    const events = await query<{ details: { reason?: string } }>(
      h.db.url,
      `SELECT details FROM security_events WHERE type = 'device_revoked'`,
    );
    expect(events).toEqual([{ details: { revokedDeviceId: deviceId, reason: 'lost' } }]);
  });

  it('ends a single session from the list', async () => {
    const res = await login();
    if (!res) throw new Error('login failed');
    const cookie = sessionCookie(res);
    const listed = sessionsResponseSchema.parse((await h.get('/api/v1/sessions', cookieA)).body);
    const target = listed.sessions.find(
      (s) => !s.current && s.deviceId === sessionResponseSchema.parse(res.body).device.id,
    );
    if (!target) throw new Error('no session');
    expect(
      (
        await h
          .http()
          .delete(`/api/v1/sessions/${target.id}`)
          .set({ Origin: 'http://127.0.0.1:3100', 'X-Ruvee-Request': '1' })
          .set('Cookie', cookieA)
      ).status,
    ).toBe(204);
    expectError(await h.get('/api/v1/account', cookie), 'unauthenticated');
  });

  it('changes the password: same AK, new wrap, other sessions ended, this one kept', async () => {
    const other = await login(SYNTHETIC_PASSWORD, account.deviceId);
    if (!other) throw new Error('login failed');
    const otherCookie = sessionCookie(other);
    const up = await stepUp(cookieA);
    await h
      .post(
        '/api/v1/auth/reauth/finish',
        { loginId: up.start.loginId, finishLoginRequest: up.finished?.finishLoginRequest },
        cookieA,
      )
      .expect(200);
    const keys = accountKeysResponseSchema.parse(
      (await h.get('/api/v1/account/keys', cookieA)).body,
    );
    const reg = startRegistration(NEW_PASSWORD);
    const regStart = await h
      .post(
        '/api/v1/account/password/start',
        { registrationRequest: reg.registrationRequest },
        cookieA,
      )
      .expect(200);
    const record = finishRegistration(
      reg.clientRegistrationState,
      registerStartResponseSchema.parse(regStart.body).registrationResponse,
      NEW_PASSWORD,
    );
    const { crypto } = account;
    const accountId = uuidToBytes(account.accountId);
    const saltPw = crypto.generatePasswordSalt();
    const auk = crypto.deriveAccountUnlockKey({
      password: NEW_PASSWORD,
      passwordSalt: saltPw,
      profile: 1,
      secretKey: account.secretKey,
      accountId,
    });
    const body = {
      registrationRecord: record,
      kdfProfile: 1,
      saltPw: b64(saltPw),
      wrappedAkPassword: b64(
        crypto.wrapAccountKey({
          accountUnlockKey: auk,
          accountKey: account.accountKey,
          accountId,
          accountKeyId: unb64(keys.akId),
          accountKeyEpoch: keys.akEpoch,
          profile: 1,
          passwordSalt: saltPw,
        }),
      ),
      expectedRowVersion: keys.rowVersion,
    };
    expectError(
      await h.post(
        '/api/v1/account/password/finish',
        { ...body, expectedRowVersion: keys.rowVersion + 1 },
        cookieA,
      ),
      'row_version_conflict',
    );
    expect((await h.post('/api/v1/account/password/finish', body, cookieA)).status).toBe(204);
    await h.get('/api/v1/account', cookieA).expect(200);
    expectError(await h.get('/api/v1/account', otherCookie), 'unauthenticated');
    expect(await login(SYNTHETIC_PASSWORD)).toBeUndefined();
    expect((await login(NEW_PASSWORD))?.status).toBe(200);
    // The new server wrap opens with the new password and SK, to the same AK (§9, §6.1).
    const after = accountKeysResponseSchema.parse(
      (await h.get('/api/v1/account/keys', cookieA)).body,
    );
    const ak = crypto.unwrapAccountKey({
      accountUnlockKey: crypto.deriveAccountUnlockKey({
        password: NEW_PASSWORD,
        passwordSalt: unb64(after.saltPw),
        profile: 1,
        secretKey: account.secretKey,
        accountId,
      }),
      accountId,
      accountKeyId: unb64(after.akId),
      accountKeyEpoch: after.akEpoch,
      profile: 1,
      passwordSalt: unb64(after.saltPw),
      envelope: unb64(after.wrappedAkPassword),
    });
    expect(b64(ak)).toBe(b64(account.accountKey));
    const changed = await query(
      h.db.url,
      `SELECT 1 FROM security_events WHERE type = 'password_changed'`,
    );
    expect(changed).toHaveLength(1);
  });

  it('rotates SK: the next keyset version, a wrap only the new SK opens (D-24)', async () => {
    const { crypto } = account;
    const accountId = uuidToBytes(account.accountId);
    const keys = accountKeysResponseSchema.parse(
      (await h.get('/api/v1/account/keys', cookieA)).body,
    );
    const newSecretKey = crypto.generateKey();
    const keysetVersion = keys.keysetVersion + 1;
    const saltPw = crypto.generatePasswordSalt();
    const auk = crypto.deriveAccountUnlockKey({
      password: NEW_PASSWORD,
      passwordSalt: saltPw,
      profile: 1,
      secretKey: newSecretKey,
      accountId,
    });
    const body = {
      keysetVersion,
      keyset: b64(
        crypto.sealKeyset({
          accountKey: account.accountKey,
          accountKeyId: unb64(keys.akId),
          accountId,
          keysetVersion,
          keyset: {
            secretKey: newSecretKey,
            vaults: [{ vaultId: account.vaultId, vkId: account.vaultKeyId, vk: account.vaultKey }],
          },
        }),
      ),
      kdfProfile: 1,
      saltPw: b64(saltPw),
      wrappedAkPassword: b64(
        crypto.wrapAccountKey({
          accountUnlockKey: auk,
          accountKey: account.accountKey,
          accountId,
          accountKeyId: unb64(keys.akId),
          accountKeyEpoch: keys.akEpoch,
          profile: 1,
          passwordSalt: saltPw,
        }),
      ),
      expectedRowVersion: keys.rowVersion,
    };
    await ageAuth();
    expectError(await h.post('/api/v1/account/secret-key', body, cookieA), 'step_up_required');
    const up = await stepUp(cookieA, NEW_PASSWORD);
    await h
      .post(
        '/api/v1/auth/reauth/finish',
        { loginId: up.start.loginId, finishLoginRequest: up.finished?.finishLoginRequest },
        cookieA,
      )
      .expect(200);
    // The version must be exactly the next one: no rollback and no gap (INV-09).
    for (const v of [keys.keysetVersion, keysetVersion + 1])
      expectError(
        await h.post('/api/v1/account/secret-key', { ...body, keysetVersion: v }, cookieA),
        'invalid_request',
      );
    expect((await h.post('/api/v1/account/secret-key', body, cookieA)).status).toBe(204);
    expectError(await h.post('/api/v1/account/secret-key', body, cookieA), 'row_version_conflict');

    const after = accountKeysResponseSchema.parse(
      (await h.get('/api/v1/account/keys', cookieA)).body,
    );
    expect(after.keysetVersion).toBe(keysetVersion);
    const unwrap = (secretKey: Uint8Array) =>
      crypto.unwrapAccountKey({
        accountUnlockKey: crypto.deriveAccountUnlockKey({
          password: NEW_PASSWORD,
          passwordSalt: unb64(after.saltPw),
          profile: 1,
          secretKey,
          accountId,
        }),
        accountId,
        accountKeyId: unb64(after.akId),
        accountKeyEpoch: after.akEpoch,
        profile: 1,
        passwordSalt: unb64(after.saltPw),
        envelope: unb64(after.wrappedAkPassword),
      });
    expect(b64(unwrap(newSecretKey))).toBe(b64(account.accountKey));
    expect(() => unwrap(account.secretKey)).toThrow();
    // The password itself did not change, and the session continues.
    expect((await login(NEW_PASSWORD))?.status).toBe(200);
    const events = await query(
      h.db.url,
      `SELECT 1 FROM security_events WHERE type = 'secret_key_rotated'`,
    );
    expect(events).toHaveLength(1);
  });

  it('rotates the Recovery Key: the old kit stops working and unfinished recoveries end', async () => {
    const { crypto } = account;
    const accountId = uuidToBytes(account.accountId);
    const rakOf = (text: string) => {
      const rk = crypto.parseRecoveryKey(text);
      return crypto.deriveRecoveryKeys(rk);
    };
    const recoveryStart = (rak: Uint8Array) =>
      h.post('/api/v1/recovery/start', {
        username: account.username,
        recoveryAuthKey: b64(rak),
        device: { id: crypto.generateUuid(), platform: 'web' },
      });
    // Someone with the old kit starts a recovery and leaves it unfinished.
    const pending = await recoveryStart(rakOf(account.recoveryKeyText).recoveryAuthKey);
    expect(pending.status, pending.text).toBe(200);
    const pendingCookie =
      (pending.headers['set-cookie'] as unknown as string[])
        .find((c) => c.startsWith('__Host-ruvee_recovery='))
        ?.split(';')[0] ?? '';
    expect(pendingCookie).not.toBe('');

    const keys = accountKeysResponseSchema.parse(
      (await h.get('/api/v1/account/keys', cookieA)).body,
    );
    const { recoveryKey, recoveryKeyId } = crypto.generateRecoveryKey();
    const derived = crypto.deriveRecoveryKeys(recoveryKey);
    const body = {
      recoveryKeyId: b64(recoveryKeyId),
      wrappedAkRecovery: b64(
        crypto.wrapAccountKeyForRecovery({
          recoveryWrapKey: derived.recoveryWrapKey,
          recoveryKeyId,
          accountId,
          accountKeyId: unb64(keys.akId),
          accountKeyEpoch: keys.akEpoch,
          accountKey: account.accountKey,
        }),
      ),
      recoveryVerifier: b64(crypto.recoveryVerifier(derived.recoveryAuthKey)),
      expectedRowVersion: keys.rowVersion,
    };
    const put = (payload: unknown) =>
      h
        .http()
        .put('/api/v1/account/recovery')
        .set({ Origin: 'http://127.0.0.1:3100', 'X-Ruvee-Request': '1' })
        .set('Cookie', cookieA)
        .send(payload as object);
    await ageAuth();
    expectError(await put(body), 'step_up_required');
    const up = await stepUp(cookieA, NEW_PASSWORD);
    await h
      .post(
        '/api/v1/auth/reauth/finish',
        { loginId: up.start.loginId, finishLoginRequest: up.finished?.finishLoginRequest },
        cookieA,
      )
      .expect(200);
    expectError(
      await put({ ...body, expectedRowVersion: keys.rowVersion + 1 }),
      'row_version_conflict',
    );
    expect((await put(body)).status).toBe(204);
    // The same key id again is refused: rotation must change the key.
    expectError(await put({ ...body, expectedRowVersion: keys.rowVersion + 1 }), 'invalid_request');

    expectError(await h.get('/api/v1/recovery/material', pendingCookie), 'unauthenticated');
    expectError(
      await recoveryStart(rakOf(account.recoveryKeyText).recoveryAuthKey),
      'recovery_failed',
    );
    h.app.get(ThrottleService).clearIpWindows();
    expect((await recoveryStart(derived.recoveryAuthKey)).status).toBe(200);
    const rotated = await query(
      h.db.url,
      `SELECT 1 FROM security_events WHERE type = 'recovery_key_rotated'`,
    );
    expect(rotated).toHaveLength(1);
  });

  it('lists security events newest first, with only allow-listed details, 50 per page', async () => {
    // A stored detail outside the allowlist (a caller mistake in the past) never leaves.
    await query(
      h.db.url,
      `INSERT INTO security_events (id, account_id, type, details, created_at)
       SELECT gen_random_uuid(), $1, 'login_failed', '{"username":"synthetic-leak"}'::jsonb,
              now() - (n || ' minutes')::interval
       FROM generate_series(1, 60) AS n`,
      [account.accountId],
    );
    const first = securityEventsResponseSchema.parse(
      (await h.get('/api/v1/account/events', cookieA).expect(200)).body,
    );
    expect(first.events).toHaveLength(50);
    expect(first.nextCursor).not.toBeNull();
    const times = first.events.map((e) => Date.parse(e.createdAt));
    expect([...times].sort((x, y) => y - x)).toEqual(times);
    expect(first.events.some((e) => e.type === 'recovery_key_rotated')).toBe(true);
    const revoked = first.events.find((e) => e.type === 'device_revoked');
    expect(Object.keys(revoked?.details ?? {}).sort()).toEqual(['reason', 'revokedDeviceId']);
    expect(revoked?.details.reason).toBe('lost');

    const pages = [first];
    let cursor = first.nextCursor;
    while (cursor) {
      const page = securityEventsResponseSchema.parse(
        (await h.get(`/api/v1/account/events?cursor=${cursor}`, cookieA).expect(200)).body,
      );
      pages.push(page);
      cursor = page.nextCursor;
    }
    const all = pages.flatMap((p) => p.events);
    expect(new Set(all.map((e) => e.id)).size).toBe(all.length);
    const counted = await query<{ count: string }>(
      h.db.url,
      `SELECT count(*) FROM security_events WHERE account_id = $1`,
      [account.accountId],
    );
    expect(all).toHaveLength(Number(counted[0]?.count));
    expect(JSON.stringify(all)).not.toContain('synthetic-leak');

    expectError(await h.get('/api/v1/account/events?cursor=nope', cookieA), 'invalid_request');
    expectError(await h.get('/api/v1/account/events'), 'unauthenticated');
  });
});
