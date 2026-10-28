import {
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  sessionResponseSchema,
} from '@ruvee/contracts';
import type request from 'supertest';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  WRITE_HEADERS,
  type Harness,
} from '../support/api-harness.js';
import { uuidToBytes } from '@ruvee/crypto';
import { loginDevice, proofNonce, signLogin, signOperation } from '../support/device-proof.js';
import { query } from '../support/temp-database.js';
import {
  startLogin,
  syntheticAccount,
  type SyntheticAccount,
} from '../support/synthetic-client.js';
import { finishLogin } from '../support/synthetic-client.js';

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

/**
 * Pre-deployment review, findings R2 and R3 (docs/security/predeployment-review.md), as
 * regressions. R2: the password plus a device's public id no longer acts as that device; only a
 * proof with its own key does (docs/security/device-proof.md, D-31 A). R3: the throttle holds
 * under parallel requests. Synthetic data only.
 */
describe('REVIEW R2 (regression): the password alone never acts as an enrolled device', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let owner: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-review-r2');
    owner = await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  beforeEach(async () => {
    const { ThrottleService } = await import('../../src/auth/throttle.service.js');
    h.app.get(ThrottleService).clearIpWindows();
    await query(h.db.url, 'DELETE FROM auth_throttle');
  });

  /** What R2 did: the password and the public device id, with no key at all. */
  async function passwordOnly() {
    const res = await loginDevice(h, account, { prove: false });
    expect(res.status, res.text).toBe(200);
    return { body: sessionResponseSchema.parse(res.body), cookie: sessionCookie(res) };
  }

  it('gives a pre-proof session that reaches only the allowlist, and leaves the device signed in', async () => {
    const { body, cookie } = await passwordOnly();
    expect(body.device).toEqual({ id: account.deviceId, status: 'active' });
    expect(body.proven).toBe(false);
    // The allowlist (device-proof.md §5): the device record and the encrypted key material.
    await h.get('/api/v1/account/keys', cookie).expect(200);
    const current = await h.get('/api/v1/devices/current', cookie).expect(200);
    expect(current.body).toMatchObject({ sessionProven: false, hasDeviceKey: true });
    // Everything else is refused, whatever the level.
    for (const path of ['/api/v1/account', '/api/v1/devices', '/api/v1/sessions', '/api/v1/vault'])
      expect((await h.get(path, cookie)).body).toMatchObject({ error: 'device_proof_required' });
    expect((await h.get('/api/v1/sync/changes?since=0', cookie)).body).toMatchObject({
      error: 'device_proof_required',
    });
    // The genuine device was not signed out (R2's "superseded").
    await h.get('/api/v1/devices', owner).expect(200);
  });

  it('cannot step up, replace wraps, rotate the kit, revoke devices or commit', async () => {
    const { cookie } = await passwordOnly();
    const client = startLogin();
    expectError(
      await h.post(
        '/api/v1/auth/reauth/start',
        { startLoginRequest: client.startLoginRequest },
        cookie,
      ),
      'device_proof_required',
    );
    const junk = Buffer.alloc(93, 0x41).toString('base64url');
    const fakeProof = {
      device: Buffer.alloc(64, 1).toString('base64url'),
      accountKey: Buffer.alloc(64, 2).toString('base64url'),
    };
    const nonce = Buffer.alloc(32, 3).toString('base64url');
    expectError(
      await h.post(
        '/api/v1/account/password/finish',
        {
          registrationRecord: Buffer.alloc(192, 1).toString('base64url'),
          kdfProfile: 1,
          saltPw: Buffer.alloc(16, 2).toString('base64url'),
          wrappedAkPassword: junk,
          expectedRowVersion: 1,
          nonce,
          proof: fakeProof,
        },
        cookie,
      ),
      'device_proof_required',
    );
    expectError(await h.post('/api/v1/sync/commits', {}, cookie), 'device_proof_required');
    expectError(
      await h.post(
        `/api/v1/devices/${account.crypto.generateUuid()}/revoke`,
        { reason: 'lost', nonce, proof: { device: fakeProof.device } },
        cookie,
      ),
      'device_proof_required',
    );
    // A pre-proof session gets a nonce only for proving itself.
    expectError(
      await h.post('/api/v1/auth/proof-nonce', { operation: 'password_change' }, cookie),
      'device_proof_required',
    );
    // Without DSK it cannot prove itself: any other key fails, and that ends the session.
    const proofNonceRes = await proofNonce(h, cookie, 'session_proof');
    const stolen = signOperation(account, 'session_proof', proofNonceRes, [], {
      deviceKey: account.crypto.generateDeviceKey(),
    });
    expectError(await h.post('/api/v1/auth/session-proof', stolen, cookie), 'device_proof_failed');
    expectError(await h.get('/api/v1/account/keys', cookie), 'unauthenticated');
    const [event] = await query<{ n: string }>(
      h.db.url,
      `SELECT count(*) AS n FROM security_events WHERE type = 'device_proof_failed'`,
    );
    expect(Number(event?.n)).toBeGreaterThanOrEqual(1);
  });

  it('refuses a login proof made with a substituted key, another operation or another login', async () => {
    const other = account.crypto.generateDeviceKey();
    expectError(await loginDevice(h, account, { deviceKey: other }), 'device_proof_failed');
    // A signature from another login's challenge (binding and nonce differ).
    const client = startLogin();
    const first = loginStartResponseSchema.parse(
      (
        await h.post('/api/v1/auth/login/start', {
          username: account.username,
          startLoginRequest: client.startLoginRequest,
          platform: 'web',
          deviceId: account.deviceId,
        })
      ).body,
    );
    const finished = finishLogin(client.clientLoginState, first.loginResponse);
    const client2 = startLogin();
    const second = loginStartResponseSchema.parse(
      (
        await h.post('/api/v1/auth/login/start', {
          username: account.username,
          startLoginRequest: client2.startLoginRequest,
          platform: 'web',
          deviceId: account.deviceId,
        })
      ).body,
    );
    const finished2 = finishLogin(client2.clientLoginState, second.loginResponse);
    expectError(
      await h.post('/api/v1/auth/login/finish', {
        loginId: second.loginId,
        finishLoginRequest: finished2?.finishLoginRequest,
        deviceProof: signLogin(account, first, finished?.finishLoginRequest ?? ''),
      }),
      'device_proof_failed',
    );
    // The reopening operation's signature is not a login's.
    expectError(
      await h.post('/api/v1/auth/login/finish', {
        loginId: first.loginId,
        finishLoginRequest: finished?.finishLoginRequest,
        deviceProof: signLogin(account, first, finished?.finishLoginRequest ?? '', {
          operation: 'reopen_login',
        }),
      }),
      'device_proof_failed',
    );
    // The genuine key still works.
    const ok = await loginDevice(h, account);
    expect(sessionResponseSchema.parse(ok.body).proven).toBe(true);
  });

  it('proves a session with the device key; nonces are bound, single-use and expire', async () => {
    const { cookie } = await passwordOnly();
    const n1 = await proofNonce(h, cookie, 'session_proof');
    // Signed for another session (its session_ref), or with another operation: refused.
    const elsewhere = signOperation(
      account,
      'session_proof',
      { ...n1, sessionRef: Buffer.alloc(32, 9).toString('base64url') },
      [],
    );
    expectError(
      await h.post('/api/v1/auth/session-proof', elsewhere, cookie),
      'device_proof_failed',
    );
    // That failure ended the pre-proof session; start again.
    const second = await passwordOnly();
    const n2 = await proofNonce(h, second.cookie, 'session_proof');
    // An expired nonce fails safely (and the failure ends the session).
    await query(h.db.url, `UPDATE proof_nonces SET expires_at = now() - interval '1 second'`);
    expectError(
      await h.post(
        '/api/v1/auth/session-proof',
        signOperation(account, 'session_proof', n2, []),
        second.cookie,
      ),
      'device_proof_failed',
    );
    // Two concurrent proofs with one nonce: exactly one succeeds.
    const third = await passwordOnly();
    const n3 = await proofNonce(h, third.cookie, 'session_proof');
    const proof = signOperation(account, 'session_proof', n3, []);
    const results = await Promise.all([
      h.post('/api/v1/auth/session-proof', proof, third.cookie),
      h.post('/api/v1/auth/session-proof', proof, third.cookie),
    ]);
    // Exactly one succeeds; the other is refused (the nonce is gone, or the session is proven).
    const statuses = results.map((r) => r.status).sort();
    expect(statuses[0]).toBe(204);
    expect([401, 403]).toContain(statuses[1]);
    // The proven session acts as the device, and the device's other sessions ended.
    await h.get('/api/v1/devices', third.cookie).expect(200);
    expectError(await h.get('/api/v1/devices', owner), 'unauthenticated');
    owner = third.cookie;
  });

  it('binds an operation proof to its account, operation and session; a used nonce stays used', async () => {
    // A fresh proven login: fresh enough for the step-up that revocation needs.
    const res = await loginDevice(h, account);
    expect(res.status, res.text).toBe(200);
    owner = sessionCookie(res);
    const addDevice = async (key?: { publicKey: Uint8Array }) => {
      const id = account.crypto.generateUuid();
      await query(
        h.db.url,
        `INSERT INTO devices (id, account_id, platform, status, enrolled_via, public_key, created_at, enrolled_at)
         VALUES ($1, $2, 'web', 'active', 'pairing', $3, now(), now())`,
        [id, account.accountId, key ? Buffer.from(key.publicKey) : null],
      );
      return id;
    };
    const [x, y] = [await addDevice(), await addDevice()];
    const fields = (id: string) => [uuidToBytes(id), { text: 'retired' }];
    const revoke = (id: string, signed: object, cookie = owner) =>
      h.post(`/api/v1/devices/${id}/revoke`, { reason: 'retired', ...signed }, cookie);

    // Signed for another account: refused.
    const n1 = await proofNonce(h, owner, 'device_revoke');
    const otherAccount = account.crypto.generateUuid();
    expectError(
      await revoke(
        x,
        signOperation(account, 'device_revoke', n1, fields(x), { accountId: otherAccount }),
      ),
      'device_proof_failed',
    );
    // A nonce issued for another operation, with a valid device_revoke signature: refused.
    const forPassword = await proofNonce(h, owner, 'password_change');
    expectError(
      await revoke(x, signOperation(account, 'device_revoke', forPassword, fields(x))),
      'device_proof_failed',
    );
    // A nonce of another proven session, signed with this session's binding: refused.
    const otherKey = account.crypto.generateDeviceKey();
    const otherId = await addDevice(otherKey);
    const otherRes = await loginDevice(h, account, { deviceId: otherId, deviceKey: otherKey });
    expect(otherRes.status, otherRes.text).toBe(200);
    const theirs = await proofNonce(h, sessionCookie(otherRes), 'device_revoke');
    const mine = await proofNonce(h, owner, 'device_revoke');
    expectError(
      await revoke(
        x,
        signOperation(
          account,
          'device_revoke',
          { ...theirs, sessionRef: mine.sessionRef },
          fields(x),
        ),
      ),
      'device_proof_failed',
    );
    // The right proof succeeds once; its nonce, signed again for another device, is refused.
    const good = await proofNonce(h, owner, 'device_revoke');
    expect((await revoke(x, signOperation(account, 'device_revoke', good, fields(x)))).status).toBe(
      204,
    );
    expectError(
      await revoke(y, signOperation(account, 'device_revoke', good, fields(y))),
      'device_proof_failed',
    );
    const [row] = await query<{ status: string }>(
      h.db.url,
      'SELECT status FROM devices WHERE id = $1',
      [y],
    );
    expect(row?.status).toBe('active');
  });

  it('lets an unproven session lapse after 10 minutes', async () => {
    const { cookie } = await passwordOnly();
    // The device has been active for longer than that too (F-10: the lapse starts at whichever
    // is later, the login or the device's enrollment).
    await query(
      h.db.url,
      `UPDATE devices SET enrolled_at = now() - interval '11 minutes' WHERE enrolled_at > now() - interval '11 minutes'`,
    );
    await query(
      h.db.url,
      `UPDATE sessions SET created_at = now() - interval '11 minutes' WHERE proven_at IS NULL AND revoked_at IS NULL`,
    );
    expectError(await h.get('/api/v1/devices/current', cookie), 'session_expired');
  });

  it('keeps proof status across token refreshes, proven or not', async () => {
    const EXTENSION_HEADERS = {
      Origin: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop',
      'X-Ruvee-Request': '1',
    };
    // An enrolled extension device with its own key (as pairing would have enrolled it).
    const extKey = account.crypto.generateDeviceKey();
    const extId = account.crypto.generateUuid();
    await query(
      h.db.url,
      `INSERT INTO devices (id, account_id, platform, status, enrolled_via, public_key, created_at, enrolled_at)
       VALUES ($1, $2, 'extension', 'active', 'pairing', $3, now(), now())`,
      [extId, account.accountId, Buffer.from(extKey.publicKey)],
    );
    const tokenLogin = async (prove: boolean) => {
      const client = startLogin();
      const start = loginStartResponseSchema.parse(
        (
          await h.http().post('/api/v1/auth/login/start').set(EXTENSION_HEADERS).send({
            username: account.username,
            startLoginRequest: client.startLoginRequest,
            platform: 'extension',
            deviceId: extId,
          })
        ).body,
      );
      const finished = finishLogin(client.clientLoginState, start.loginResponse);
      const res = await h
        .http()
        .post('/api/v1/auth/login/finish')
        .set(EXTENSION_HEADERS)
        .send({
          loginId: start.loginId,
          finishLoginRequest: finished?.finishLoginRequest,
          ...(prove
            ? {
                deviceProof: signLogin(account, start, finished?.finishLoginRequest ?? '', {
                  deviceKey: extKey,
                  deviceId: extId,
                }),
              }
            : {}),
        });
      const body = sessionResponseSchema.parse(res.body);
      if (!body.tokens) throw new Error('no tokens');
      return body;
    };
    const refreshAndRead = async (refreshToken: string) => {
      const refreshed = await h
        .http()
        .post('/api/v1/auth/refresh')
        .set(EXTENSION_HEADERS)
        .send({ refreshToken });
      expect(refreshed.status, refreshed.text).toBe(200);
      const access = (refreshed.body as { accessToken: string }).accessToken;
      return h
        .http()
        .get('/api/v1/devices')
        .set({ Authorization: `Bearer ${access}` });
    };
    const unproven = await tokenLogin(false);
    expect(unproven.proven).toBe(false);
    expect((await refreshAndRead(unproven.tokens?.refreshToken ?? '')).body).toMatchObject({
      error: 'device_proof_required',
    });
    const proven = await tokenLogin(true);
    expect(proven.proven).toBe(true);
    expect((await refreshAndRead(proven.tokens?.refreshToken ?? '')).status).toBe(200);

    // Follow-up review F-11: a refresh does not outlive the 10-minute pre-proof lapse.
    const stale = await tokenLogin(false);
    await query(
      h.db.url,
      `UPDATE devices SET enrolled_at = now() - interval '11 minutes' WHERE id = $1`,
      [extId],
    );
    await query(
      h.db.url,
      `UPDATE sessions SET created_at = now() - interval '11 minutes'
       WHERE device_id = $1 AND kind = 'token' AND proven_at IS NULL AND revoked_at IS NULL`,
      [extId],
    );
    expectError(
      await h
        .http()
        .post('/api/v1/auth/refresh')
        .set(EXTENSION_HEADERS)
        .send({ refreshToken: stale.tokens?.refreshToken }),
      'session_expired',
    );
    // A proven one is not affected by its age.
    const again = await tokenLogin(true);
    await query(
      h.db.url,
      `UPDATE sessions SET created_at = now() - interval '11 minutes'
       WHERE device_id = $1 AND kind = 'token' AND proven_at IS NOT NULL AND revoked_at IS NULL`,
      [extId],
    );
    expect((await refreshAndRead(again.tokens?.refreshToken ?? '')).status).toBe(200);
  });
});

const WRONG = 'synthetic wrong guess 00';
const GARBAGE_FINISH = Buffer.alloc(64, 1).toString('base64url');
const tally = (statuses: number[]) => ({
  evaluated: statuses.filter((x) => x === 401).length,
  refused: statuses.filter((x) => x === 429).length,
});

describe('REVIEW R3 (regression): the per-username throttle holds under parallel requests', () => {
  let h: Harness;
  let account: SyntheticAccount;

  beforeAll(async () => {
    // The documented topology: one API behind Caddy, client addresses from X-Forwarded-For.
    process.env.TRUSTED_PROXY_ADDRESS = '127.0.0.1';
    vi.resetModules();
    h = await startHarness();
    account = await syntheticAccount('synthetic-review-r3');
    await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    delete process.env.TRUSTED_PROXY_ADDRESS;
    await h.close();
  });

  beforeEach(async () => {
    await query(h.db.url, 'DELETE FROM auth_throttle');
  });

  // A different client address for every request: no per-IP window ever fills (an attacker
  // with many addresses), so only the per-username bound can stop them.
  let address = 0;
  const from = () => `198.51.100.${String((address++ % 250) + 1)}`;
  const post = (path: string, body: object, cookie?: string) => {
    const req = h.http().post(path).set(WRITE_HEADERS).set('X-Forwarded-For', from()).send(body);
    return cookie ? req.set('Cookie', cookie) : req;
  };
  const startWrong = async () => {
    const res = await post('/api/v1/auth/login/start', {
      username: account.username,
      startLoginRequest: startLogin(WRONG).startLoginRequest,
      platform: 'web',
    });
    return loginStartResponseSchema.parse(res.body).loginId;
  };

  it('evaluates at most five of twelve parallel login finishes; the rest are 429', async () => {
    // Twelve logins started before any failure is recorded, then finished all at once.
    const starts = await Promise.all(Array.from({ length: 12 }, startWrong));
    const finishes = await Promise.all(
      starts.map((loginId) =>
        post('/api/v1/auth/login/finish', { loginId, finishLoginRequest: GARBAGE_FINISH }),
      ),
    );
    expect(tally(finishes.map((r) => r.status))).toEqual({ evaluated: 5, refused: 7 });
    const limited = finishes.find((r) => r.status === 429);
    expect(Number(limited?.headers['retry-after'])).toBeGreaterThan(0);
    // A new start is blocked too, and so is the right password until the delay ends.
    const after = await post('/api/v1/auth/login/start', {
      username: account.username,
      startLoginRequest: startLogin().startLoginRequest,
      platform: 'web',
    });
    expect(after.status).toBe(429);
  });

  it('applies the same bound sequentially: five evaluated, then 429', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 7; i++) {
      const loginId = await startWrong().catch(() => undefined);
      if (!loginId) {
        statuses.push(429);
        continue;
      }
      statuses.push(
        (await post('/api/v1/auth/login/finish', { loginId, finishLoginRequest: GARBAGE_FINISH }))
          .status,
      );
    }
    expect(tally(statuses)).toEqual({ evaluated: 5, refused: 2 });
  });

  it('bounds parallel step-up finishes on a stolen session the same way', async () => {
    const client = startLogin();
    const start = loginStartResponseSchema.parse(
      (
        await post('/api/v1/auth/login/start', {
          username: account.username,
          startLoginRequest: client.startLoginRequest,
          platform: 'web',
          deviceId: account.deviceId,
        })
      ).body,
    );
    const finished = finishLogin(client.clientLoginState, start.loginResponse);
    // A session proven by the device key: only such a session may step up (device-proof.md §7).
    const cookie = sessionCookie(
      await post('/api/v1/auth/login/finish', {
        loginId: start.loginId,
        finishLoginRequest: finished?.finishLoginRequest,
        deviceProof: signLogin(account, start, finished?.finishLoginRequest ?? ''),
      }),
    );
    const reauths = await Promise.all(
      Array.from({ length: 9 }, async () =>
        loginStartResponseSchema.parse(
          (
            await post(
              '/api/v1/auth/reauth/start',
              { startLoginRequest: startLogin(WRONG).startLoginRequest },
              cookie,
            )
          ).body,
        ),
      ),
    );
    const finishes = await Promise.all(
      reauths.map((r) =>
        post(
          '/api/v1/auth/reauth/finish',
          { loginId: r.loginId, finishLoginRequest: GARBAGE_FINISH },
          cookie,
        ),
      ),
    );
    expect(tally(finishes.map((r) => r.status))).toEqual({ evaluated: 5, refused: 4 });
  });

  it('counts at most five parallel recovery attempts per username per hour', async () => {
    const attempts = await Promise.all(
      Array.from({ length: 9 }, () =>
        post('/api/v1/recovery/start', {
          username: account.username,
          recoveryAuthKey: Buffer.alloc(32, 9).toString('base64url'),
          device: { id: account.crypto.generateUuid(), platform: 'web' },
        }),
      ),
    );
    expect(tally(attempts.map((r) => r.status))).toEqual({ evaluated: 5, refused: 4 });
  });
});
