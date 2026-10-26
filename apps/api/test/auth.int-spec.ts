import {
  API_ERRORS,
  currentDeviceResponseSchema,
  errorResponseSchema,
  loginStartResponseSchema,
  registerStartResponseSchema,
  sessionResponseSchema,
} from '@ruvee/contracts';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import type request from 'supertest';
import { ThrottleService } from '../src/auth/throttle.service.js';
import { signLogin } from './support/device-proof.js';
import { query } from './support/temp-database.js';
import { sessionCookie, startHarness, WRITE_HEADERS, type Harness } from './support/api-harness.js';
import {
  finishLogin,
  finishRegistration,
  startLogin,
  startRegistration,
  SYNTHETIC_PASSWORD,
  syntheticAccount,
  type SyntheticAccount,
} from './support/synthetic-client.js';

const loginStart = (res: request.Response) => loginStartResponseSchema.parse(res.body);
const session = (res: request.Response) => sessionResponseSchema.parse(res.body);

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

describe('account bootstrap, login and sessions (OPAQUE, real database)', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let firstCookie: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-owner');
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  beforeEach(() => {
    h.app.get(ThrottleService).clearIpWindows();
  });

  async function login(
    username: string,
    password = SYNTHETIC_PASSWORD,
    deviceId?: string,
  ): Promise<request.Response> {
    const client = startLogin(password);
    const start = await h
      .post('/api/v1/auth/login/start', {
        username,
        startLoginRequest: client.startLoginRequest,
        platform: 'web',
        ...(deviceId ? { deviceId } : {}),
      })
      .expect(200);
    const finished = finishLogin(
      client.clientLoginState,
      loginStart(start).loginResponse,
      password,
    );
    if (!finished) throw new Error('client rejected the login');
    // The enrolled device signs the challenge with its key (device-proof.md §5).
    const proof =
      deviceId === account.deviceId
        ? { deviceProof: signLogin(account, loginStart(start), finished.finishLoginRequest) }
        : {};
    return h.post('/api/v1/auth/login/finish', {
      loginId: loginStart(start).loginId,
      finishLoginRequest: finished.finishLoginRequest,
      ...proof,
    });
  }

  it('refuses registration without a valid bootstrap token and records the failure', async () => {
    const reg = startRegistration();
    const res = await h.post('/api/v1/auth/register/start', {
      bootstrapToken: Buffer.alloc(32, 9).toString('base64url'),
      username: account.username,
      registrationRequest: reg.registrationRequest,
    });
    expectError(res, 'bootstrap_failed');
    const events = await query<{ type: string }>(h.db.url, `SELECT type FROM security_events`);
    expect(events.map((e) => e.type)).toEqual(['bootstrap_failed']);
  });

  it('creates the account, first device, session and vault, then closes registration', async () => {
    const token = await h.bootstrapToken();
    const reg = startRegistration();
    const start = await h
      .post('/api/v1/auth/register/start', {
        bootstrapToken: token,
        username: account.username,
        registrationRequest: reg.registrationRequest,
      })
      .expect(200);
    const record = finishRegistration(
      reg.clientRegistrationState,
      registerStartResponseSchema.parse(start.body).registrationResponse,
    );
    const res = await h.post('/api/v1/auth/register/finish', account.finish(record, token));
    expect(res.status, res.text).toBe(201);
    expect(sessionResponseSchema.parse(res.body)).toEqual({
      accountId: account.accountId,
      device: { id: account.deviceId, status: 'active' },
      proven: true,
    });
    const setCookie = (res.headers['set-cookie'] as unknown as string[])[0] ?? '';
    // INV-13: __Host- prefix, HttpOnly, Secure, SameSite=Strict, Path=/, no Domain.
    expect(setCookie).toMatch(/^__Host-ruvee_session=[A-Za-z0-9_-]{43}; /);
    for (const attribute of ['Path=/', 'HttpOnly', 'SameSite=Strict', 'Secure'])
      expect(setCookie).toContain(attribute);
    expect(setCookie).not.toMatch(/Domain=/i);
    firstCookie = sessionCookie(res);

    // The token is single use, and registration is closed for everyone afterwards (INV-20).
    const again = await h.post('/api/v1/auth/register/finish', account.finish(record, token));
    expectError(again, 'not_found');
    const fresh = await h.bootstrapToken();
    expectError(
      await h.post('/api/v1/auth/register/start', {
        bootstrapToken: fresh,
        username: 'someone-else',
        registrationRequest: startRegistration().registrationRequest,
      }),
      'not_found',
    );
    const vault = await h.get('/api/v1/vault', firstCookie).expect(200);
    expect(vault.body).toMatchObject({ vaultId: account.vaultId, currentSeq: 0 });
  });

  it('serves the key material to the enrolled device, never the recovery wrap', async () => {
    const res = await h.get('/api/v1/account/keys', firstCookie).expect(200);
    expect(Object.keys(res.body as object).sort()).toEqual([
      'akEpoch',
      'akId',
      'kdfProfile',
      'keyset',
      'keysetVersion',
      'rowVersion',
      'saltPw',
      'wrappedAkPassword',
    ]);
    const account2 = await h.get('/api/v1/account', firstCookie).expect(200);
    expect(account2.body).toMatchObject({
      accountId: account.accountId,
      username: 'synthetic-owner',
    });
  });

  it('logs in an enrolled device, and puts an unknown device in pending', async () => {
    const enrolled = await login(account.username, SYNTHETIC_PASSWORD, account.deviceId);
    expect(enrolled.status, enrolled.text).toBe(200);
    expect(session(enrolled).device).toEqual({ id: account.deviceId, status: 'active' });
    expect(session(enrolled).proven).toBe(true);

    const fresh = await login(account.username);
    expect(fresh.status).toBe(200);
    expect(session(fresh).device.status).toBe('pending');
    const pendingCookie = sessionCookie(fresh);
    const current = await h.get('/api/v1/devices/current', pendingCookie).expect(200);
    expect(currentDeviceResponseSchema.parse(current.body)).toMatchObject({
      status: 'pending',
      sessionProven: false,
      hasDeviceKey: false,
    });
    // A pending device reaches no encrypted data (device-enrollment §1).
    expectError(await h.get('/api/v1/account/keys', pendingCookie), 'device_not_enrolled');
    expectError(await h.get('/api/v1/sync/changes?since=0', pendingCookie), 'device_not_enrolled');
  });

  it('consumes a login id once, so a replayed finish is refused (INV-23)', async () => {
    const client = startLogin();
    const start = await h
      .post('/api/v1/auth/login/start', {
        username: account.username,
        startLoginRequest: client.startLoginRequest,
        platform: 'web',
      })
      .expect(200);
    const finished = finishLogin(client.clientLoginState, loginStart(start).loginResponse);
    const body = {
      loginId: loginStart(start).loginId,
      finishLoginRequest: finished?.finishLoginRequest,
    };
    expect((await h.post('/api/v1/auth/login/finish', body)).status).toBe(200);
    expectError(await h.post('/api/v1/auth/login/finish', body), 'login_failed');
  });

  it('gives unknown usernames a response of the same shape and size', async () => {
    const responses = [];
    for (const username of [account.username, 'nobody-here']) {
      const client = startLogin('synthetic wrong guess');
      const res = await h
        .post('/api/v1/auth/login/start', {
          username,
          startLoginRequest: client.startLoginRequest,
          platform: 'web',
        })
        .expect(200);
      expect(
        finishLogin(
          client.clientLoginState,
          loginStart(res).loginResponse,
          'synthetic wrong guess',
        ),
      ).toBe(undefined);
      responses.push(loginStart(res));
    }
    const [known, unknown] = responses;
    expect(Object.keys(known ?? {})).toEqual(Object.keys(unknown ?? {}));
    expect(known?.loginResponse.length).toBe(unknown?.loginResponse.length);
    expect(known?.loginId.length).toBe(unknown?.loginId.length);
  });

  it('keeps known and unknown usernames within a timing tolerance (T-16)', async () => {
    async function median(username: string): Promise<number> {
      const samples: number[] = [];
      for (let i = 0; i < 9; i++) {
        const client = startLogin();
        const t0 = performance.now();
        await h
          .post('/api/v1/auth/login/start', {
            username,
            startLoginRequest: client.startLoginRequest,
            platform: 'web',
          })
          .expect(200);
        samples.push(performance.now() - t0);
      }
      return samples.sort((a, b) => a - b)[4] ?? 0;
    }
    const known = await median(account.username);
    const unknown = await median('nobody-at-all');
    // Loose on purpose: this catches a missing database lookup or an early return, not
    // microsecond differences, which a local test cannot measure reliably.
    expect(Math.abs(known - unknown)).toBeLessThan(Math.max(known, unknown) * 0.5 + 5);
  });

  it('throttles repeated failures identically for known and unknown usernames, with Retry-After', async () => {
    for (const username of ['throttle-target', account.username]) {
      h.app.get(ThrottleService).clearIpWindows();
      for (let i = 0; i < 5; i++) {
        const client = startLogin('synthetic wrong guess');
        const start = await h
          .post('/api/v1/auth/login/start', {
            username,
            startLoginRequest: client.startLoginRequest,
            platform: 'web',
          })
          .expect(200);
        // A forged finish message: the server's OPAQUE check fails.
        expectError(
          await h.post('/api/v1/auth/login/finish', {
            loginId: loginStart(start).loginId,
            finishLoginRequest: Buffer.alloc(64, i + 1).toString('base64url'),
          }),
          'login_failed',
        );
      }
      const blocked = await h.post('/api/v1/auth/login/start', {
        username,
        startLoginRequest: startLogin().startLoginRequest,
        platform: 'web',
      });
      expectError(blocked, 'rate_limited');
      expect(Number(blocked.headers['retry-after'])).toBeGreaterThanOrEqual(1);
    }
    await query(h.db.url, `DELETE FROM auth_throttle`);
  });

  it('limits unauthenticated auth requests per client address (20 per minute)', async () => {
    const body = {
      username: 'ip-limit-probe',
      startLoginRequest: startLogin().startLoginRequest,
      platform: 'web',
    };
    for (let i = 0; i < 20; i++) await h.post('/api/v1/auth/login/start', body).expect(200);
    const limited = await h.post('/api/v1/auth/login/start', body);
    expectError(limited, 'rate_limited');
    expect(Number(limited.headers['retry-after'])).toBeGreaterThanOrEqual(1);
  });

  it('enforces the CSRF rules on state-changing requests (T-17)', async () => {
    const body = {
      username: account.username,
      startLoginRequest: startLogin().startLoginRequest,
      platform: 'web',
    };
    const path = '/api/v1/auth/login/start';
    expectError(await h.http().post(path).set('X-Ruvee-Request', '1').send(body), 'csrf_rejected');
    expectError(
      await h
        .http()
        .post(path)
        .set({ Origin: 'https://evil.example', 'X-Ruvee-Request': '1' })
        .send(body),
      'csrf_rejected',
    );
    expectError(
      await h.http().post(path).set({ Origin: WRITE_HEADERS.Origin }).send(body),
      'csrf_rejected',
    );
    expectError(
      await h
        .http()
        .post('/api/v1/auth/logout')
        .set({ Origin: WRITE_HEADERS.Origin })
        .set('Cookie', firstCookie),
      'csrf_rejected',
    );
  });

  it('refuses a request that carries both a cookie and a bearer token, and bearer alone', async () => {
    expectError(
      await h.get('/api/v1/account', firstCookie).set('Authorization', 'Bearer synthetic'),
      'invalid_request',
    );
    expectError(
      await h.http().get('/api/v1/account').set('Authorization', 'Bearer synthetic'),
      'unauthenticated',
    );
  });

  it('logs out and refuses the revoked session afterwards', async () => {
    const res = await login(account.username, SYNTHETIC_PASSWORD, account.deviceId);
    const cookie = sessionCookie(res);
    const out = await h.http().post('/api/v1/auth/logout').set(WRITE_HEADERS).set('Cookie', cookie);
    expect(out.status).toBe(204);
    expect(String(out.headers['set-cookie'])).toContain('Max-Age=0');
    expectError(await h.get('/api/v1/account', cookie), 'unauthenticated');
    expectError(await h.get('/api/v1/account', '__Host-ruvee_session=garbage'), 'unauthenticated');
    expectError(await h.get('/api/v1/account'), 'unauthenticated');
  });

  it('refuses a device that was revoked, on every session and at login', async () => {
    const res = await login(account.username, SYNTHETIC_PASSWORD);
    const deviceId = session(res).device.id;
    const cookie = sessionCookie(res);
    await query(
      h.db.url,
      `UPDATE devices SET status = 'revoked', revoked_at = now() WHERE id = $1`,
      [deviceId],
    );
    expectError(await h.get('/api/v1/devices/current', cookie), 'device_revoked');
    expectError(await login(account.username, SYNTHETIC_PASSWORD, deviceId), 'device_revoked');
  });

  it('never sends or stores the password, Recovery Key or vault keys (INV-01 capture)', async () => {
    const forbidden = [
      SYNTHETIC_PASSWORD,
      account.recoveryKeyText,
      account.recoveryKeyText.replace(/-/g, ''),
      Buffer.from(account.secretKey).toString('base64url'),
      Buffer.from(account.accountKey).toString('base64url'),
      Buffer.from(account.vaultKey).toString('base64url'),
    ];
    const dump = await query<{ row: string }>(
      h.db.url,
      `SELECT row_to_json(t)::text AS row FROM (
         SELECT * FROM accounts) t
       UNION ALL SELECT row_to_json(t)::text FROM (SELECT * FROM account_keys) t
       UNION ALL SELECT row_to_json(t)::text FROM (SELECT * FROM opaque_credentials) t
       UNION ALL SELECT row_to_json(t)::text FROM (SELECT * FROM devices) t
       UNION ALL SELECT row_to_json(t)::text FROM (SELECT * FROM security_events) t`,
    );
    const haystacks = [...h.sent, ...h.logs, ...dump.map((d) => d.row)].join('\n');
    for (const secret of forbidden) expect(haystacks).not.toContain(secret);
    // Logs carry route templates and never usernames or OPAQUE messages.
    expect(h.logs.join('\n')).not.toContain(account.username);
    // Security event details stay within their allowlists.
    const details = await query<{ details: object }>(
      h.db.url,
      `SELECT details FROM security_events`,
    );
    for (const { details: d } of details)
      for (const key of Object.keys(d))
        expect([
          'newDevice',
          'proven',
          'sessionId',
          'reason',
          'enrolledDeviceId',
          'via',
          'operation',
        ]).toContain(key);
  });

  it('never stores, logs or returns the OPAQUE server setup (INV-21)', async () => {
    const setup = readFileSync('test/fixtures/opaque-server-setup.test-only', 'utf8').trim();
    const forms = [setup, Buffer.from(setup, 'base64url').toString('hex')];
    const res = await login(account.username, SYNTHETIC_PASSWORD, account.deviceId);
    const cookie = sessionCookie(res);
    const bodies = [res.text];
    for (const path of ['/api/v1/account', '/api/v1/account/keys', '/api/v1/devices'])
      bodies.push((await h.get(path, cookie)).text);
    const tables = await query<{ table_name: string }>(
      h.db.url,
      `SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'`,
    );
    const dump: string[] = [];
    for (const { table_name: table } of tables) {
      const rows = await query<{ row: string }>(
        h.db.url,
        `SELECT row_to_json(t)::text AS row FROM "${table}" t`,
      );
      dump.push(...rows.map((r) => r.row));
    }
    const haystack = [...bodies, ...h.logs, ...dump].join('\n');
    for (const form of forms) expect(haystack).not.toContain(form);
  });

  it('stores only the SHA-256 of each 256-bit session token (INV-13)', async () => {
    const res = await login(account.username, SYNTHETIC_PASSWORD, account.deviceId);
    const token = sessionCookie(res).split('=')[1] ?? '';
    expect(Buffer.from(token, 'base64url')).toHaveLength(32);
    const rows = await query<{ hash: string; row: string }>(
      h.db.url,
      `SELECT encode(secret_hash, 'hex') AS hash, row_to_json(s)::text AS row FROM sessions s`,
    );
    const expected = createHash('sha256').update(token).digest('hex');
    expect(rows.map((r) => r.hash)).toContain(expected);
    const hex = Buffer.from(token, 'base64url').toString('hex');
    for (const { row } of rows) {
      expect(row).not.toContain(token);
      expect(row).not.toContain(hex);
    }
  });
});
