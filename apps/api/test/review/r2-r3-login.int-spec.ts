import {
  accountKeysResponseSchema,
  loginStartResponseSchema,
  registerStartResponseSchema,
  sessionResponseSchema,
} from '@ruvee/contracts';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  WRITE_HEADERS,
  type Harness,
} from '../support/api-harness.js';
import { query } from '../support/temp-database.js';
import {
  startLogin,
  syntheticAccount,
  type SyntheticAccount,
} from '../support/synthetic-client.js';
import { finishLogin, finishRegistration, startRegistration } from '../support/synthetic-client.js';

const ATTACKER_PASSWORD = 'synthetic attacker chosen passphrase 1';

/**
 * Pre-deployment review, findings R2 and R3 (docs/security/predeployment-review.md). The R2 tests
 * describe the CURRENT behaviour (R2 is open, D-31 proposed) and are expected to fail once it is
 * fixed. The R3 tests below are regressions: the throttle holds under parallel requests.
 */
describe('REVIEW R2: login device binding (open)', () => {
  let h: Harness;
  let account: SyntheticAccount;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-review-r2');
    await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  beforeEach(async () => {
    const { ThrottleService } = await import('../../src/auth/throttle.service.js');
    h.app.get(ThrottleService).clearIpWindows();
  });

  it('R2: the password plus a known device id yields an ACTIVE device, with no device secret', async () => {
    // A fresh client that holds no key: only the password and the (non-secret) device id.
    const client = startLogin();
    const start = await h.post('/api/v1/auth/login/start', {
      username: account.username,
      startLoginRequest: client.startLoginRequest,
      platform: 'web',
      deviceId: account.deviceId,
    });
    const parsed = loginStartResponseSchema.parse(start.body);
    const finished = finishLogin(client.clientLoginState, parsed.loginResponse);
    const res = await h.post('/api/v1/auth/login/finish', {
      loginId: parsed.loginId,
      finishLoginRequest: finished?.finishLoginRequest,
    });
    expect(sessionResponseSchema.parse(res.body).device).toEqual({
      id: account.deviceId,
      status: 'active',
    });
    // An active session: the full key material, and step-up is one more OPAQUE run away.
    const cookie = (res.headers['set-cookie'] as unknown as string[])[0]?.split(';')[0] ?? '';
    expect((await h.get('/api/v1/account/keys', cookie)).status).toBe(200);
  });

  it('R2: that session can replace the password with a junk wrap, locking the owner out', async () => {
    // Password only: no SK, no AK. Log in as the known device, step up, change the password.
    const loginAs = async () => {
      const client = startLogin();
      const start = loginStartResponseSchema.parse(
        (
          await h.post('/api/v1/auth/login/start', {
            username: account.username,
            startLoginRequest: client.startLoginRequest,
            platform: 'web',
            deviceId: account.deviceId,
          })
        ).body,
      );
      const finished = finishLogin(client.clientLoginState, start.loginResponse);
      const res = await h.post('/api/v1/auth/login/finish', {
        loginId: start.loginId,
        finishLoginRequest: finished?.finishLoginRequest,
      });
      return (res.headers['set-cookie'] as unknown as string[])[0]?.split(';')[0] ?? '';
    };
    const cookie = await loginAs();
    const client = startLogin();
    const reauth = loginStartResponseSchema.parse(
      (
        await h.post(
          '/api/v1/auth/reauth/start',
          { startLoginRequest: client.startLoginRequest },
          cookie,
        )
      ).body,
    );
    const up = finishLogin(client.clientLoginState, reauth.loginResponse);
    expect(
      (
        await h.post(
          '/api/v1/auth/reauth/finish',
          { loginId: reauth.loginId, finishLoginRequest: up?.finishLoginRequest },
          cookie,
        )
      ).status,
    ).toBe(200);
    const keys = accountKeysResponseSchema.parse(
      (await h.get('/api/v1/account/keys', cookie)).body,
    );
    const reg = startRegistration(ATTACKER_PASSWORD);
    const regStart = await h.post(
      '/api/v1/account/password/start',
      { registrationRequest: reg.registrationRequest },
      cookie,
    );
    const record = finishRegistration(
      reg.clientRegistrationState,
      registerStartResponseSchema.parse(regStart.body).registrationResponse,
      ATTACKER_PASSWORD,
    );
    // A "wrap" that keeps the real header (purpose, key id) and replaces the ciphertext: it
    // wraps nothing. The server checks only the header.
    const junk = Buffer.from(keys.wrappedAkPassword, 'base64url');
    junk.fill(0x41, 40);
    const res = await h.post(
      '/api/v1/account/password/finish',
      {
        registrationRecord: record,
        kdfProfile: 1,
        saltPw: Buffer.alloc(16, 2).toString('base64url'),
        wrappedAkPassword: junk.toString('base64url'),
        expectedRowVersion: keys.rowVersion,
      },
      cookie,
    );
    expect(res.status, res.text).toBe(204);
    // The owner's password no longer logs in; the server's password wrap opens nothing.
    const owner = startLogin();
    const start = loginStartResponseSchema.parse(
      (
        await h.post('/api/v1/auth/login/start', {
          username: account.username,
          startLoginRequest: owner.startLoginRequest,
          platform: 'web',
        })
      ).body,
    );
    expect(finishLogin(owner.clientLoginState, start.loginResponse)).toBeUndefined();
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
    const cookie = sessionCookie(
      await post('/api/v1/auth/login/finish', {
        loginId: start.loginId,
        finishLoginRequest: finished?.finishLoginRequest,
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
