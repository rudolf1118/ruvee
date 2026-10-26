import {
  accountKeysResponseSchema,
  loginStartResponseSchema,
  registerStartResponseSchema,
  sessionResponseSchema,
} from '@ruvee/contracts';
import { registerAccount, startHarness, type Harness } from '../support/api-harness.js';
import {
  startLogin,
  syntheticAccount,
  type SyntheticAccount,
} from '../support/synthetic-client.js';
import { finishLogin, finishRegistration, startRegistration } from '../support/synthetic-client.js';

const ATTACKER_PASSWORD = 'synthetic attacker chosen passphrase 1';

/**
 * Pre-deployment review, findings R2 and R3 (docs/security/predeployment-review.md). These tests
 * describe the CURRENT behaviour and are expected to fail once the findings are fixed.
 */
describe('REVIEW R2/R3: login device binding and the per-username throttle', () => {
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

  it('R3: guesses started in parallel are all checked, past the five-failure limit', async () => {
    const wrong = 'synthetic wrong guess 00';
    // Twelve logins started before any failure is recorded: the throttle is checked at start.
    const starts = await Promise.all(
      Array.from({ length: 12 }, async () => {
        const client = startLogin(wrong);
        const res = await h.post('/api/v1/auth/login/start', {
          username: account.username,
          startLoginRequest: client.startLoginRequest,
          platform: 'web',
        });
        return loginStartResponseSchema.parse(res.body).loginId;
      }),
    );
    // The per-IP limit (20 a minute) is real but per address; an attacker with a few addresses
    // has a fresh window for each, so it is reset here to isolate the per-username throttle.
    const { ThrottleService } = await import('../../src/auth/throttle.service.js');
    const clearIp = () => {
      h.app.get(ThrottleService).clearIpWindows();
    };
    clearIp();
    const finishes = [];
    for (const loginId of starts)
      finishes.push(
        (
          await h.post('/api/v1/auth/login/finish', {
            loginId,
            finishLoginRequest: Buffer.alloc(64, 1).toString('base64url'),
          })
        ).status,
      );
    // Every one of the twelve was evaluated (401), none refused as rate_limited (429)...
    expect(finishes).toEqual(Array(12).fill(401));
    // ...although a new start is now blocked.
    clearIp();
    const after = await h.post('/api/v1/auth/login/start', {
      username: account.username,
      startLoginRequest: startLogin(wrong).startLoginRequest,
      platform: 'web',
    });
    expect(after.status).toBe(429);
  });
});
