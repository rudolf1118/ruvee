import {
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  RECOVERY_COOKIE_SECURE,
  REOPEN_COOKIE_SECURE,
  SESSION_COOKIE_SECURE,
  sessionResponseSchema,
} from '@ruvee/contracts';
import type request from 'supertest';
import { ThrottleService } from '../../src/auth/throttle.service.js';
import { registerAccount, startHarness, type Harness } from '../support/api-harness.js';
import {
  finishLogin,
  startLogin,
  SYNTHETIC_PASSWORD,
  syntheticAccount,
  type SyntheticAccount,
} from '../support/synthetic-client.js';

/**
 * Follow-up review F-6: an `Authorization` header exempts a request from the CSRF checks only on
 * routes where that bearer token is the credential the guard then checks. On the unauthenticated
 * routes a header of any value (fake, real, malformed) changes nothing, and no request may carry a
 * cookie of any kind together with a bearer token. Synthetic data only.
 */

const WEB = { Origin: 'http://127.0.0.1:3100', 'X-Ruvee-Request': '1' } as const;
const EXTENSION = {
  Origin: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop',
  'X-Ruvee-Request': '1',
} as const;
const FAKE = `Bearer ${'A'.repeat(43)}`;

/** Every state-changing route of access level `none`, outside health. */
const UNAUTHENTICATED_WRITES = [
  '/api/v1/auth/register/start',
  '/api/v1/auth/register/finish',
  '/api/v1/auth/login/start',
  '/api/v1/auth/login/finish',
  '/api/v1/auth/refresh',
  '/api/v1/recovery/start',
  '/api/v1/reopen/login/start',
  '/api/v1/reopen/login/finish',
  '/api/v1/reopen/recovery/start',
] as const;

function errorOf(res: request.Response): string | undefined {
  const parsed = errorResponseSchema.safeParse(res.body);
  return parsed.success ? parsed.data.error : undefined;
}

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorOf(res)).toBe(code);
}

describe('F-6: CSRF and bearer tokens are decided together (real database)', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let webCookie: string;
  let accessToken: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-f6-owner');
    webCookie = await registerAccount(h, account);
    // A real token session, as the extension gets one.
    const client = startLogin(SYNTHETIC_PASSWORD);
    const start = await h
      .http()
      .post('/api/v1/auth/login/start')
      .set(EXTENSION)
      .send({
        username: account.username,
        startLoginRequest: client.startLoginRequest,
        platform: 'extension',
      })
      .expect(200);
    const parsed = loginStartResponseSchema.parse(start.body);
    const finished = finishLogin(client.clientLoginState, parsed.loginResponse);
    if (!finished) throw new Error('login rejected');
    const res = await h
      .http()
      .post('/api/v1/auth/login/finish')
      .set(EXTENSION)
      .send({ loginId: parsed.loginId, finishLoginRequest: finished.finishLoginRequest })
      .expect(200);
    accessToken = sessionResponseSchema.parse(res.body).tokens?.accessToken ?? '';
    expect(accessToken).not.toBe('');
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  beforeEach(() => {
    h.app.get(ThrottleService).clearIpWindows();
  });

  const post = (path: string, headers: Record<string, string>) =>
    h.http().post(path).set(headers).send({});

  describe.each(UNAUTHENTICATED_WRITES)('%s', (path) => {
    it('refuses a request with no Origin and no CSRF header', async () => {
      expectError(await post(path, {}), 'csrf_rejected');
    });

    it('refuses a fake bearer-shaped header with no Origin and no CSRF header', async () => {
      expectError(await post(path, { Authorization: FAKE }), 'csrf_rejected');
    });

    it('refuses a real access token with no Origin and no CSRF header', async () => {
      expectError(await post(path, { Authorization: `Bearer ${accessToken}` }), 'csrf_rejected');
    });

    it('refuses a fake bearer header from a foreign origin', async () => {
      expectError(
        await post(path, {
          Authorization: FAKE,
          Origin: 'https://evil.example',
          'X-Ruvee-Request': '1',
        }),
        'csrf_rejected',
      );
    });

    it('refuses a malformed Authorization header', async () => {
      for (const value of [
        'Bearer short',
        `Basic ${'A'.repeat(43)}`,
        `Bearer ${'A'.repeat(43)} x`,
        '',
      ])
        expectError(await post(path, { ...WEB, Authorization: value }), 'unauthenticated');
    });

    it('refuses a bearer header together with any cookie', async () => {
      for (const name of [SESSION_COOKIE_SECURE, RECOVERY_COOKIE_SECURE, REOPEN_COOKIE_SECURE])
        expectError(
          await post(path, { ...WEB, Authorization: FAKE, Cookie: `${name}=${'B'.repeat(43)}` }),
          'invalid_request',
        );
    });

    it('lets a well-formed request through the guard whatever the header', async () => {
      for (const headers of [WEB, { ...WEB, Authorization: FAKE }]) {
        const res = await post(path, headers);
        expect(['csrf_rejected', 'unauthenticated']).not.toContain(errorOf(res));
      }
    });
  });

  it('refuses a cookie of any kind with a bearer token before the handler sees a valid body', async () => {
    // A complete body, so the handler would answer recovery_failed if the guard let it through.
    const body = {
      username: 'nobody-at-all',
      recoveryAuthKey: 'A'.repeat(43),
      device: { id: account.crypto.generateUuid(), platform: 'web' },
    };
    expect(errorOf(await h.http().post('/api/v1/recovery/start').set(WEB).send(body))).toBe(
      'recovery_failed',
    );
    for (const name of [SESSION_COOKIE_SECURE, RECOVERY_COOKIE_SECURE, REOPEN_COOKIE_SECURE])
      for (const headers of [{}, WEB])
        expectError(
          await h
            .http()
            .post('/api/v1/recovery/start')
            .set({ ...headers, Authorization: FAKE, Cookie: `${name}=${'B'.repeat(43)}` })
            .send(body),
          'invalid_request',
        );
  });

  it('still exempts a real bearer token on an authenticated route', async () => {
    const res = await h
      .http()
      .get('/api/v1/devices/current')
      .set('Authorization', `Bearer ${accessToken}`);
    expect(res.status, res.text).toBe(200);
    // With no Origin and no CSRF header: the token is the credential, so CSRF does not apply.
    const out = await h
      .http()
      .post('/api/v1/auth/logout')
      .set('Authorization', `Bearer ${accessToken}`)
      .send({});
    expect(out.status, out.text).toBeLessThan(300);
  });

  it('refuses a fake bearer token on an authenticated route as unauthenticated', async () => {
    expectError(
      await h.http().post('/api/v1/auth/logout').set('Authorization', FAKE).send({}),
      'unauthenticated',
    );
  });

  it('refuses a bearer token together with the session cookie on an authenticated route', async () => {
    expectError(
      await h
        .http()
        .post('/api/v1/auth/logout')
        .set({ Authorization: `Bearer ${accessToken}`, Cookie: webCookie })
        .send({}),
      'invalid_request',
    );
  });

  it('refuses a bearer token on recovery routes, which are cookie-only', async () => {
    expectError(
      await h
        .http()
        .post('/api/v1/recovery/proof-nonce')
        .set({ ...WEB, Authorization: `Bearer ${accessToken}` })
        .send({}),
      'unauthenticated',
    );
  });

  it('the cookie session itself still needs Origin and the CSRF header', async () => {
    expectError(
      await h.http().post('/api/v1/auth/logout').set('Cookie', webCookie).send({}),
      'csrf_rejected',
    );
  });
});
