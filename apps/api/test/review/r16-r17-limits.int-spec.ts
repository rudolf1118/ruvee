import { loginStartResponseSchema } from '@ruvee/contracts';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  type Harness,
} from '../support/api-harness.js';
import {
  finishLogin,
  startLogin,
  syntheticAccount,
  type SyntheticAccount,
} from '../support/synthetic-client.js';

/**
 * Regressions for predeployment-review R16 (no per-session request limit) and R17 (behind a
 * proxy with no TRUSTED_PROXY_ADDRESS nothing said so). Synthetic data only.
 */
describe('REVIEW R16/R17 (regression): per-session limit and the proxy warning', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let cookie: string;

  beforeAll(async () => {
    // Warnings are what this file checks; TRUSTED_PROXY_ADDRESS stays unset on purpose.
    process.env.LOG_LEVEL = 'warn';
    delete process.env.TRUSTED_PROXY_ADDRESS;
    vi.resetModules();
    h = await startHarness();
    account = await syntheticAccount('synthetic-review-r16');
    cookie = await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    process.env.LOG_LEVEL = 'silent';
    await h.close();
  });

  it('R16: answers 429 after 300 authenticated requests a minute on one session only', async () => {
    const statuses: number[] = [];
    // Registration's own requests were unauthenticated: the session starts with a full window.
    for (let i = 0; i < 301; i++)
      statuses.push((await h.get('/api/v1/account/keys', cookie)).status);
    expect(statuses.slice(0, 300).every((s) => s === 200)).toBe(true);
    expect(statuses[300]).toBe(429);
    const limited = await h.get('/api/v1/account/keys', cookie);
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);

    // Another session of the same account is not affected.
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
    const other = sessionCookie(
      await h.post('/api/v1/auth/login/finish', {
        loginId: start.loginId,
        finishLoginRequest: finished?.finishLoginRequest,
      }),
    );
    expect((await h.get('/api/v1/account/keys', other)).status).toBe(200);
  }, 60_000);

  it('R17: warns once, without the header value, when X-Forwarded-For arrives with no trusted proxy', async () => {
    const warnings = () => h.logs.filter((l) => l.includes('TRUSTED_PROXY_ADDRESS is not set'));
    expect(warnings()).toEqual([]);
    for (let i = 0; i < 3; i++)
      await h.http().get('/health/live').set('X-Forwarded-For', '203.0.113.77');
    expect(warnings()).toHaveLength(1);
    expect(warnings()[0]).not.toContain('203.0.113.77');
  });
});
