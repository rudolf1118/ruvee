import { query } from '../support/temp-database.js';
import { registerAccount, startHarness, type Harness } from '../support/api-harness.js';
import { syntheticAccount, type SyntheticAccount } from '../support/synthetic-client.js';

/**
 * Pre-deployment review, finding R1 (docs/security/predeployment-review.md): the maintenance
 * gate and the CSRF/bearer rules match `/api/` case-sensitively, but routing is not. These
 * tests describe the CURRENT behaviour and are expected to fail once R1 is fixed; then turn
 * them into assertions of the fixed behaviour.
 */
describe('REVIEW R1: upper-case paths bypass the maintenance gate and CSRF checks', () => {
  let setup: Harness;
  let h: Harness;
  let cookie: string;
  let freshCookie = '';
  let account: SyntheticAccount;

  beforeAll(async () => {
    setup = await startHarness();
    account = await syntheticAccount('synthetic-review-r1');
    cookie = await registerAccount(setup, account);
    // A restored installation waiting to be reopened: the guard row is all the gate reads. A
    // new app process on the same database, as after a real restore (the gate caches `open`).
    await query(
      setup.db.url,
      `CREATE TABLE ruvee_restore_guard (id smallint PRIMARY KEY, state text NOT NULL)`,
    );
    await query(setup.db.url, `INSERT INTO ruvee_restore_guard VALUES (1, 'reopening')`);
    // As APPLY POLICY does: every restored session is revoked.
    await query(setup.db.url, `UPDATE sessions SET revoked_at = now(), revoke_reason = 'restored'`);
    vi.resetModules();
    h = await startHarness({ database: setup.db });
  }, 60_000);

  afterAll(async () => {
    await h.close();
    await setup.close();
  });

  it('closes the lower-case route', async () => {
    const res = await h.get('/api/v1/account/keys', cookie);
    expect(res.status).toBe(503);
  });

  it('still refuses a revoked restored cookie in upper case (revocation holds)', async () => {
    const res = await h.get('/API/v1/account/keys', cookie);
    expect(res.status, res.text).toBe(401);
  });

  it('creates a full session from the snapshot-time password, with no reopening code (R1, vulnerable)', async () => {
    const { startLogin, finishLogin } = await import('../support/synthetic-client.js');
    const { loginStartResponseSchema } = await import('@ruvee/contracts');
    const client = startLogin();
    const start = await h.post('/API/v1/auth/login/start', {
      username: 'synthetic-review-r1',
      startLoginRequest: client.startLoginRequest,
      platform: 'web',
      // Device ids are server-visible metadata, not secrets (api-design.md); see also R2.
      deviceId: account.deviceId,
    });
    expect(start.status, start.text).toBe(200);
    const parsed = loginStartResponseSchema.parse(start.body);
    const finished = finishLogin(client.clientLoginState, parsed.loginResponse);
    const finish = await h.post('/API/v1/auth/login/finish', {
      loginId: parsed.loginId,
      finishLoginRequest: finished?.finishLoginRequest,
    });
    expect(finish.status, finish.text).toBe(200);
    // ...and that session reads the vault while the installation is still closed.
    const fresh = (finish.headers['set-cookie'] as unknown as string[])
      .find((c) => c.includes('ruvee_session='))
      ?.split(';')[0];
    freshCookie = fresh ?? '';
    const keys = await h.get('/API/v1/account/keys', freshCookie);
    expect(keys.status, keys.text).toBe(200);
    expect((await h.get('/api/v1/account/keys', freshCookie)).status).toBe(503);
    const spellings: Record<string, number> = Object.fromEntries(
      await Promise.all(
        [
          '/Api/v1/account/keys',
          '/%61pi/v1/account/keys',
          '/api//v1/account/keys',
          '/api/v1/account/keys/',
        ].map(async (p) => [p, (await h.get(p, freshCookie)).status] as const),
      ),
    );
    // Only a change of case gets through; encoded, doubled or trailing variants do not.
    expect(spellings).toEqual({
      '/Api/v1/account/keys': 200,
      '/%61pi/v1/account/keys': 404,
      '/api//v1/account/keys': 404,
      '/api/v1/account/keys/': 503,
    });
  });

  it('accepts a state-changing request without Origin or the CSRF header (R1, vulnerable)', async () => {
    // Bodyless POST, no Origin, no X-Ruvee-Request. In the open state (the `setup` app) the
    // lower-case route is refused as CSRF and the upper-case one is served.
    const lower = await setup.http().post('/api/v1/auth/logout').set('Cookie', freshCookie);
    expect(lower.status).toBe(403);
    const upper = await setup.http().post('/API/v1/auth/logout').set('Cookie', freshCookie);
    expect(upper.status, upper.text).toBe(204);
  });
});
