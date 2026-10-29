import { loginStartResponseSchema } from '@ruvee/contracts';
import { registerAccount, startHarness, type Harness } from '../support/api-harness.js';
import {
  startLogin,
  syntheticAccount,
  type SyntheticAccount,
} from '../support/synthetic-client.js';
import { query } from '../support/temp-database.js';

/**
 * Regression for predeployment-review R1. Before the fix, `/API/…` reached the same handlers
 * as `/api/…` while the maintenance gate, the CSRF checks and the bearer rules matched only the
 * lower-case text. Now routing is case-sensitive and strict, and those decisions come from the
 * matched handler (route-class.ts), so no spelling of a path reaches a handler unchecked.
 */
const SPELLINGS = [
  '/API/v1/account/keys',
  '/Api/v1/account/keys',
  '/api/V1/account/keys',
  '/api/v1/Account/keys',
  '/%61pi/v1/account/keys',
  '/api/v1/account/keys/',
  '/api//v1/account/keys',
  '/api/v1/./account/keys',
  '/api/v1/account/keys%2F',
];

describe('REVIEW R1 (regression): no path spelling bypasses the gate, CSRF or bearer rules', () => {
  let setup: Harness;
  let h: Harness;
  let cookie: string;
  let account: SyntheticAccount;

  beforeAll(async () => {
    setup = await startHarness();
    account = await syntheticAccount('synthetic-review-r1');
    cookie = await registerAccount(setup, account);
    // A restored installation waiting to be reopened, served by a new app process as after a
    // real restore. Restored sessions are revoked as APPLY POLICY does.
    await query(setup.db.url, `CREATE SCHEMA IF NOT EXISTS ruvee_control`);
    await query(
      setup.db.url,
      `CREATE TABLE ruvee_control.restore_guard (id smallint PRIMARY KEY, state text NOT NULL)`,
    );
    await query(setup.db.url, `INSERT INTO ruvee_control.restore_guard VALUES (1, 'reopening')`);
    // What PREPARE grants the runtime role, so the API reads `reopening`, not just "closed".
    await query(
      setup.db.url,
      `GRANT SELECT (id, state) ON ruvee_control.restore_guard TO "${setup.db.runtime.name}"`,
    );
    await query(setup.db.url, `UPDATE sessions SET revoked_at = now(), revoke_reason = 'restored'`);
    // One API process per database (S-1): the first app must stop, or it keeps the instance lock
    // and the second answers every route `server_unavailable`, never reaching the gate.
    await setup.app.close();
    vi.resetModules();
    h = await startHarness({ database: setup.db });
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  it('closes the lower-case route and serves health', async () => {
    const closed = await h.get('/api/v1/account/keys', cookie);
    expect([closed.status, (closed.body as { error?: string }).error]).toEqual([503, 'reopening']);
    expect((await h.get('/health/live')).status).toBe(200);
  });

  it('routes no other spelling to a handler', async () => {
    for (const path of SPELLINGS) {
      const res = await h.get(path, cookie);
      // 404 (no handler) or the gate's 503; never served.
      expect([404, 503], `${path}: ${String(res.status)}`).toContain(res.status);
    }
    for (const path of ['/HEALTH/live', '/health/LIVE', '/health/live/'])
      expect((await h.get(path)).status, path).toBe(404);
  });

  it('creates no session from the snapshot-time password under another spelling', async () => {
    const client = startLogin();
    for (const prefix of ['/API/v1', '/Api/v1', '/api/V1']) {
      const start = await h.post(`${prefix}/auth/login/start`, {
        username: account.username,
        startLoginRequest: client.startLoginRequest,
        platform: 'web',
        deviceId: account.deviceId,
      });
      expect(start.status, prefix).toBe(404);
    }
    // The real route is closed by the gate.
    const start = await h.post('/api/v1/auth/login/start', {
      username: account.username,
      startLoginRequest: client.startLoginRequest,
      platform: 'web',
      deviceId: account.deviceId,
    });
    expect(start.status).toBe(503);
    expect(loginStartResponseSchema.safeParse(start.body).success).toBe(false);
  });

  it('applies CSRF and the cookie-xor-bearer rule on every spelling that routes', async () => {
    // In an open installation of its own (one API process per database, S-1), with a live session.
    vi.resetModules();
    const open = await startHarness();
    try {
      const fresh = await registerAccount(open, await syntheticAccount('synthetic-review-r1-open'));
      for (const path of ['/api/v1/auth/logout', '/API/v1/auth/logout', '/Api/v1/auth/logout']) {
        const res = await open.http().post(path).set('Cookie', fresh);
        expect([403, 404], `${path}: ${String(res.status)}`).toContain(res.status);
      }
      const both = await open
        .http()
        .get('/api/v1/account/keys')
        .set('Cookie', fresh)
        .set('Authorization', `Bearer ${'A'.repeat(43)}`);
      expect(both.status).toBe(400);
    } finally {
      await open.close();
    }
  });
});
