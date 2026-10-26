import {
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  sessionResponseSchema,
} from '@ruvee/contracts';
import type request from 'supertest';
import { ThrottleService } from '../src/auth/throttle.service.js';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  type Harness,
} from './support/api-harness.js';
import { restoreSnapshot, takeSnapshot } from './support/backup-snapshot.js';
import {
  finishLogin,
  startLogin,
  SYNTHETIC_PASSWORD,
  syntheticAccount,
  type SyntheticAccount,
} from './support/synthetic-client.js';
import { query } from './support/temp-database.js';

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

/**
 * What restoring an older copy of the database brings back today (backup-restore.md §3.4). These
 * tests describe the current behaviour on purpose: they are the evidence for D-28, which decides
 * what a restore must undo. They use the format-neutral snapshot scaffolding, not a backup format.
 */
describe('restoring an older database copy (characterization, input to D-28)', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let owner: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-restore-owner');
    owner = await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  beforeEach(() => {
    h.app.get(ThrottleService).clearIpWindows();
  });

  async function loginNewDevice(): Promise<{ cookie: string; deviceId: string }> {
    const client = startLogin(SYNTHETIC_PASSWORD);
    const start = loginStartResponseSchema.parse(
      (
        await h
          .post('/api/v1/auth/login/start', {
            username: account.username,
            startLoginRequest: client.startLoginRequest,
            platform: 'web',
          })
          .expect(200)
      ).body,
    );
    const finished = finishLogin(client.clientLoginState, start.loginResponse);
    if (!finished) throw new Error('login failed');
    const res = await h
      .post('/api/v1/auth/login/finish', {
        loginId: start.loginId,
        finishLoginRequest: finished.finishLoginRequest,
      })
      .expect(200);
    return {
      cookie: sessionCookie(res),
      deviceId: sessionResponseSchema.parse(res.body).device.id,
    };
  }

  it('brings back a device, and its session, that were removed after the copy was taken', async () => {
    const other = await loginNewDevice();
    await takeSnapshot(h.db.url);

    // After the backup: the device is removed (here directly; the API path is tested elsewhere).
    await query(
      h.db.url,
      `UPDATE devices SET status = 'revoked', revoked_at = now() WHERE id = $1`,
      [other.deviceId],
    );
    await query(
      h.db.url,
      `UPDATE sessions SET revoked_at = now(), revoke_reason = 'device_revoked'
       WHERE device_id = $1 AND revoked_at IS NULL`,
      [other.deviceId],
    );
    expectError(await h.get('/api/v1/devices/current', other.cookie), 'device_revoked');

    await restoreSnapshot(h.db.url);
    // Today the restored server knows nothing of the removal: the old session works again.
    await h.get('/api/v1/devices/current', other.cookie).expect(200);
    await h.get('/api/v1/devices/current', owner).expect(200);
  });

  it('forgets every security event recorded after the copy was taken', async () => {
    await takeSnapshot(h.db.url);
    const before = await query<{ n: string }>(
      h.db.url,
      'SELECT count(*) AS n FROM security_events',
    );
    await loginNewDevice();
    const after = await query<{ n: string }>(h.db.url, 'SELECT count(*) AS n FROM security_events');
    expect(Number(after[0]?.n)).toBeGreaterThan(Number(before[0]?.n));
    await restoreSnapshot(h.db.url);
    const restored = await query<{ n: string }>(
      h.db.url,
      'SELECT count(*) AS n FROM security_events',
    );
    expect(restored[0]?.n).toBe(before[0]?.n);
  });

  // The behaviour M1 must have once D-28 is decided (backup-restore.md §3.4 and §6).
  it.todo('after a restore, every cookie and token session is ended (D-28)');
  it.todo('after a restore, open pairings and recovery sessions are gone (D-28)');
  it.todo('after a restore, a server_restored event and a device review are required (D-28)');
});
