import {
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  sessionResponseSchema,
  tokenPairSchema,
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
 * What restoring an older copy of the database brings back today (backup-restore.md §3.7). These
 * tests describe the current behaviour on purpose: they are the evidence for D-28, which decides
 * what a restore must undo. They use the format-neutral snapshot scaffolding, not a backup format.
 */
describe('restoring a raw older database copy (characterization, why D-28 exists)', () => {
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

  it('brings back a refresh token that was rotated after the copy, and forgets the newer one', async () => {
    const EXT = {
      Origin: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop',
      'X-Ruvee-Request': '1',
    };
    const client = startLogin(SYNTHETIC_PASSWORD);
    const start = loginStartResponseSchema.parse(
      (
        await h
          .http()
          .post('/api/v1/auth/login/start')
          .set(EXT)
          .send({
            username: account.username,
            startLoginRequest: client.startLoginRequest,
            platform: 'extension',
          })
          .expect(200)
      ).body,
    );
    const finished = finishLogin(client.clientLoginState, start.loginResponse);
    if (!finished) throw new Error('login failed');
    const first = tokenPairSchema.parse(
      sessionResponseSchema.parse(
        (
          await h
            .http()
            .post('/api/v1/auth/login/finish')
            .set(EXT)
            .send({ loginId: start.loginId, finishLoginRequest: finished.finishLoginRequest })
            .expect(200)
        ).body,
      ).tokens,
    );
    await takeSnapshot(h.db.url);
    const refresh = (refreshToken: string) =>
      h.http().post('/api/v1/auth/refresh').set(EXT).send({ refreshToken });
    const second = tokenPairSchema.parse((await refresh(first.refreshToken).expect(200)).body);

    await restoreSnapshot(h.db.url);
    // The rotation never happened as far as the restored server knows.
    expectError(await refresh(second.refreshToken), 'unauthenticated');
    expect((await refresh(first.refreshToken)).status).toBe(200);
  });

  it('brings back a recovery session that was ended after the copy', async () => {
    const rk = account.crypto.parseRecoveryKey(account.recoveryKeyText);
    const { recoveryAuthKey } = account.crypto.deriveRecoveryKeys(rk);
    const started = await h
      .post('/api/v1/recovery/start', {
        username: account.username,
        recoveryAuthKey: Buffer.from(recoveryAuthKey).toString('base64url'),
        device: { id: account.crypto.generateUuid(), platform: 'web' },
      })
      .expect(200);
    const cookie =
      (started.headers['set-cookie'] as unknown as string[])
        .find((c) => c.startsWith('__Host-ruvee_recovery='))
        ?.split(';')[0] ?? '';
    await takeSnapshot(h.db.url);
    await query(
      h.db.url,
      `UPDATE sessions SET revoked_at = now(), revoke_reason = 'user'
       WHERE kind = 'recovery' AND revoked_at IS NULL`,
    );
    expectError(await h.get('/api/v1/recovery/material', cookie), 'unauthenticated');
    await restoreSnapshot(h.db.url);
    await h.get('/api/v1/recovery/material', cookie).expect(200);
  });

  // What the restore tool does about all of this (revised D-28, backup-restore.md §3.6) is tested
  // with real dumps in restore.int-spec.ts and restore-edges.int-spec.ts. These tests stay: they
  // show why the tool's policy step is needed, because a raw database copy undoes nothing.
});
