import { uuidToBytes } from '@ruvee/crypto';
import {
  API_ERRORS,
  errorResponseSchema,
  recoveryMaterialResponseSchema,
  recoveryStartResponseSchema,
  registerStartResponseSchema,
} from '@ruvee/contracts';
import type request from 'supertest';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  type Harness,
} from '../support/api-harness.js';
import { loginDevice, signCompletion } from '../support/device-proof.js';
import {
  finishRegistration,
  startRegistration,
  syntheticAccount,
  type SyntheticAccount,
} from '../support/synthetic-client.js';
import { query } from '../support/temp-database.js';

/**
 * Accounts from before D-31 have no `AVPK` (docs/security/device-proof.md §9, owner decision of
 * 2026-10-27): no caller establishes one, whether it holds the Recovery Key's auth value, the
 * password, or even `AK`. The account stays synthetic-only and moves by export and import.
 * Reopening a pre-D-31 snapshot is covered in `reopen.int-spec.ts`. Synthetic data only.
 */

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));
const NEW_PASSWORD = 'synthetic legacy passphrase 5e2d';

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

function recoveryCookie(res: request.Response): string {
  const header = res.headers['set-cookie'] as unknown as string[] | undefined;
  const cookie = header?.find((c) => c.startsWith('__Host-ruvee_recovery='));
  if (!cookie) throw new Error('no recovery cookie');
  return cookie.split(';')[0] ?? '';
}

describe('a pre-D-31 account never acquires a trusted AVPK (real database)', () => {
  let h: Harness;
  let account: SyntheticAccount;

  /** Everything recovery or reopening would replace, and the trust anchor. */
  const keysRow = () =>
    query<Record<string, unknown>>(
      h.db.url,
      `SELECT row_version, salt_pw, wrapped_ak_password, recovery_key_id, wrapped_ak_recovery,
              recovery_verifier, ak_verify_key FROM account_keys`,
    );
  const devicesRow = () =>
    query<Record<string, unknown>>(
      h.db.url,
      'SELECT id, status, public_key FROM devices ORDER BY id',
    );
  const asLegacy = async () => {
    await query(h.db.url, 'UPDATE account_keys SET ak_verify_key = NULL');
    await query(h.db.url, 'UPDATE devices SET public_key = NULL');
  };

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-legacy-owner');
    await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  beforeEach(async () => {
    const { ThrottleService } = await import('../../src/auth/throttle.service.js');
    h.app.get(ThrottleService).clearIpWindows();
    await query(h.db.url, 'DELETE FROM auth_throttle');
    // Each test starts from a D-31 account and turns it into a legacy one where it needs to.
    await query(h.db.url, 'UPDATE account_keys SET ak_verify_key = $1', [
      Buffer.from(account.akVerifyKey),
    ]);
    await query(h.db.url, 'UPDATE devices SET public_key = $1 WHERE id = $2', [
      Buffer.from(account.deviceKey.publicKey),
      account.deviceId,
    ]);
  });

  const rak = () =>
    account.crypto.deriveRecoveryKeys(account.crypto.parseRecoveryKey(account.recoveryKeyText));
  const start = (deviceId = account.crypto.generateUuid()) =>
    h.post('/api/v1/recovery/start', {
      username: account.username,
      recoveryAuthKey: b64(rak().recoveryAuthKey),
      device: { id: deviceId, platform: 'web' },
    });

  /** A complete, well-formed recovery completion, as the client builds it. */
  async function completionFields(cookie: string) {
    const { crypto } = account;
    const keys = rak();
    const material = recoveryMaterialResponseSchema.parse(
      (await h.get('/api/v1/recovery/material', cookie).expect(200)).body,
    );
    const accountId = uuidToBytes(account.accountId);
    const reg = startRegistration(NEW_PASSWORD);
    const regStart = await h
      .post(
        '/api/v1/recovery/password/start',
        { registrationRequest: reg.registrationRequest },
        cookie,
      )
      .expect(200);
    const record = finishRegistration(
      reg.clientRegistrationState,
      registerStartResponseSchema.parse(regStart.body).registrationResponse,
      NEW_PASSWORD,
    );
    const ak = crypto.unwrapAccountKeyForRecovery({
      recoveryWrapKey: keys.recoveryWrapKey,
      recoveryKeyId: unb64(material.recoveryKeyId),
      accountId,
      accountKeyId: unb64(material.akId),
      accountKeyEpoch: material.akEpoch,
      envelope: unb64(material.wrappedAkRecovery),
    });
    const saltPw = crypto.generatePasswordSalt();
    const auk = crypto.deriveAccountUnlockKey({
      password: NEW_PASSWORD,
      passwordSalt: saltPw,
      profile: 1,
      secretKey: account.secretKey,
      accountId,
    });
    const rotated = crypto.generateRecoveryKey();
    const rotatedKeys = crypto.deriveRecoveryKeys(rotated.recoveryKey);
    return {
      registrationRecord: record,
      kdfProfile: 1,
      saltPw: b64(saltPw),
      wrappedAkPassword: b64(
        crypto.wrapAccountKey({
          accountUnlockKey: auk,
          accountKey: ak,
          accountId,
          accountKeyId: unb64(material.akId),
          accountKeyEpoch: material.akEpoch,
          profile: 1,
          passwordSalt: saltPw,
        }),
      ),
      recoveryKeyId: b64(rotated.recoveryKeyId),
      wrappedAkRecovery: b64(
        crypto.wrapAccountKeyForRecovery({
          recoveryWrapKey: rotatedKeys.recoveryWrapKey,
          recoveryKeyId: rotated.recoveryKeyId,
          accountId,
          accountKeyId: unb64(material.akId),
          accountKeyEpoch: material.akEpoch,
          accountKey: ak,
        }),
      ),
      recoveryVerifier: b64(crypto.recoveryVerifier(rotatedKeys.recoveryAuthKey)),
      expectedRowVersion: material.rowVersion,
    };
  }

  it('refuses recovery at its start, before a device or a session exists', async () => {
    await asLegacy();
    const [keys, devices] = [await keysRow(), await devicesRow()];
    const deviceId = account.crypto.generateUuid();
    const res = await start(deviceId);
    expectError(res, 'migration_required');
    expect(res.headers['set-cookie']).toBeUndefined();
    expect(await keysRow()).toEqual(keys);
    expect(await devicesRow()).toEqual(devices);
    expect(
      await query(
        h.db.url,
        `SELECT 1 FROM sessions WHERE kind = 'recovery' AND revoked_at IS NULL`,
      ),
    ).toEqual([]);
  });

  it('refuses a completion with an attacker-selected AVPK, and one with AK’s own', async () => {
    // A recovery started while the account had its AVPK, completed after it is gone: the
    // completion check alone must hold.
    const started = await start();
    expect(started.status, started.text).toBe(200);
    const cookie = recoveryCookie(started);
    const deviceId = recoveryStartResponseSchema.parse(started.body).deviceId;
    const fields = await completionFields(cookie);
    await asLegacy();
    const [keys, devices] = [await keysRow(), await devicesRow()];
    const deviceKey = account.crypto.generateDeviceKey();
    // Someone with RAK but not AK signs with a key of their choosing; before this change the
    // server took the AVPK the request carried and installed the attacker's wraps.
    const attacker = await signCompletion(h, account, cookie, 'recovery_complete', fields, {
      deviceKey,
      deviceId,
      accountKey: account.crypto.generateKey(),
    });
    expectError(await h.post('/api/v1/recovery/complete', attacker, cookie), 'migration_required');
    // Even AK's own proof does not make the presented key the anchor (fresh-account strategy).
    const owner = await signCompletion(h, account, cookie, 'recovery_complete', fields, {
      deviceKey,
      deviceId,
    });
    expectError(await h.post('/api/v1/recovery/complete', owner, cookie), 'migration_required');
    expect(await keysRow()).toEqual(keys);
    expect(await devicesRow()).toEqual(devices);
  });

  it('gives a password-only caller no proven session and no tier-3 operation', async () => {
    await asLegacy();
    const keys = await keysRow();
    // The device has no DPK: any key it signs with is refused.
    const proven = await loginDevice(h, account, { deviceKey: account.crypto.generateDeviceKey() });
    expect(proven.status).not.toBe(200);
    const res = await loginDevice(h, account, { prove: false });
    expect(res.status, res.text).toBe(200);
    const cookie = sessionCookie(res);
    for (const [method, path] of [
      ['post', '/api/v1/account/password/start'],
      ['post', '/api/v1/account/password/finish'],
      ['post', '/api/v1/account/secret-key'],
      ['put', '/api/v1/account/recovery'],
      ['post', '/api/v1/pairings'],
    ] as const) {
      const r =
        method === 'put'
          ? await h
              .http()
              .put(path)
              .set({ Cookie: cookie, Origin: 'http://127.0.0.1:3100', 'X-Ruvee-Request': '1' })
              .send({})
          : await h.post(path, {}, cookie);
      expectError(r, 'device_proof_required');
    }
    for (const operation of ['password_change_v2', 'secret_key_rotate', 'recovery_key_rotate'])
      expect((await h.post('/api/v1/auth/proof-nonce', { operation }, cookie)).status).not.toBe(
        200,
      );
    // And a session proof cannot succeed without a registered DPK.
    expect((await h.post('/api/v1/auth/session-proof', {}, cookie)).status).not.toBe(200);
    expect(await keysRow()).toEqual(keys);
  });

  it('a D-31 account keeps its AVPK through recovery: a replacement is refused', async () => {
    const before = await keysRow();
    const started = await start();
    const cookie = recoveryCookie(started);
    const deviceId = recoveryStartResponseSchema.parse(started.body).deviceId;
    const fields = await completionFields(cookie);
    const forged = await signCompletion(h, account, cookie, 'recovery_complete', fields, {
      deviceKey: account.crypto.generateDeviceKey(),
      deviceId,
      accountKey: account.crypto.generateKey(),
    });
    expectError(await h.post('/api/v1/recovery/complete', forged, cookie), 'device_key_mismatch');
    expect(await keysRow()).toEqual(before);
  });
});
