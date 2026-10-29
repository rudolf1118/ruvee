import { uuidToBytes, type ProofField } from '@ruvee/crypto';
import {
  accountKeysResponseSchema,
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  registerStartResponseSchema,
  sessionResponseSchema,
  type AccountKeysResponse,
  type ProofNonceResponse,
} from '@ruvee/contracts';
import type request from 'supertest';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  type Harness as Server,
} from '../support/api-harness.js';
import {
  finishLogin,
  finishRegistration,
  startLogin,
  startRegistration,
  syntheticAccount,
  type SyntheticAccount,
} from '../support/synthetic-client.js';
import { loginDevice, proofNonce, signOperation } from '../support/device-proof.js';
import { query } from '../support/temp-database.js';

/**
 * Follow-up review S-4: how a proof nonce (device-proof.md §6) behaves across every way a signed
 * request can end. A nonce is consumed in the same transaction as the operation's effect
 * (`ProofService.spend`). When the operation itself refuses after a valid proof, the nonce is
 * spent anyway (option B, owner decision 2026-10-28); a failure that decided nothing leaves it for
 * the identical retry. The password change (op 12) and device revocation (op 7) are the
 * representative operations; every nonce-consuming operation goes through the same `spend`.
 * Synthetic accounts only.
 */
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));
const NEW_PASSWORD = 'synthetic s4 passphrase 3b7d';

interface PasswordBody {
  registrationRecord: string;
  kdfProfile: number;
  saltPw: string;
  wrappedAkPassword: string;
  expectedRowVersion: number;
  keysetVersion: number;
}

const passwordFields = (b: PasswordBody): ProofField[] => [
  unb64(b.registrationRecord),
  { u8: b.kdfProfile },
  unb64(b.saltPw),
  unb64(b.wrappedAkPassword),
  { u64: b.expectedRowVersion },
  { u32: b.keysetVersion },
];

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

describe('S-4: proof nonces across failures, retries and concurrency (real database)', () => {
  let current: Server | undefined;
  let n = 0;

  afterEach(async () => {
    await current?.close();
    current = undefined;
  });

  const server = (): Server => {
    if (!current) throw new Error('no installation');
    return current;
  };

  /** A new installation (one account per installation), its account and a fresh session. */
  async function fresh() {
    await current?.close();
    vi.resetModules();
    current = await startHarness();
    n += 1;
    const account = await syntheticAccount(`synthetic-s4-${String(n)}`);
    const cookie = await registerAccount(server(), account);
    // One earlier key change, so a stale row version is still a valid one (at least 1).
    await query(server().db.url, 'UPDATE account_keys SET row_version = row_version + 1');
    return { account, cookie };
  }

  const keysOf = async (cookie: string) =>
    accountKeysResponseSchema.parse(
      (await server().get('/api/v1/account/keys', cookie).expect(200)).body,
    );

  const rows = <T extends Record<string, unknown> = Record<string, unknown>>(
    sql: string,
    params: unknown[] = [],
  ) => query<T>(server().db.url, sql, params);

  /** What a password change writes, and its event: equal before and after a refusal. */
  async function passwordState(account: SyntheticAccount) {
    const [keys, credential, events] = await Promise.all([
      rows(
        'SELECT row_version, salt_pw, wrapped_ak_password FROM account_keys WHERE account_id = $1',
        [account.accountId],
      ),
      rows('SELECT registration_record FROM opaque_credentials WHERE account_id = $1', [
        account.accountId,
      ]),
      rows(`SELECT id FROM security_events WHERE type = 'password_changed'`),
    ]);
    return { keys, credential, changes: events.length };
  }

  /** A password-change body for this account's current keys, `expectedRowVersion` overridable. */
  async function passwordBody(
    account: SyntheticAccount,
    cookie: string,
    keys: AccountKeysResponse,
    expectedRowVersion = keys.rowVersion,
  ): Promise<PasswordBody> {
    const reg = startRegistration(NEW_PASSWORD);
    const start = await server()
      .post(
        '/api/v1/account/password/start',
        { registrationRequest: reg.registrationRequest },
        cookie,
      )
      .expect(200);
    const record = finishRegistration(
      reg.clientRegistrationState,
      registerStartResponseSchema.parse(start.body).registrationResponse,
      NEW_PASSWORD,
    );
    const { crypto } = account;
    const accountId = uuidToBytes(account.accountId);
    const saltPw = crypto.generatePasswordSalt();
    const auk = crypto.deriveAccountUnlockKey({
      password: NEW_PASSWORD,
      passwordSalt: saltPw,
      profile: 1,
      secretKey: account.secretKey,
      accountId,
    });
    return {
      registrationRecord: record,
      kdfProfile: 1,
      saltPw: b64(saltPw),
      wrappedAkPassword: b64(
        crypto.wrapAccountKey({
          accountUnlockKey: auk,
          accountKey: account.accountKey,
          accountId,
          accountKeyId: unb64(keys.akId),
          accountKeyEpoch: keys.akEpoch,
          profile: 1,
          passwordSalt: saltPw,
        }),
      ),
      expectedRowVersion,
      keysetVersion: keys.keysetVersion,
    };
  }

  const signPassword = (
    account: SyntheticAccount,
    nonce: ProofNonceResponse,
    body: PasswordBody,
  ) => ({
    ...body,
    ...signOperation(account, 'password_change_v2', nonce, passwordFields(body), {
      accountKey: true,
    }),
  });

  const finish = (cookie: string, body: object) =>
    server().post('/api/v1/account/password/finish', body, cookie);

  /** A pending second device of the account, from a login without a device id. */
  async function pendingDevice(account: SyntheticAccount): Promise<string> {
    const client = startLogin();
    const start = loginStartResponseSchema.parse(
      (
        await server()
          .post('/api/v1/auth/login/start', {
            username: account.username,
            startLoginRequest: client.startLoginRequest,
            platform: 'web',
          })
          .expect(200)
      ).body,
    );
    const finished = finishLogin(client.clientLoginState, start.loginResponse);
    if (!finished) throw new Error('OPAQUE refused the password');
    const res = await server()
      .post('/api/v1/auth/login/finish', {
        loginId: start.loginId,
        finishLoginRequest: finished.finishLoginRequest,
      })
      .expect(200);
    return sessionResponseSchema.parse(res.body).device.id;
  }

  async function signedRevoke(account: SyntheticAccount, cookie: string, deviceId: string) {
    const nonce = await proofNonce(server(), cookie, 'device_revoke');
    return {
      reason: 'retired' as const,
      ...signOperation(account, 'device_revoke', nonce, [
        uuidToBytes(deviceId),
        { text: 'retired' },
      ]),
    };
  }

  const revoke = (cookie: string, deviceId: string, body: object) =>
    server().post(`/api/v1/devices/${deviceId}/revoke`, body, cookie);

  const revokedEvents = async () =>
    (await rows(`SELECT id FROM security_events WHERE type = 'device_revoked'`)).length;

  // ---- How a request can end ----

  it('an invalid proof burns its nonce: the correctly signed request is refused afterwards', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const body = await passwordBody(account, cookie, keys);
    const nonce = await proofNonce(server(), cookie, 'password_change_v2');
    const before = await passwordState(account);
    const good = signPassword(account, nonce, body);
    const forged = { ...good, proof: { ...good.proof, device: good.proof.accountKey } };
    expectError(await finish(cookie, forged), 'device_proof_failed');
    expectError(await finish(cookie, good), 'device_proof_failed');
    expect(await passwordState(account)).toEqual(before);
  });

  it('a refusal after a valid proof spends the nonce: a replay is refused, and nothing changes', async () => {
    const { account, cookie } = await fresh();
    // Op 12: a row version that is no longer current (another change happened since).
    const keys = await keysOf(cookie);
    const signed = signPassword(
      account,
      await proofNonce(server(), cookie, 'password_change_v2'),
      await passwordBody(account, cookie, keys, keys.rowVersion - 1),
    );
    const before = await passwordState(account);
    expectError(await finish(cookie, signed), 'row_version_conflict');
    expectError(await finish(cookie, signed), 'device_proof_failed');
    expect(await passwordState(account)).toEqual(before);
    // Op 7: a device that is already revoked.
    const other = await pendingDevice(account);
    expect((await revoke(cookie, other, await signedRevoke(account, cookie, other))).status).toBe(
      204,
    );
    const again = await signedRevoke(account, cookie, other);
    expectError(await revoke(cookie, other, again), 'not_found');
    expectError(await revoke(cookie, other, again), 'device_proof_failed');
    expect(await revokedEvents()).toBe(1);
    // Spending touches only that nonce: the session's open nonce for another operation still works.
    const third = await pendingDevice(account);
    const open = await signedRevoke(account, cookie, third);
    const refused = signPassword(
      account,
      await proofNonce(server(), cookie, 'password_change_v2'),
      await passwordBody(account, cookie, keys, keys.rowVersion - 1),
    );
    expectError(await finish(cookie, refused), 'row_version_conflict');
    expect((await revoke(cookie, third, open)).status).toBe(204);
  });

  it('concurrent duplicates of a refused request: none applies, and the nonce ends spent', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const signed = signPassword(
      account,
      await proofNonce(server(), cookie, 'password_change_v2'),
      await passwordBody(account, cookie, keys, keys.rowVersion - 1),
    );
    const before = await passwordState(account);
    const results = await Promise.all(Array.from({ length: 8 }, () => finish(cookie, signed)));
    for (const r of results)
      expect(['row_version_conflict', 'device_proof_failed']).toContain(
        errorResponseSchema.parse(r.body).error,
      );
    expectError(await finish(cookie, signed), 'device_proof_failed');
    expect(await passwordState(account)).toEqual(before);
  });

  it('a transaction that fails without a decision leaves the nonce for the same request', async () => {
    const { account, cookie } = await fresh();
    // A database failure inside the transaction, once: after the nonce was consumed and the
    // keys were written, the security event cannot be stored. Sequences are not rolled back.
    await rows(`CREATE SEQUENCE s4_failures`);
    await rows(`CREATE FUNCTION s4_fail_once() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF nextval('s4_failures') = 1 THEN RAISE EXCEPTION 's4 synthetic failure'; END IF;
        RETURN NEW;
      END $$`);
    await rows(`CREATE TRIGGER s4_fail_once BEFORE INSERT ON security_events
      FOR EACH ROW EXECUTE FUNCTION s4_fail_once()`);
    const keys = await keysOf(cookie);
    const signed = signPassword(
      account,
      await proofNonce(server(), cookie, 'password_change_v2'),
      await passwordBody(account, cookie, keys),
    );
    const before = await passwordState(account);
    expectError(await finish(cookie, signed), 'internal_error');
    expect(await passwordState(account)).toEqual(before);
    // The client retries the very same request: it applies, once.
    expect((await finish(cookie, signed)).status).toBe(204);
    expectError(await finish(cookie, signed), 'device_proof_failed');
    const after = await passwordState(account);
    expect(after.changes).toBe(1);
    expect(after.keys[0]?.row_version).toBe(String(keys.rowVersion + 1));
  });

  it('a lost response: the replay of an applied request is refused and applies nothing', async () => {
    const { account, cookie } = await fresh();
    const other = await pendingDevice(account);
    const signed = await signedRevoke(account, cookie, other);
    expect((await revoke(cookie, other, signed)).status).toBe(204);
    expectError(await revoke(cookie, other, signed), 'device_proof_failed');
    expect(await revokedEvents()).toBe(1);
  });

  it('concurrent duplicates of one signed request apply exactly once', async () => {
    const { account, cookie } = await fresh();
    const other = await pendingDevice(account);
    const revoking = await signedRevoke(account, cookie, other);
    const revoked = await Promise.all(
      Array.from({ length: 8 }, () => revoke(cookie, other, revoking)),
    );
    expect(revoked.map((r) => r.status).sort()).toEqual([204, 401, 401, 401, 401, 401, 401, 401]);
    expect(await revokedEvents()).toBe(1);

    const keys = await keysOf(cookie);
    const signed = signPassword(
      account,
      await proofNonce(server(), cookie, 'password_change_v2'),
      await passwordBody(account, cookie, keys),
    );
    const results = await Promise.all(Array.from({ length: 8 }, () => finish(cookie, signed)));
    expect(results.map((r) => r.status).sort()).toEqual([204, 401, 401, 401, 401, 401, 401, 401]);
    for (const r of results.filter((r) => r.status !== 204)) expectError(r, 'device_proof_failed');
    const after = await passwordState(account);
    expect(after.changes).toBe(1);
    expect(after.keys[0]?.row_version).toBe(String(keys.rowVersion + 1));
  });

  // ---- Retrying the same request, or signing another one ----

  it('after a refusal, a different payload signed with the same nonce is refused', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const nonce = await proofNonce(server(), cookie, 'password_change_v2');
    const stale = signPassword(
      account,
      nonce,
      await passwordBody(account, cookie, keys, keys.rowVersion - 1),
    );
    expectError(await finish(cookie, stale), 'row_version_conflict');
    const before = await passwordState(account);
    const fixed = signPassword(account, nonce, await passwordBody(account, cookie, keys));
    expectError(await finish(cookie, fixed), 'device_proof_failed');
    expect(await passwordState(account)).toEqual(before);
    // A new nonce is what a retry needs.
    const retry = signPassword(
      account,
      await proofNonce(server(), cookie, 'password_change_v2'),
      await passwordBody(account, cookie, keys),
    );
    expect((await finish(cookie, retry)).status).toBe(204);
  });

  it('a request signed with a future row version stays refused once that version arrives', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const ahead = signPassword(
      account,
      await proofNonce(server(), cookie, 'password_change_v2'),
      await passwordBody(account, cookie, keys, keys.rowVersion + 1),
    );
    expectError(await finish(cookie, ahead), 'row_version_conflict');
    // Any write that raises row_version (here a direct one, standing in for another operation).
    await rows('UPDATE account_keys SET row_version = row_version + 1 WHERE account_id = $1', [
      account.accountId,
    ]);
    const before = await passwordState(account);
    expectError(await finish(cookie, ahead), 'device_proof_failed');
    expect(await passwordState(account)).toEqual(before);
  });

  // ---- Follow-up review F-24: rows that can no longer authorize anything are removed ----

  it('issuing a nonce removes spent and long-expired rows, and keeps every usable one', async () => {
    const { account, cookie } = await fresh();
    const other = await pendingDevice(account);
    // A spent nonce (an applied revocation); then, written directly so no issue prunes them
    // first: an open nonce for op 6, one for op 5 that expired a minute ago, and one for op 6
    // that expired an hour ago.
    expect((await revoke(cookie, other, await signedRevoke(account, cookie, other))).status).toBe(
      204,
    );
    const add = (operation: number, created: string, expires: string) =>
      rows(
        `INSERT INTO proof_nonces (id, account_id, device_id, session_id, operation, nonce_hash,
           created_at, expires_at)
         SELECT gen_random_uuid(), account_id, device_id, session_id, $1,
           sha256(random()::text::bytea), now() + $2::interval, now() + $3::interval
         FROM proof_nonces LIMIT 1`,
        [operation, created, expires],
      );
    await add(6, '0 minutes', '2 minutes');
    await add(5, '-3 minutes', '-1 minute');
    await add(6, '-62 minutes', '-60 minutes');
    expect(await rows('SELECT 1 FROM proof_nonces')).toHaveLength(4);
    await proofNonce(server(), cookie, 'password_change_v2');
    const after = await rows<{ operation: number; consumed: boolean; expired: boolean }>(
      `SELECT operation, consumed_at IS NOT NULL AS consumed, expires_at < now() AS expired
       FROM proof_nonces ORDER BY operation, expires_at`,
    );
    // Kept: the open nonce for op 6, the recently expired op 5, and the new op 12.
    expect(after).toEqual([
      { operation: 5, consumed: false, expired: true },
      { operation: 6, consumed: false, expired: false },
      { operation: 12, consumed: false, expired: false },
    ]);
  });

  // ---- What a nonce is bound to ----

  it('a nonce authorizes only its own operation, session, account and payload', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const body = await passwordBody(account, cookie, keys);
    const before = await passwordState(account);

    // Another operation's nonce, signed as op 12.
    const revokeNonce = await proofNonce(server(), cookie, 'device_revoke');
    expectError(
      await finish(cookie, signPassword(account, revokeNonce, body)),
      'device_proof_failed',
    );

    // Another session's nonce: signed for this session (its `sessionRef`) but issued to another.
    // (The second login supersedes the first session; its nonce row stays.)
    const foreign = await proofNonce(server(), cookie, 'password_change_v2');
    const second = sessionCookie(await loginDevice(server(), account));
    const own = await proofNonce(server(), second, 'password_change_v2');
    expectError(
      await finish(second, signPassword(account, { ...own, nonce: foreign.nonce }, body)),
      'device_proof_failed',
    );

    // Another account id in the signed bytes.
    const mine = await proofNonce(server(), second, 'password_change_v2');
    expectError(
      await finish(second, {
        ...body,
        ...signOperation(account, 'password_change_v2', mine, passwordFields(body), {
          accountKey: true,
          accountId: account.crypto.generateUuid(),
        }),
      }),
      'device_proof_failed',
    );

    // A payload other than the one signed.
    const signed = signPassword(
      account,
      await proofNonce(server(), second, 'password_change_v2'),
      body,
    );
    expectError(
      await finish(second, { ...signed, expectedRowVersion: keys.rowVersion + 1 }),
      'device_proof_failed',
    );
    expect(await passwordState(account)).toEqual(before);
  });

  it('expiry and replacement are enforced, for a nonce left open by a failure too', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const body = await passwordBody(account, cookie, keys);
    const before = await passwordState(account);

    // Expired: past its 2 minutes (moved back in the database instead of waiting).
    const expiring = signPassword(
      account,
      await proofNonce(server(), cookie, 'password_change_v2'),
      body,
    );
    await rows(`UPDATE proof_nonces SET expires_at = now() - interval '1 second'`);
    expectError(await finish(cookie, expiring), 'device_proof_failed');

    // Replaced: an open nonce is dead once a newer one is issued for the same operation.
    const replaced = signPassword(
      account,
      await proofNonce(server(), cookie, 'password_change_v2'),
      body,
    );
    await proofNonce(server(), cookie, 'password_change_v2');
    expectError(await finish(cookie, replaced), 'device_proof_failed');

    // Left open by a failure that decided nothing, then expired: dead as well.
    await rows(`CREATE SEQUENCE s4_expiry_failures`);
    await rows(`CREATE FUNCTION s4_fail_expiry() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN
        IF nextval('s4_expiry_failures') = 1 THEN RAISE EXCEPTION 's4 synthetic failure'; END IF;
        RETURN NEW;
      END $$`);
    await rows(`CREATE TRIGGER s4_fail_expiry BEFORE INSERT ON security_events
      FOR EACH ROW EXECUTE FUNCTION s4_fail_expiry()`);
    const late = signPassword(
      account,
      await proofNonce(server(), cookie, 'password_change_v2'),
      body,
    );
    expectError(await finish(cookie, late), 'internal_error');
    await rows(`UPDATE proof_nonces SET expires_at = now() - interval '1 second'`);
    expectError(await finish(cookie, late), 'device_proof_failed');
    expect(await passwordState(account)).toEqual(before);
  });
});
