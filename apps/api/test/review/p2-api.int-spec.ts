import { randomBytes } from 'node:crypto';
import {
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  sessionResponseSchema,
} from '@ruvee/contracts';
import { uuidToBytes } from '@ruvee/crypto';
import pg from 'pg';
import type request from 'supertest';
import { assertEmptyDatabase } from '../../src/admin/restore-control.js';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  WRITE_HEADERS,
  type Harness,
} from '../support/api-harness.js';
import { loginDevice, proofNonce, signOperation } from '../support/device-proof.js';
import {
  finishLogin,
  startLogin,
  startRegistration,
  syntheticAccount,
  type SyntheticAccount,
} from '../support/synthetic-client.js';
import { createTempDatabase, query } from '../support/temp-database.js';

/**
 * Pre-deployment review, remaining findings (docs/security/predeployment-review.md §12): R21,
 * the R23 CSRF and empty-target items, and the D-31 verification gaps (concurrent nonces, lost
 * responses, refresh, the stored AVPK). Synthetic data only.
 */

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

const EXTENSION = {
  Origin: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop',
  'X-Ruvee-Request': '1',
};
const pairingIdText = () => randomBytes(16).toString('base64url');

describe('REVIEW R21, R23 and D-31 verification (real database)', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let owner: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-review-p2');
    owner = await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  beforeEach(async () => {
    const { ThrottleService } = await import('../../src/auth/throttle.service.js');
    await h.app.get(ThrottleService).clearIpWindows();
    await query(h.db.url, 'DELETE FROM auth_throttle');
    await query(h.db.url, 'DELETE FROM pairings');
  });

  it('R21: concurrent pairing creates never exceed three open pairings', async () => {
    const results = await Promise.all(
      Array.from({ length: 8 }, () =>
        h.post('/api/v1/pairings', { pairingId: pairingIdText() }, owner),
      ),
    );
    const statuses = results.map((r) => r.status).sort();
    // Before: count-then-insert at READ COMMITTED let several creates see fewer than three.
    expect(statuses.filter((s) => s === 201)).toHaveLength(3);
    expect(statuses.filter((s) => s === 429)).toHaveLength(5);
    const [open] = await query<{ n: string }>(h.db.url, 'SELECT count(*) AS n FROM pairings');
    expect(Number(open?.n)).toBe(3);
  });

  it('R21: concurrent creates count exactly against the hourly limit of ten', async () => {
    // Pairings are deleted between rounds, so only the hourly window bounds them.
    let created = 0;
    for (let round = 0; round < 4; round++) {
      const results = await Promise.all(
        Array.from({ length: 3 }, () =>
          h.post('/api/v1/pairings', { pairingId: pairingIdText() }, owner),
        ),
      );
      created += results.filter((r) => r.status === 201).length;
      await query(h.db.url, 'DELETE FROM pairings');
    }
    expect(created).toBe(10);
  });

  it('R23: an extension origin passes CSRF only on login and refresh', async () => {
    const client = startLogin();
    const login = await h.http().post('/api/v1/auth/login/start').set(EXTENSION).send({
      username: account.username,
      startLoginRequest: client.startLoginRequest,
      platform: 'extension',
    });
    expect(login.status, login.text).toBe(200);
    // Before: every unauthenticated route accepted the extension origin.
    for (const [path, body] of [
      [
        '/api/v1/auth/register/start',
        {
          bootstrapToken: 'B'.repeat(43),
          username: 'synthetic-intruder',
          registrationRequest: startRegistration().registrationRequest,
        },
      ],
      [
        '/api/v1/recovery/start',
        {
          username: account.username,
          recoveryAuthKey: Buffer.alloc(32, 1).toString('base64url'),
          device: { id: account.crypto.generateUuid(), platform: 'web' },
        },
      ],
      [
        '/api/v1/reopen/recovery/start',
        {
          reopenCode: `RC1-${'A'.repeat(43)}`,
          username: account.username,
          recoveryAuthKey: Buffer.alloc(32, 1).toString('base64url'),
          device: { id: account.crypto.generateUuid(), platform: 'web' },
        },
      ],
    ] as const)
      expectError(await h.http().post(path).set(EXTENSION).send(body), 'csrf_rejected');
  });

  it('D-31: concurrent nonce requests leave one open nonce; only the last one issued works', async () => {
    const issued = await Promise.all(
      Array.from({ length: 6 }, () => proofNonce(h, owner, 'device_revoke')),
    );
    const [open] = await query<{ n: string }>(
      h.db.url,
      `SELECT count(*) AS n FROM proof_nonces WHERE operation = 7 AND consumed_at IS NULL`,
    );
    // Before: delete-then-insert outside a transaction could leave several open nonces.
    expect(Number(open?.n)).toBe(1);
    const other = account.crypto.generateUuid();
    await query(
      h.db.url,
      `INSERT INTO devices (id, account_id, platform, status, enrolled_via, created_at, enrolled_at)
       VALUES ($1, $2, 'web', 'active', 'pairing', now(), now())`,
      [other, account.accountId],
    );
    const fields = [uuidToBytes(other), { text: 'retired' }];
    const outcomes = [];
    for (const nonce of issued)
      outcomes.push(
        (
          await h.post(
            `/api/v1/devices/${other}/revoke`,
            { reason: 'retired', ...signOperation(account, 'device_revoke', nonce, fields) },
            owner,
          )
        ).status,
      );
    expect(outcomes.filter((s) => s === 204)).toHaveLength(1);
    expect(outcomes.filter((s) => s === 401)).toHaveLength(issued.length - 1);
  });

  it('D-31: a revocation whose reply was lost, sent again, changes nothing a second time', async () => {
    const other = account.crypto.generateUuid();
    await query(
      h.db.url,
      `INSERT INTO devices (id, account_id, platform, status, enrolled_via, created_at, enrolled_at)
       VALUES ($1, $2, 'web', 'active', 'pairing', now(), now())`,
      [other, account.accountId],
    );
    const nonce = await proofNonce(h, owner, 'device_revoke');
    const body = {
      reason: 'lost' as const,
      ...signOperation(account, 'device_revoke', nonce, [uuidToBytes(other), { text: 'lost' }]),
    };
    expect((await h.post(`/api/v1/devices/${other}/revoke`, body, owner)).status).toBe(204);
    // The client never saw that reply and sends the same request again.
    const again = await h.post(`/api/v1/devices/${other}/revoke`, body, owner);
    expect(again.status).toBeGreaterThanOrEqual(400);
    const events = await query<{ n: string }>(
      h.db.url,
      `SELECT count(*) AS n FROM security_events WHERE type = 'device_revoked'
         AND details->>'revokedDeviceId' = $1`,
      [other],
    );
    expect(Number(events[0]?.n)).toBe(1);
    // The caller's own session is unaffected.
    await h.get('/api/v1/devices', owner).expect(200);
  });

  it('D-31: a session proof sent again after a lost reply keeps the session proven', async () => {
    const res = await loginDevice(h, account, { prove: false });
    const cookie = sessionCookie(res);
    const nonce = await proofNonce(h, cookie, 'session_proof');
    const proof = signOperation(account, 'session_proof', nonce, []);
    expect((await h.post('/api/v1/auth/session-proof', proof, cookie)).status).toBe(204);
    // Sent again: refused, and neither revokes the proven session nor proves anything twice.
    expectError(await h.post('/api/v1/auth/session-proof', proof, cookie), 'forbidden');
    await h.get('/api/v1/devices', cookie).expect(200);
    owner = cookie;
  });

  it('D-31: a token session proven after login keeps that status across refreshes', async () => {
    const extKey = account.crypto.generateDeviceKey();
    const extId = account.crypto.generateUuid();
    await query(
      h.db.url,
      `INSERT INTO devices (id, account_id, platform, status, enrolled_via, public_key, created_at, enrolled_at)
       VALUES ($1, $2, 'extension', 'active', 'pairing', $3, now(), now())`,
      [extId, account.accountId, Buffer.from(extKey.publicKey)],
    );
    const client = startLogin();
    const start = loginStartResponseSchema.parse(
      (
        await h.http().post('/api/v1/auth/login/start').set(EXTENSION).send({
          username: account.username,
          startLoginRequest: client.startLoginRequest,
          platform: 'extension',
          deviceId: extId,
        })
      ).body,
    );
    const finished = finishLogin(client.clientLoginState, start.loginResponse);
    // Logged in without the proof (the local wrap did not open), proven right after (§5 step 3).
    const body = sessionResponseSchema.parse(
      (
        await h.http().post('/api/v1/auth/login/finish').set(EXTENSION).send({
          loginId: start.loginId,
          finishLoginRequest: finished?.finishLoginRequest,
        })
      ).body,
    );
    expect(body.proven).toBe(false);
    const bearer = (token: string) => ({ ...EXTENSION, Authorization: `Bearer ${token}` });
    const access = body.tokens?.accessToken ?? '';
    const nonce = (
      await h
        .http()
        .post('/api/v1/auth/proof-nonce')
        .set(bearer(access))
        .send({ operation: 'session_proof' })
    ).body as { nonce: string; sessionRef: string; expiresAt: string };
    const proof = signOperation(account, 'session_proof', nonce, [], {
      deviceKey: extKey,
      deviceId: extId,
    });
    const proved = await h
      .http()
      .post('/api/v1/auth/session-proof')
      .set(bearer(access))
      .send(proof);
    expect(proved.status, proved.text).toBe(204);
    let refreshToken = body.tokens?.refreshToken ?? '';
    for (let n = 0; n < 2; n++) {
      const refreshed = await h
        .http()
        .post('/api/v1/auth/refresh')
        .set(EXTENSION)
        .send({ refreshToken });
      expect(refreshed.status, refreshed.text).toBe(200);
      const tokens = refreshed.body as { accessToken: string; refreshToken: string };
      refreshToken = tokens.refreshToken;
      await h.http().get('/api/v1/devices').set(bearer(tokens.accessToken)).expect(200);
    }
  });

  it('D-31: key material is replaced only against the stored AVPK, never one the request brings', async () => {
    const res = await loginDevice(h, account);
    const cookie = sessionCookie(res);
    owner = cookie;
    const { crypto } = account;
    const rotation = async () => {
      const [row] = await query<{ row_version: string }>(
        h.db.url,
        'SELECT row_version FROM account_keys',
      );
      const rotated = crypto.generateRecoveryKey();
      const keys = crypto.deriveRecoveryKeys(rotated.recoveryKey);
      const wrapped = crypto.wrapAccountKeyForRecovery({
        recoveryWrapKey: keys.recoveryWrapKey,
        recoveryKeyId: rotated.recoveryKeyId,
        accountId: uuidToBytes(account.accountId),
        accountKeyId: account.accountKeyId,
        accountKeyEpoch: 1,
        accountKey: account.accountKey,
      });
      const verifier = crypto.recoveryVerifier(keys.recoveryAuthKey);
      const expectedRowVersion = Number(row?.row_version);
      const nonce = await proofNonce(h, cookie, 'recovery_key_rotate');
      return {
        recoveryKeyId: Buffer.from(rotated.recoveryKeyId).toString('base64url'),
        wrappedAkRecovery: Buffer.from(wrapped).toString('base64url'),
        recoveryVerifier: Buffer.from(verifier).toString('base64url'),
        expectedRowVersion,
        ...signOperation(
          account,
          'recovery_key_rotate',
          nonce,
          [rotated.recoveryKeyId, wrapped, verifier, { u64: expectedRowVersion }],
          { accountKey: true },
        ),
      };
    };
    const put = (body: object) =>
      h.http().put('/api/v1/account/recovery').set(WRITE_HEADERS).set('Cookie', cookie).send(body);
    // An account from before D-31 has no AVPK: a correct DSK and AVSK proof is still refused,
    // and nothing establishes an AVPK from what the request carries.
    await query(h.db.url, 'UPDATE account_keys SET ak_verify_key = NULL');
    try {
      expectError(await put(await rotation()), 'device_proof_failed');
      const [after] = await query<{ ak_verify_key: Buffer | null }>(
        h.db.url,
        'SELECT ak_verify_key FROM account_keys',
      );
      expect(after?.ak_verify_key).toBeNull();
    } finally {
      await query(h.db.url, 'UPDATE account_keys SET ak_verify_key = $1', [
        Buffer.from(account.akVerifyKey),
      ]);
    }
    // With the account's own AVPK the same request succeeds.
    expect((await put(await rotation())).status).toBe(204);
  });
});

describe('REVIEW R23 (regression): a restore target counts every object, not only tables', () => {
  for (const [label, sql] of [
    ['a function', 'CREATE FUNCTION public.r23_fn() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$'],
    ['a view', 'CREATE VIEW public.r23_view AS SELECT 1 AS x'],
    ['a type', "CREATE TYPE public.r23_type AS ENUM ('a')"],
    ['a domain', 'CREATE DOMAIN public.r23_domain AS int'],
    ['a schema', 'CREATE SCHEMA r23_schema'],
    ['a sequence', 'CREATE SEQUENCE public.r23_seq'],
    ['a large object', 'SELECT lo_create(0)'],
    ['a table', 'CREATE TABLE public.r23_table (x int)'],
  ] as const)
    it(`is not empty with only ${label}`, async () => {
      const db = await createTempDatabase();
      const c = new pg.Client({ connectionString: db.url });
      await c.connect();
      try {
        expect(await assertEmptyDatabase(c)).toBe(true);
        await c.query(sql);
        // Before: only pg_tables was counted, so all but the table passed as empty.
        expect(await assertEmptyDatabase(c)).toBe(false);
      } finally {
        await c.end();
        await db.drop();
      }
    });
});
