import { uuidToBytes, type ProofField } from '@ruvee/crypto';
import {
  accountKeysResponseSchema,
  API_ERRORS,
  errorResponseSchema,
  registerStartResponseSchema,
  type AccountKeysResponse,
} from '@ruvee/contracts';
import type request from 'supertest';
import { registerAccount, startHarness, type Harness as Server } from '../support/api-harness.js';
import {
  finishRegistration,
  startRegistration,
  SYNTHETIC_PASSWORD,
  syntheticAccount,
  type SyntheticAccount,
} from '../support/synthetic-client.js';
import { proofNonce, signOperation } from '../support/device-proof.js';
import { query } from '../support/temp-database.js';

/**
 * Follow-up review F-4: a password change names, and both proofs sign, the keyset version whose
 * `SK` the new wrap was made with (op 12, `password_change_v2`); the server applies it only while
 * that is the account's version, atomically with the `row_version` check. Synthetic accounts.
 *
 * What this does not give: the server cannot open the wrap, so it cannot tell which `SK` made it.
 * The last test shows a client holding `DSK` and `AK` that claims the current version over a wrap
 * made with the old `SK`, and is accepted.
 */
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));
const NEW_PASSWORD = 'synthetic f4 passphrase 71aa';

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

/** One byte changed, so a fixed-length field stays valid and only its signature can catch it. */
function flipLast(text: string): string {
  const bytes = unb64(text);
  bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 1;
  return b64(bytes);
}

describe('F-4: a password change is bound to the keyset version (real database)', () => {
  let current: Server | undefined;
  let n = 0;

  afterEach(async () => {
    await current?.close();
    current = undefined;
  });

  /** The installation of the running test. */
  const server = (): Server => {
    if (!current) throw new Error('no installation');
    return current;
  };

  /**
   * A new installation (it holds one account), its account and session. The session's
   * authentication is fresh, so step-up holds. The app reads its configuration again.
   */
  async function fresh() {
    await current?.close();
    vi.resetModules();
    current = await startHarness();
    n += 1;
    const account = await syntheticAccount(`synthetic-f4-${String(n)}`);
    const cookie = await registerAccount(server(), account);
    return { account, cookie };
  }

  const keysOf = async (cookie: string) =>
    accountKeysResponseSchema.parse(
      (await server().get('/api/v1/account/keys', cookie).expect(200)).body,
    );

  /** Everything a refused change must leave as it was: key material, OPAQUE record, sessions. */
  async function snapshot(account: SyntheticAccount) {
    const [keys, credential, sessions, events] = await Promise.all([
      query(server().db.url, 'SELECT * FROM account_keys WHERE account_id = $1', [
        account.accountId,
      ]),
      query(server().db.url, 'SELECT * FROM opaque_credentials WHERE account_id = $1', [
        account.accountId,
      ]),
      query(
        server().db.url,
        'SELECT id, revoked_at FROM sessions WHERE account_id = $1 ORDER BY id',
        [account.accountId],
      ),
      query(
        server().db.url,
        `SELECT 1 FROM security_events WHERE account_id = $1 AND type = 'password_changed'`,
        [account.accountId],
      ),
    ]);
    return { keys, credential, sessions, passwordChanged: events.length };
  }

  /** A password-change body as a client makes it: a wrap of `AK` under `AUK(password, SK)`. */
  async function passwordBody(
    account: SyntheticAccount,
    cookie: string,
    keys: AccountKeysResponse,
    secretKey: Uint8Array,
    keysetVersion: number,
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
      secretKey,
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
      expectedRowVersion: keys.rowVersion,
      keysetVersion,
    };
  }

  async function signedPassword(account: SyntheticAccount, cookie: string, body: PasswordBody) {
    const nonce = await proofNonce(server(), cookie, 'password_change_v2');
    return {
      ...body,
      ...signOperation(account, 'password_change_v2', nonce, passwordFields(body), {
        accountKey: true,
      }),
    };
  }

  const finish = (cookie: string, body: object) =>
    server().post('/api/v1/account/password/finish', body, cookie);

  /** A signed Secret Key rotation to the next version, as the rotating device sends it. */
  async function rotationBody(
    account: SyntheticAccount,
    cookie: string,
    keys: AccountKeysResponse,
    newSecretKey: Uint8Array,
  ) {
    const { crypto } = account;
    const accountId = uuidToBytes(account.accountId);
    const keysetVersion = keys.keysetVersion + 1;
    const saltPw = crypto.generatePasswordSalt();
    const auk = crypto.deriveAccountUnlockKey({
      password: SYNTHETIC_PASSWORD,
      passwordSalt: saltPw,
      profile: 1,
      secretKey: newSecretKey,
      accountId,
    });
    const body = {
      keysetVersion,
      keyset: b64(
        crypto.sealKeyset({
          accountKey: account.accountKey,
          accountKeyId: unb64(keys.akId),
          accountId,
          keysetVersion,
          keyset: {
            secretKey: newSecretKey,
            vaults: [{ vaultId: account.vaultId, vkId: account.vaultKeyId, vk: account.vaultKey }],
          },
        }),
      ),
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
      expectedRowVersion: keys.rowVersion,
    };
    const nonce = await proofNonce(server(), cookie, 'secret_key_rotate');
    return {
      ...body,
      ...signOperation(
        account,
        'secret_key_rotate',
        nonce,
        [
          { u32: body.keysetVersion },
          unb64(body.keyset),
          { u8: body.kdfProfile },
          unb64(body.saltPw),
          unb64(body.wrappedAkPassword),
          { u64: body.expectedRowVersion },
        ],
        { accountKey: true },
      ),
    };
  }

  /** Whether the server's password wrap opens with this password and `SK`, to the account's AK. */
  async function wrapOpens(
    account: SyntheticAccount,
    cookie: string,
    password: string,
    secretKey: Uint8Array,
  ): Promise<boolean> {
    const keys = await keysOf(cookie);
    const { crypto } = account;
    const accountId = uuidToBytes(account.accountId);
    try {
      const ak = crypto.unwrapAccountKey({
        accountUnlockKey: crypto.deriveAccountUnlockKey({
          password,
          passwordSalt: unb64(keys.saltPw),
          profile: 1,
          secretKey,
          accountId,
        }),
        accountId,
        accountKeyId: unb64(keys.akId),
        accountKeyEpoch: keys.akEpoch,
        profile: 1,
        passwordSalt: unb64(keys.saltPw),
        envelope: unb64(keys.wrappedAkPassword),
      });
      return b64(ak) === b64(account.accountKey);
    } catch {
      return false;
    }
  }

  it('applies a change made with the current SK and version', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const body = await passwordBody(account, cookie, keys, account.secretKey, keys.keysetVersion);
    const res = await finish(cookie, await signedPassword(account, cookie, body));
    expect(res.status, res.text).toBe(204);
    const after = await keysOf(cookie);
    expect(after.keysetVersion).toBe(keys.keysetVersion);
    expect(after.rowVersion).toBe(keys.rowVersion + 1);
    expect(await wrapOpens(account, cookie, NEW_PASSWORD, account.secretKey)).toBe(true);
  });

  it('refuses the old format: no version, the retired operation, or the old signed payload', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const body = await passwordBody(account, cookie, keys, account.secretKey, keys.keysetVersion);
    const before = await snapshot(account);
    // A body without the version is invalid, however it is signed.
    const old: Partial<PasswordBody> = await signedPassword(account, cookie, body);
    delete old.keysetVersion;
    expectError(await finish(cookie, old), 'invalid_request');
    // No nonce is issued for op 4 any more.
    expectError(
      await server().post('/api/v1/auth/proof-nonce', { operation: 'password_change' }, cookie),
      'invalid_request',
    );
    // A new-format body whose proofs sign only the old five fields: no signature verifies.
    const nonce = await proofNonce(server(), cookie, 'password_change_v2');
    expectError(
      await finish(cookie, {
        ...body,
        ...signOperation(account, 'password_change_v2', nonce, passwordFields(body).slice(0, 5), {
          accountKey: true,
        }),
      }),
      'device_proof_failed',
    );
    // An unsupported version value is refused by the contract.
    for (const keysetVersion of [-1, 2 ** 32, 1.5])
      expectError(
        await finish(cookie, { ...(await signedPassword(account, cookie, body)), keysetVersion }),
        'invalid_request',
      );
    expect(await snapshot(account)).toEqual(before);
  });

  it('refuses a stale version after SK rotation, with a fresh row version, and changes nothing', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const newSecretKey = account.crypto.generateKey();
    expect(
      (
        await server().post(
          '/api/v1/account/secret-key',
          await rotationBody(account, cookie, keys, newSecretKey),
          cookie,
        )
      ).status,
    ).toBe(204);
    // The accidental F-4 write: a client that re-read row_version but still holds the old SK,
    // and says so honestly.
    const current = await keysOf(cookie);
    expect(current.keysetVersion).toBe(keys.keysetVersion + 1);
    const stale = await passwordBody(
      account,
      cookie,
      current,
      account.secretKey,
      keys.keysetVersion,
    );
    const before = await snapshot(account);
    const signed = await signedPassword(account, cookie, stale);
    expectError(await finish(cookie, signed), 'row_version_conflict');
    // A higher version than the account's is refused the same way.
    expectError(
      await finish(
        cookie,
        await signedPassword(account, cookie, {
          ...stale,
          keysetVersion: current.keysetVersion + 1,
        }),
      ),
      'row_version_conflict',
    );
    expect(await snapshot(account)).toEqual(before);
    // The up-to-date wrap is intact: SK' and the unchanged password still open it.
    expect(await wrapOpens(account, cookie, SYNTHETIC_PASSWORD, newSecretKey)).toBe(true);
    // After adopting SK', the same user's retry succeeds.
    const retry = await passwordBody(account, cookie, current, newSecretKey, current.keysetVersion);
    expect((await finish(cookie, await signedPassword(account, cookie, retry))).status).toBe(204);
    expect(await wrapOpens(account, cookie, NEW_PASSWORD, newSecretKey)).toBe(true);
  });

  it('each proof covers every field, the version included', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const body = await passwordBody(account, cookie, keys, account.secretKey, keys.keysetVersion);
    const before = await snapshot(account);
    const alterations: [string, PasswordBody][] = [
      ['registrationRecord', { ...body, registrationRecord: flipLast(body.registrationRecord) }],
      ['saltPw', { ...body, saltPw: flipLast(body.saltPw) }],
      ['wrappedAkPassword', { ...body, wrappedAkPassword: flipLast(body.wrappedAkPassword) }],
      ['expectedRowVersion', { ...body, expectedRowVersion: body.expectedRowVersion + 1 }],
      ['keysetVersion', { ...body, keysetVersion: body.keysetVersion + 1 }],
    ];
    for (const [field, altered] of alterations) {
      // The altered body sent; one proof signs it, the other signs the original.
      for (const honest of ['device', 'accountKey'] as const) {
        const nonce = await proofNonce(server(), cookie, 'password_change_v2');
        const overOriginal = signOperation(
          account,
          'password_change_v2',
          nonce,
          passwordFields(body),
          {
            accountKey: true,
          },
        );
        const overAltered = signOperation(
          account,
          'password_change_v2',
          nonce,
          passwordFields(altered),
          {
            accountKey: true,
          },
        );
        const proof =
          honest === 'device'
            ? { device: overAltered.proof.device, accountKey: overOriginal.proof.accountKey }
            : { device: overOriginal.proof.device, accountKey: overAltered.proof.accountKey };
        const res = await finish(cookie, { ...altered, nonce: nonce.nonce, proof });
        expect(res.status, `${field}, only the ${honest} proof over it`).toBe(401);
        expectError(res, 'device_proof_failed');
      }
    }
    expect(await snapshot(account)).toEqual(before);
  });

  it('a concurrent SK rotation and password change never leave a wrap under the replaced SK', async () => {
    for (let round = 0; round < 3; round++) {
      const { account, cookie } = await fresh();
      const keys = await keysOf(cookie);
      const newSecretKey = account.crypto.generateKey();
      // Both prepared against the same state; each operation has its own open nonce.
      const change = await signedPassword(
        account,
        cookie,
        await passwordBody(account, cookie, keys, account.secretKey, keys.keysetVersion),
      );
      const rotation = await rotationBody(account, cookie, keys, newSecretKey);
      const [p, r] = await Promise.all([
        finish(cookie, change),
        server().post('/api/v1/account/secret-key', rotation, cookie),
      ]);
      expect([p.status, r.status].sort(), `${p.text} ${r.text}`).toEqual([204, 409]);
      const after = await keysOf(cookie);
      expect(after.rowVersion).toBe(keys.rowVersion + 1);
      if (r.status === 204) {
        // The rotation won: the new keyset and its wrap, the password unchanged.
        expect(after.keysetVersion).toBe(keys.keysetVersion + 1);
        expect(await wrapOpens(account, cookie, SYNTHETIC_PASSWORD, newSecretKey)).toBe(true);
      } else {
        // The change won: still the old keyset, and its wrap is under that keyset's SK.
        expect(after.keysetVersion).toBe(keys.keysetVersion);
        expect(await wrapOpens(account, cookie, NEW_PASSWORD, account.secretKey)).toBe(true);
      }
    }
  });

  it('a lost response and a retry: the replay is refused, and a refused request spends its nonce', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const signed = await signedPassword(
      account,
      cookie,
      await passwordBody(account, cookie, keys, account.secretKey, keys.keysetVersion),
    );
    expect((await finish(cookie, signed)).status).toBe(204);
    // The client never saw that answer and sends the same request again: its nonce is spent.
    const applied = await snapshot(account);
    expectError(await finish(cookie, signed), 'device_proof_failed');
    expect(await snapshot(account)).toEqual(applied);
    // A conflict changes nothing and spends the nonce (follow-up review S-4): replaying that
    // exact request is refused as a spent proof.
    const stale = await signedPassword(
      account,
      cookie,
      await passwordBody(account, cookie, keys, account.secretKey, keys.keysetVersion),
    );
    expectError(await finish(cookie, stale), 'row_version_conflict');
    expectError(await finish(cookie, stale), 'device_proof_failed');
    expect(await snapshot(account)).toEqual(applied);
  });

  it('residual: a client holding DSK and AK can claim the current version over a wrap under the old SK', async () => {
    const { account, cookie } = await fresh();
    const keys = await keysOf(cookie);
    const newSecretKey = account.crypto.generateKey();
    expect(
      (
        await server().post(
          '/api/v1/account/secret-key',
          await rotationBody(account, cookie, keys, newSecretKey),
          cookie,
        )
      ).status,
    ).toBe(204);
    // A stale device of this account (still active, so it has a proven session, DSK and AK)
    // reads the current version from GET /account/keys, which any proven session may, and
    // claims it over a wrap made with the SK it still holds.
    const current = await keysOf(cookie);
    const lying = await passwordBody(
      account,
      cookie,
      current,
      account.secretKey,
      current.keysetVersion,
    );
    const res = await finish(cookie, await signedPassword(account, cookie, lying));
    // The server cannot open the wrap, so it accepts. Up-to-date devices, which hold SK', can no
    // longer open the server's wrap; the old SK opens it again.
    expect(res.status, res.text).toBe(204);
    expect(await wrapOpens(account, cookie, NEW_PASSWORD, newSecretKey)).toBe(false);
    expect(await wrapOpens(account, cookie, NEW_PASSWORD, account.secretKey)).toBe(true);
  });
});
