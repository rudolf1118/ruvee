import { uuidToBytes } from '@ruvee/crypto';
import {
  loginStartResponseSchema,
  registerStartResponseSchema,
  reopenMaterialResponseSchema,
  type ReopenMaterialResponse,
} from '@ruvee/contracts';
import type request from 'supertest';
import type { Harness } from './api-harness.js';
import {
  finishLogin,
  finishRegistration,
  startLogin,
  startRegistration,
  SYNTHETIC_PASSWORD,
  type SyntheticAccount,
} from './synthetic-client.js';

/**
 * A reopening client (backup-restore.md §3.13) built from the real libraries, as the web app
 * does it: authenticate with the host code and a snapshot-time credential, unwrap `AK` with the
 * device's `SK` or the Recovery Key, then send the new password and new Recovery Kit at once.
 */

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));

export function reopenCookie(res: request.Response): string {
  const header = res.headers['set-cookie'] as unknown as string[] | undefined;
  const cookie = header?.find((c) => /^(__Host-)?ruvee_reopen=/.test(c));
  if (!cookie) throw new Error('no reopen cookie in the response');
  return cookie.split(';')[0] ?? '';
}

/** Password path: returns the responses of both steps (the second sets the reopen cookie). */
export async function reopenWithPassword(
  h: Harness,
  account: SyntheticAccount,
  reopenCode: string,
  options: { password?: string; deviceId?: string; username?: string } = {},
) {
  const password = options.password ?? SYNTHETIC_PASSWORD;
  const client = startLogin(password);
  const start = await h.post('/api/v1/reopen/login/start', {
    reopenCode,
    username: options.username ?? account.username,
    startLoginRequest: client.startLoginRequest,
    deviceId: options.deviceId ?? account.deviceId,
  });
  if (start.status !== 200) return { start, finish: undefined };
  const parsed = loginStartResponseSchema.parse(start.body);
  const finished = finishLogin(client.clientLoginState, parsed.loginResponse, password);
  if (!finished) return { start, finish: undefined };
  const finish = await h.post('/api/v1/reopen/login/finish', {
    loginId: parsed.loginId,
    finishLoginRequest: finished.finishLoginRequest,
  });
  return { start, finish };
}

/** Recovery Kit path, with the snapshot-time kit (or `recoveryKeyText`). */
export function reopenWithKit(
  h: Harness,
  account: SyntheticAccount,
  reopenCode: string,
  options: { recoveryKeyText?: string; deviceId?: string } = {},
) {
  const keys = account.crypto.deriveRecoveryKeys(
    account.crypto.parseRecoveryKey(options.recoveryKeyText ?? account.recoveryKeyText),
  );
  return h.post('/api/v1/reopen/recovery/start', {
    reopenCode,
    username: account.username,
    recoveryAuthKey: b64(keys.recoveryAuthKey),
    device: { id: options.deviceId ?? account.crypto.generateUuid(), platform: 'web' },
  });
}

export async function reopenMaterial(h: Harness, cookie: string): Promise<ReopenMaterialResponse> {
  const res = await h.get('/api/v1/reopen/material', cookie);
  if (res.status !== 200) throw new Error(`material: ${String(res.status)} ${res.text}`);
  return reopenMaterialResponseSchema.parse(res.body);
}

/** `AK` from the material: the password wrap needs `SK` (the device's), the recovery wrap `RK`. */
export function unwrapReopenMaterial(
  account: SyntheticAccount,
  material: ReopenMaterialResponse,
  credential: { password?: string; secretKey?: Uint8Array; recoveryKeyText?: string },
): { accountKey: Uint8Array; secretKey: Uint8Array } {
  const { crypto } = account;
  const accountId = uuidToBytes(account.accountId);
  let accountKey: Uint8Array;
  if (material.via === 'password') {
    const p = material.password;
    if (!p) throw new Error('no password wrap');
    const auk = crypto.deriveAccountUnlockKey({
      password: credential.password ?? SYNTHETIC_PASSWORD,
      passwordSalt: unb64(p.saltPw),
      profile: p.kdfProfile,
      secretKey: credential.secretKey ?? account.secretKey,
      accountId,
    });
    accountKey = crypto.unwrapAccountKey({
      accountUnlockKey: auk,
      accountId,
      accountKeyId: unb64(material.akId),
      accountKeyEpoch: material.akEpoch,
      profile: p.kdfProfile,
      passwordSalt: unb64(p.saltPw),
      envelope: unb64(p.wrappedAkPassword),
    });
  } else {
    if (!material.wrappedAkRecovery) throw new Error('no recovery wrap');
    const keys = crypto.deriveRecoveryKeys(
      crypto.parseRecoveryKey(credential.recoveryKeyText ?? account.recoveryKeyText),
    );
    accountKey = crypto.unwrapAccountKeyForRecovery({
      recoveryWrapKey: keys.recoveryWrapKey,
      recoveryKeyId: unb64(material.recoveryKeyId),
      accountId,
      accountKeyId: unb64(material.akId),
      accountKeyEpoch: material.akEpoch,
      envelope: unb64(material.wrappedAkRecovery),
    });
  }
  const keyset = crypto.openKeyset({
    accountKey,
    accountKeyId: unb64(material.akId),
    accountId,
    keysetVersion: material.keysetVersion,
    envelope: unb64(material.keyset),
  });
  return { accountKey, secretKey: keyset.secretKey };
}

/**
 * The completion body: a new OPAQUE record for `newPassword`, its wrap under the same `SK`, and a
 * newly generated Recovery Key (`keepKit` reuses the old key id, which the server must refuse).
 */
export async function reopenCompleteBody(
  h: Harness,
  account: SyntheticAccount,
  cookie: string,
  material: ReopenMaterialResponse,
  unwrapped: { accountKey: Uint8Array; secretKey: Uint8Array },
  newPassword: string,
  options: { keepKit?: boolean } = {},
) {
  const { crypto } = account;
  const accountId = uuidToBytes(account.accountId);
  const reg = startRegistration(newPassword);
  const regStart = await h.post(
    '/api/v1/reopen/password/start',
    { registrationRequest: reg.registrationRequest },
    cookie,
  );
  if (regStart.status !== 200) throw new Error(`password/start: ${String(regStart.status)}`);
  const record = finishRegistration(
    reg.clientRegistrationState,
    registerStartResponseSchema.parse(regStart.body).registrationResponse,
    newPassword,
  );
  const saltPw = crypto.generatePasswordSalt();
  const auk = crypto.deriveAccountUnlockKey({
    password: newPassword,
    passwordSalt: saltPw,
    profile: 1,
    secretKey: unwrapped.secretKey,
    accountId,
  });
  const rotated = crypto.generateRecoveryKey();
  const recoveryKeyId = options.keepKit ? unb64(material.recoveryKeyId) : rotated.recoveryKeyId;
  const rotatedKeys = crypto.deriveRecoveryKeys(rotated.recoveryKey);
  return {
    newKitText: crypto.formatRecoveryKey(rotated.recoveryKey),
    body: {
      registrationRecord: record,
      kdfProfile: 1,
      saltPw: b64(saltPw),
      wrappedAkPassword: b64(
        crypto.wrapAccountKey({
          accountUnlockKey: auk,
          accountKey: unwrapped.accountKey,
          accountId,
          accountKeyId: unb64(material.akId),
          accountKeyEpoch: material.akEpoch,
          profile: 1,
          passwordSalt: saltPw,
        }),
      ),
      recoveryKeyId: b64(recoveryKeyId),
      wrappedAkRecovery: b64(
        crypto.wrapAccountKeyForRecovery({
          recoveryWrapKey: rotatedKeys.recoveryWrapKey,
          recoveryKeyId,
          accountId,
          accountKeyId: unb64(material.akId),
          accountKeyEpoch: material.akEpoch,
          accountKey: unwrapped.accountKey,
        }),
      ),
      recoveryVerifier: b64(crypto.recoveryVerifier(rotatedKeys.recoveryAuthKey)),
      expectedRowVersion: material.rowVersion,
    },
  };
}
