import {
  uuidToBytes,
  type DeviceKeyPair,
  type ProofField,
  type ProofOperation,
} from '@ruvee/crypto';
import { proofNonceResponseSchema, type ProofNonceResponse } from '@ruvee/contracts';
import type { Harness } from './api-harness.js';
import type { SyntheticAccount } from './synthetic-client.js';

/**
 * Device proofs as a client makes them (docs/security/device-proof.md §4), with the same
 * `@ruvee/crypto` code the web app uses. Synthetic keys only.
 */
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const raw = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));

/** `deviceProof` for `login/finish` (op 1) or `reopen/login/finish` (op 10). */
export function signLogin(
  account: SyntheticAccount,
  start: { loginId: string; challenge: string },
  finishLoginRequest: string,
  options: {
    operation?: 'login' | 'reopen_login';
    deviceKey?: DeviceKeyPair;
    deviceId?: string;
  } = {},
): string {
  const { crypto } = account;
  const operation = options.operation ?? 'login';
  return b64(
    crypto.signDeviceProof({
      operation,
      accountId: uuidToBytes(account.accountId),
      deviceId: uuidToBytes(options.deviceId ?? account.deviceId),
      binding: crypto.loginBinding(raw(start.loginId)),
      nonce: raw(start.challenge),
      payload: crypto.proofPayload(operation, [raw(finishLoginRequest)]),
      secretKey: (options.deviceKey ?? account.deviceKey).secretKey,
    }),
  );
}

export async function proofNonce(
  h: Harness,
  cookie: string,
  operation: string,
  path = '/api/v1/auth/proof-nonce',
): Promise<ProofNonceResponse> {
  const res = await h.post(path, { operation }, cookie);
  if (res.status !== 200) throw new Error(`proof-nonce ${String(res.status)}: ${res.text}`);
  return proofNonceResponseSchema.parse(res.body);
}

/** `{ nonce, proof }` for an operation-bound request (§7), signed by the device and, if asked, AK. */
export function signOperation(
  account: SyntheticAccount,
  operation: ProofOperation,
  nonce: ProofNonceResponse,
  fields: readonly ProofField[],
  options: {
    accountKey?: boolean;
    deviceKey?: DeviceKeyPair;
    deviceId?: string;
    accountKeyMaterial?: Uint8Array;
  } = {},
): { nonce: string; proof: { device: string; accountKey?: string } } {
  const { crypto } = account;
  const base = {
    operation,
    accountId: uuidToBytes(account.accountId),
    binding: raw(nonce.sessionRef),
    nonce: raw(nonce.nonce),
    payload: crypto.proofPayload(operation, fields),
  };
  const device = b64(
    crypto.signDeviceProof({
      ...base,
      deviceId: uuidToBytes(options.deviceId ?? account.deviceId),
      secretKey: (options.deviceKey ?? account.deviceKey).secretKey,
    }),
  );
  if (!options.accountKey) return { nonce: nonce.nonce, proof: { device } };
  const accountKey = b64(
    crypto.signAccountProof({
      ...base,
      accountKeyId: account.accountKeyId,
      accountKeyEpoch: 1,
      accountKey: options.accountKeyMaterial ?? account.accountKey,
    }),
  );
  return { nonce: nonce.nonce, proof: { device, accountKey } };
}

export { b64 as toB64, raw as fromB64 };

/**
 * Logs in as an enrolled device, signing the challenge as a real client does (device-proof.md
 * §5). `prove: false` logs in with the password alone: a pre-proof session.
 */
export async function loginDevice(
  h: Harness,
  account: SyntheticAccount,
  options: {
    password?: string;
    platform?: 'web' | 'extension';
    deviceId?: string;
    deviceKey?: DeviceKeyPair;
    prove?: boolean;
  } = {},
) {
  const { loginStartResponseSchema } = await import('@ruvee/contracts');
  const { finishLogin, startLogin, SYNTHETIC_PASSWORD } = await import('./synthetic-client.js');
  const password = options.password ?? SYNTHETIC_PASSWORD;
  const deviceId = options.deviceId ?? account.deviceId;
  const client = startLogin(password);
  const startRes = await h.post('/api/v1/auth/login/start', {
    username: account.username,
    startLoginRequest: client.startLoginRequest,
    platform: options.platform ?? 'web',
    deviceId,
  });
  if (startRes.status !== 200) return startRes;
  const start = loginStartResponseSchema.parse(startRes.body);
  const finished = finishLogin(client.clientLoginState, start.loginResponse, password);
  if (!finished) throw new Error('OPAQUE refused the password');
  return h.post('/api/v1/auth/login/finish', {
    loginId: start.loginId,
    finishLoginRequest: finished.finishLoginRequest,
    ...(options.prove === false
      ? {}
      : {
          deviceProof: signLogin(account, start, finished.finishLoginRequest, {
            deviceId,
            ...(options.deviceKey ? { deviceKey: options.deviceKey } : {}),
          }),
        }),
  });
}

/** The fields of a recovery or reopening completion, without its proof (device-proof.md §8). */
export interface CompletionFields {
  readonly registrationRecord: string;
  readonly kdfProfile: number;
  readonly saltPw: string;
  readonly wrappedAkPassword: string;
  readonly recoveryKeyId: string;
  readonly wrappedAkRecovery: string;
  readonly recoveryVerifier: string;
  readonly expectedRowVersion: number;
  readonly label?: string;
}

/**
 * A completion body as the client sends it (op 9 or 11): the device key it keeps or enrolls,
 * the account's `AVPK`, a nonce of this recovery or reopen session, and both proofs.
 */
export async function signCompletion(
  h: Harness,
  account: SyntheticAccount,
  cookie: string,
  operation: 'recovery_complete' | 'reopen_complete',
  body: CompletionFields,
  options: { deviceKey: DeviceKeyPair; deviceId: string; accountKey?: Uint8Array },
) {
  const accountKey = options.accountKey ?? account.accountKey;
  const akVerifyKey = account.crypto.accountProofPublicKey(accountKey);
  const nonce = await proofNonce(
    h,
    cookie,
    operation,
    operation === 'recovery_complete'
      ? '/api/v1/recovery/proof-nonce'
      : '/api/v1/reopen/proof-nonce',
  );
  const signed = signOperation(
    account,
    operation,
    nonce,
    [
      raw(body.registrationRecord),
      { u8: body.kdfProfile },
      raw(body.saltPw),
      raw(body.wrappedAkPassword),
      raw(body.recoveryKeyId),
      raw(body.wrappedAkRecovery),
      raw(body.recoveryVerifier),
      { u64: body.expectedRowVersion },
      body.label === undefined ? null : raw(body.label),
      options.deviceKey.publicKey,
      akVerifyKey,
    ],
    {
      accountKey: true,
      accountKeyMaterial: accountKey,
      deviceKey: options.deviceKey,
      deviceId: options.deviceId,
    },
  );
  return {
    ...body,
    devicePublicKey: b64(options.deviceKey.publicKey),
    akVerifyKey: b64(akVerifyKey),
    ...signed,
  };
}
