import {
  accountKeysResponseSchema,
  API_ERRORS,
  commitResponseSchema,
  CSRF_HEADER,
  CSRF_HEADER_VALUE,
  currentDeviceResponseSchema,
  devicesResponseSchema,
  errorResponseSchema,
  accountResponseSchema,
  loginStartResponseSchema,
  recoveryMaterialResponseSchema,
  recoveryStartResponseSchema,
  reopenMaterialResponseSchema,
  reopenStartResponseSchema,
  pairingStateResponseSchema,
  proofNonceResponseSchema,
  reauthFinishResponseSchema,
  registerStartResponseSchema,
  sessionResponseSchema,
  securityEventsResponseSchema,
  sessionsResponseSchema,
  syncChangesResponseSchema,
  tokenPairSchema,
  vaultStateResponseSchema,
  type ApiErrorCode,
  type CommitRequest,
  type LoginFinishRequest,
  type LoginStartRequest,
  type PairingApproveRequest,
  type PairingJoinRequest,
  type PasswordChangeFinishRequest,
  type ProofNonceOperation,
  type SessionProofRequest,
  type RecoveryCompleteRequest,
  type RecoveryKeyRotateRequest,
  type RecoveryStartRequest,
  type ReopenLoginStartRequest,
  type ReopenRecoveryStartRequest,
  type ReauthStartRequest,
  type RegisterFinishRequest,
  type RegisterStartRequest,
  type RevokeDeviceRequest,
  type TokenPair,
  type SecretKeyRotateRequest,
} from '@ruvee/contracts';
import { z } from 'zod';

/** A response with a contract error code. Messages are the contract's fixed text. */
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: ApiErrorCode,
    readonly details: unknown,
    readonly retryAfterSeconds: number | undefined,
  ) {
    super(API_ERRORS[code].message);
    this.name = 'ApiError';
  }
}

/** The server could not be reached, or answered with something outside the contract. */
export class NetworkError extends Error {
  constructor(readonly reason: 'offline' | 'unexpected_response') {
    super(
      reason === 'offline' ? 'The server could not be reached.' : 'Unexpected server response.',
    );
    this.name = 'NetworkError';
  }
}

/**
 * How requests reach the API. The web app uses same-origin cookies; the extension uses a full
 * server URL, bearer tokens and `credentials: 'omit'` (extension-design.md §2).
 */
export interface Transport {
  /** `/api/v1` on the web; `https://server/api/v1` in the extension. */
  readonly baseUrl: string;
  readonly credentials: RequestCredentials;
  /** The `Authorization` value for the next request, if this client uses tokens. */
  authorization?(): Promise<string | undefined>;
  /** Refreshes an expired access token; true if the request should be retried once. */
  refresh?(): Promise<boolean>;
  /** Receives the tokens a token platform's login returns. */
  onTokens?(tokens: TokenPair): Promise<void>;
}

/** The web app: same origin, cookie session. */
export const SAME_ORIGIN: Transport = { baseUrl: '/api/v1', credentials: 'same-origin' };

/**
 * JSON requests with the CSRF header on every write (authentication.md §6). The browser sends
 * `Origin` itself. Every response body is validated against its contract schema: the server is
 * not trusted to send well-formed data.
 */
async function request<S extends z.ZodType>(
  transport: Transport,
  method: 'GET' | 'POST' | 'PUT' | 'DELETE',
  path: string,
  schema: S | null,
  body?: unknown,
  retried = false,
): Promise<z.output<S>> {
  const authorization = await transport.authorization?.();
  let res: Response;
  try {
    res = await fetch(`${transport.baseUrl}${path}`, {
      method,
      credentials: transport.credentials,
      cache: 'no-store',
      headers: {
        Accept: 'application/json',
        ...(authorization ? { Authorization: authorization } : {}),
        ...(method === 'GET'
          ? {}
          : { 'Content-Type': 'application/json', [CSRF_HEADER]: CSRF_HEADER_VALUE }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    throw new NetworkError('offline');
  }
  if (!res.ok) {
    const parsed = errorResponseSchema.safeParse(await res.json().catch(() => undefined));
    if (!parsed.success) throw new NetworkError('unexpected_response');
    // An expired access token: refresh once and repeat the request.
    if (
      authorization !== undefined &&
      parsed.data.error === 'session_expired' &&
      !retried &&
      transport.refresh &&
      (await transport.refresh())
    )
      return request(transport, method, path, schema, body, true);
    const retryAfter = Number(res.headers.get('Retry-After'));
    throw new ApiError(
      res.status,
      parsed.data.error,
      'details' in parsed.data ? parsed.data.details : undefined,
      Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter : undefined,
    );
  }
  if (schema === null) return undefined as z.output<S>;
  const parsed = schema.safeParse(await res.json().catch(() => undefined));
  if (!parsed.success) throw new NetworkError('unexpected_response');
  return parsed.data;
}

/** `POST /auth/refresh` for token clients; used by their transport, not by the engine. */
export function refreshTokens(transport: Transport, refreshToken: string): Promise<TokenPair> {
  return request(
    { baseUrl: transport.baseUrl, credentials: transport.credentials },
    'POST',
    '/auth/refresh',
    tokenPairSchema,
    { refreshToken },
  );
}

export function createApi(t: Transport) {
  const send = <S extends z.ZodType>(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    schema: S | null,
    body?: unknown,
  ) => request(t, method, path, schema, body);
  return {
    registerStart: (body: RegisterStartRequest) =>
      send('POST', '/auth/register/start', registerStartResponseSchema, body),
    registerFinish: (body: RegisterFinishRequest) =>
      send('POST', '/auth/register/finish', sessionResponseSchema, body),
    loginStart: (body: LoginStartRequest) =>
      send('POST', '/auth/login/start', loginStartResponseSchema, body),
    loginFinish: async (body: LoginFinishRequest) => {
      const session = await send('POST', '/auth/login/finish', sessionResponseSchema, body);
      if (session.tokens) await t.onTokens?.(session.tokens);
      return session;
    },
    logout: () => send('POST', '/auth/logout', null, {}),
    currentDevice: () => send('GET', '/devices/current', currentDeviceResponseSchema),
    // Device proof of possession (docs/security/device-proof.md §5, §6).
    proofNonce: (operation: ProofNonceOperation) =>
      send('POST', '/auth/proof-nonce', proofNonceResponseSchema, { operation }),
    sessionProof: (body: SessionProofRequest) => send('POST', '/auth/session-proof', null, body),
    recoveryProofNonce: () =>
      send('POST', '/recovery/proof-nonce', proofNonceResponseSchema, {
        operation: 'recovery_complete',
      }),
    reopenProofNonce: () =>
      send('POST', '/reopen/proof-nonce', proofNonceResponseSchema, {
        operation: 'reopen_complete',
      }),
    accountKeys: () => send('GET', '/account/keys', accountKeysResponseSchema),
    vaultState: () => send('GET', '/vault', vaultStateResponseSchema),
    changes: (since: number) =>
      send('GET', `/sync/changes?since=${String(since)}`, syncChangesResponseSchema),
    commit: (body: CommitRequest) => send('POST', '/sync/commits', commitResponseSchema, body),
    account: () => send('GET', '/account', accountResponseSchema),
    recoveryStart: (body: RecoveryStartRequest) =>
      send('POST', '/recovery/start', recoveryStartResponseSchema, body),
    recoveryMaterial: () => send('GET', '/recovery/material', recoveryMaterialResponseSchema),
    recoveryPasswordStart: (registrationRequest: string) =>
      send('POST', '/recovery/password/start', registerStartResponseSchema, {
        registrationRequest,
      }),
    recoveryComplete: (body: RecoveryCompleteRequest) =>
      send('POST', '/recovery/complete', sessionResponseSchema, body),
    // Reopening a restored installation (backup-restore.md §3.13). The code goes in the body.
    reopenLoginStart: (body: ReopenLoginStartRequest) =>
      send('POST', '/reopen/login/start', loginStartResponseSchema, body),
    reopenLoginFinish: (body: LoginFinishRequest) =>
      send('POST', '/reopen/login/finish', reopenStartResponseSchema, body),
    reopenRecoveryStart: (body: ReopenRecoveryStartRequest) =>
      send('POST', '/reopen/recovery/start', reopenStartResponseSchema, body),
    reopenMaterial: () => send('GET', '/reopen/material', reopenMaterialResponseSchema),
    reopenPasswordStart: (registrationRequest: string) =>
      send('POST', '/reopen/password/start', registerStartResponseSchema, {
        registrationRequest,
      }),
    reopenComplete: (body: RecoveryCompleteRequest) =>
      send('POST', '/reopen/complete', sessionResponseSchema, body),
    pairingCreate: (pairingId: string) =>
      send('POST', '/pairings', z.strictObject({ expiresAt: z.iso.datetime() }), { pairingId }),
    pairingState: (pairingId: string) =>
      send('GET', `/pairings/${pairingId}`, pairingStateResponseSchema),
    pairingRequest: (pairingId: string, body: PairingJoinRequest) =>
      send('POST', `/pairings/${pairingId}/request`, null, body),
    pairingApprove: (pairingId: string, body: PairingApproveRequest) =>
      send('POST', `/pairings/${pairingId}/approve`, null, body),
    pairingComplete: (pairingId: string) =>
      send('POST', `/pairings/${pairingId}/complete`, null, {}),
    pairingCancel: (pairingId: string, reason: 'user' | 'mac_failed') =>
      send('DELETE', `/pairings/${pairingId}`, null, { reason }),
    reauthStart: (body: ReauthStartRequest) =>
      send('POST', '/auth/reauth/start', loginStartResponseSchema, body),
    reauthFinish: (body: LoginFinishRequest) =>
      send('POST', '/auth/reauth/finish', reauthFinishResponseSchema, body),
    devices: () => send('GET', '/devices', devicesResponseSchema),
    sessions: () => send('GET', '/sessions', sessionsResponseSchema),
    endSession: (sessionId: string) => send('DELETE', `/sessions/${sessionId}`, null),
    revokeDevice: (deviceId: string, body: RevokeDeviceRequest) =>
      send('POST', `/devices/${deviceId}/revoke`, null, body),
    passwordStart: (registrationRequest: string) =>
      send('POST', '/account/password/start', registerStartResponseSchema, {
        registrationRequest,
      }),
    passwordFinish: (body: PasswordChangeFinishRequest) =>
      send('POST', '/account/password/finish', null, body),
    rotateSecretKey: (body: SecretKeyRotateRequest) =>
      send('POST', '/account/secret-key', null, body),
    activity: (cursor?: string) =>
      send(
        'GET',
        cursor === undefined ? '/account/events' : `/account/events?cursor=${cursor}`,
        securityEventsResponseSchema,
      ),
    rotateRecoveryKey: (body: RecoveryKeyRotateRequest) =>
      send('PUT', '/account/recovery', null, body),
  };
}

export type Api = ReturnType<typeof createApi>;
