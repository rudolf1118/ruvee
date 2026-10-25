import {
  accountKeysResponseSchema,
  API_ERRORS,
  commitResponseSchema,
  CSRF_HEADER,
  CSRF_HEADER_VALUE,
  deviceSchema,
  errorResponseSchema,
  accountResponseSchema,
  loginStartResponseSchema,
  recoveryMaterialResponseSchema,
  recoveryStartResponseSchema,
  pairingStateResponseSchema,
  registerStartResponseSchema,
  sessionResponseSchema,
  syncChangesResponseSchema,
  vaultStateResponseSchema,
  type ApiErrorCode,
  type CommitRequest,
  type LoginFinishRequest,
  type LoginStartRequest,
  type PairingApproveRequest,
  type PairingJoinRequest,
  type RecoveryCompleteRequest,
  type RecoveryStartRequest,
  type RegisterFinishRequest,
  type RegisterStartRequest,
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

const BASE = '/api/v1';

/**
 * Same-origin JSON requests with the CSRF header on every write (authentication.md §6). The
 * browser sends `Origin` and the session cookie itself. Every response body is validated
 * against its contract schema: the server is not trusted to send well-formed data.
 */
async function request<S extends z.ZodType>(
  method: 'GET' | 'POST' | 'DELETE',
  path: string,
  schema: S | null,
  body?: unknown,
): Promise<z.output<S>> {
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, {
      method,
      credentials: 'same-origin',
      cache: 'no-store',
      headers:
        method === 'GET'
          ? { Accept: 'application/json' }
          : {
              Accept: 'application/json',
              'Content-Type': 'application/json',
              [CSRF_HEADER]: CSRF_HEADER_VALUE,
            },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  } catch {
    throw new NetworkError('offline');
  }
  if (!res.ok) {
    const parsed = errorResponseSchema.safeParse(await res.json().catch(() => undefined));
    if (!parsed.success) throw new NetworkError('unexpected_response');
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

export const api = {
  registerStart: (body: RegisterStartRequest) =>
    request('POST', '/auth/register/start', registerStartResponseSchema, body),
  registerFinish: (body: RegisterFinishRequest) =>
    request('POST', '/auth/register/finish', sessionResponseSchema, body),
  loginStart: (body: LoginStartRequest) =>
    request('POST', '/auth/login/start', loginStartResponseSchema, body),
  loginFinish: (body: LoginFinishRequest) =>
    request('POST', '/auth/login/finish', sessionResponseSchema, body),
  logout: () => request('POST', '/auth/logout', null, {}),
  currentDevice: () => request('GET', '/devices/current', deviceSchema),
  accountKeys: () => request('GET', '/account/keys', accountKeysResponseSchema),
  vaultState: () => request('GET', '/vault', vaultStateResponseSchema),
  changes: (since: number) =>
    request('GET', `/sync/changes?since=${String(since)}`, syncChangesResponseSchema),
  commit: (body: CommitRequest) => request('POST', '/sync/commits', commitResponseSchema, body),
  account: () => request('GET', '/account', accountResponseSchema),
  recoveryStart: (body: RecoveryStartRequest) =>
    request('POST', '/recovery/start', recoveryStartResponseSchema, body),
  recoveryMaterial: () => request('GET', '/recovery/material', recoveryMaterialResponseSchema),
  recoveryPasswordStart: (registrationRequest: string) =>
    request('POST', '/recovery/password/start', registerStartResponseSchema, {
      registrationRequest,
    }),
  recoveryComplete: (body: RecoveryCompleteRequest) =>
    request('POST', '/recovery/complete', sessionResponseSchema, body),
  pairingCreate: (pairingId: string) =>
    request('POST', '/pairings', z.strictObject({ expiresAt: z.iso.datetime() }), { pairingId }),
  pairingState: (pairingId: string) =>
    request('GET', `/pairings/${pairingId}`, pairingStateResponseSchema),
  pairingRequest: (pairingId: string, body: PairingJoinRequest) =>
    request('POST', `/pairings/${pairingId}/request`, null, body),
  pairingApprove: (pairingId: string, body: PairingApproveRequest) =>
    request('POST', `/pairings/${pairingId}/approve`, null, body),
  pairingComplete: (pairingId: string) =>
    request('POST', `/pairings/${pairingId}/complete`, null, {}),
  pairingCancel: (pairingId: string, reason: 'user' | 'mac_failed') =>
    request('DELETE', `/pairings/${pairingId}`, null, { reason }),
};

export type Api = typeof api;
