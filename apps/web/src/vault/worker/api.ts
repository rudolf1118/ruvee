import {
  accountKeysResponseSchema,
  API_ERRORS,
  commitResponseSchema,
  CSRF_HEADER,
  CSRF_HEADER_VALUE,
  deviceSchema,
  errorResponseSchema,
  loginStartResponseSchema,
  registerStartResponseSchema,
  sessionResponseSchema,
  syncChangesResponseSchema,
  vaultStateResponseSchema,
  type ApiErrorCode,
  type CommitRequest,
  type LoginFinishRequest,
  type LoginStartRequest,
  type RegisterFinishRequest,
  type RegisterStartRequest,
} from '@ruvee/contracts';
import { type z } from 'zod';

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
  method: 'GET' | 'POST',
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
};

export type Api = typeof api;
