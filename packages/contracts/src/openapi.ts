import { z } from 'zod';
import {
  API_ERRORS,
  type ApiErrorCode,
  errorResponseSchema,
  errorResponseSchemas,
} from './errors.js';
import {
  accountKeysResponseSchema,
  accountResponseSchema,
  CSRF_HEADER,
  CSRF_HEADER_VALUE,
  deviceSchema,
  devicesResponseSchema,
  loginFinishRequestSchema,
  loginStartRequestSchema,
  loginStartResponseSchema,
  passwordChangeFinishRequestSchema,
  secretKeyRotateRequestSchema,
  recoveryKeyRotateRequestSchema,
  securityEventsResponseSchema,
  reauthFinishResponseSchema,
  reauthStartRequestSchema,
  revokeDeviceRequestSchema,
  sessionsResponseSchema,
  registerFinishRequestSchema,
  registerStartRequestSchema,
  registerStartResponseSchema,
  SESSION_COOKIE_SECURE,
  sessionResponseSchema,
  refreshRequestSchema,
  tokenPairSchema,
} from './auth.js';
import { livenessResponseSchema, notReadyResponseSchema, readyResponseSchema } from './health.js';
import {
  JSON_MEDIA_TYPE,
  MAX_REQUEST_BODY_BYTES,
  REQUEST_ID_HEADER,
  REQUEST_ID_PATTERN,
  requestIdSchema,
} from './http.js';
import {
  commitRequestSchema,
  commitResponseSchema,
  MAX_COMMIT_BODY_BYTES,
  SYNC_PAGE_MAX,
  SYNC_PAGE_MIN,
  syncChangesResponseSchema,
  vaultStateResponseSchema,
} from './sync.js';
import {
  recoveryCompleteRequestSchema,
  recoveryMaterialResponseSchema,
  recoveryPasswordStartRequestSchema,
  recoveryStartRequestSchema,
  recoveryStartResponseSchema,
} from './recovery.js';
import {
  REOPEN_COOKIE_SECURE,
  reopenLoginStartRequestSchema,
  reopenMaterialResponseSchema,
  reopenRecoveryStartRequestSchema,
  reopenStartResponseSchema,
} from './reopen.js';
import {
  createPairingRequestSchema,
  pairingApproveRequestSchema,
  pairingCancelRequestSchema,
  pairingJoinRequestSchema,
  pairingStateResponseSchema,
} from './pairing.js';

type JsonSchema = Record<string, unknown>;

function jsonSchema(schema: z.ZodType): JsonSchema {
  const result: JsonSchema = z.toJSONSchema(schema, {
    target: 'draft-2020-12',
    unrepresentable: 'throw',
  });
  // OpenAPI 3.1 sets the dialect for the whole document.
  delete result.$schema;
  return result;
}

const ref = (name: string) => ({ $ref: `#/components/schemas/${name}` });

const commonHeaders = {
  'X-Request-Id': { $ref: '#/components/headers/X-Request-Id' },
  'Cache-Control': { $ref: '#/components/headers/Cache-Control' },
};

function jsonResponse(description: string, schema: JsonSchema) {
  return { description, headers: commonHeaders, content: { [JSON_MEDIA_TYPE]: { schema } } };
}

function errorResponse(code: ApiErrorCode) {
  return jsonResponse(API_ERRORS[code].message, ref(errorSchemaName(code)));
}

function errorSchemaName(code: ApiErrorCode): string {
  const words = code.split('_').map((w) => w.charAt(0).toUpperCase() + w.slice(1));
  return `Error${words.join('')}`;
}

const DESCRIPTION = `Endpoints that are implemented today, and nothing else. The endpoints proposed in
docs/architecture/api-design.md are not part of this document until they are built.

Authentication is OPAQUE (\`/api/v1/auth/*\`), followed by a cookie session
(\`${SESSION_COOKIE_SECURE}\`; \`ruvee_session\` on loopback HTTP development). Every
non-GET \`/api/v1\` request must send \`Origin\` equal to the configured public origin and
\`${CSRF_HEADER}: ${CSRF_HEADER_VALUE}\`, otherwise \`403 csrf_rejected\`. A bearer token is
not accepted yet. Each operation's \`x-ruvee-access\` names its level: none, session (pending or
active device), active (enrolled device) or step-up.

Conventions that apply to every request:

- Every response carries \`${REQUEST_ID_HEADER}\`. A caller-supplied value matching
  \`${REQUEST_ID_PATTERN.source}\` is echoed back; any other
  value is replaced by a generated UUID.
- Every response carries \`Cache-Control: no-store\`.
- Request bodies are read only for POST, PUT, PATCH and DELETE. They must be \`${JSON_MEDIA_TYPE}\`
  (UTF-8, no content encoding) and at most ${MAX_REQUEST_BODY_BYTES} bytes
  (${MAX_COMMIT_BODY_BYTES} for \`POST /api/v1/sync/commits\`). Request schemas reject unknown
  fields.
- Errors use the \`ErrorResponse\` shape with a code from a closed list and a fixed message.
  Unknown paths return \`404 not_found\`.`;

type Access = 'none' | 'session' | 'active' | 'step-up' | 'recovery' | 'reopen';

const idParameter = (name: string, description: string) => ({
  name,
  in: 'path',
  required: true,
  description,
  schema: { type: 'string', format: 'uuid' },
});

const PAIRING_ID_PARAMETER = {
  name: 'pairingId',
  in: 'path',
  required: true,
  description:
    'pairing_id, 16 bytes in unpadded base64url. Not a secret; logged only as a template.',
  schema: { type: 'string', pattern: '^[A-Za-z0-9_-]{22}$' },
};

const ACCESS_ERRORS: Record<Access, ApiErrorCode[]> = {
  none: [],
  session: ['unauthenticated', 'session_expired', 'device_revoked'],
  active: ['unauthenticated', 'session_expired', 'device_revoked', 'device_not_enrolled'],
  recovery: ['unauthenticated', 'session_expired', 'device_revoked'],
  reopen: ['unauthenticated', 'session_expired'],
  'step-up': [
    'unauthenticated',
    'session_expired',
    'device_revoked',
    'device_not_enrolled',
    'step_up_required',
  ],
};

function errors(codes: readonly ApiErrorCode[]) {
  const byStatus = new Map<number, ApiErrorCode[]>();
  for (const code of codes) {
    const status = API_ERRORS[code].status;
    byStatus.set(status, [...(byStatus.get(status) ?? []), code]);
  }
  return Object.fromEntries(
    [...byStatus].map(([status, list]) => [
      String(status),
      {
        description: list.map((c) => API_ERRORS[c].message).join(' / '),
        headers: commonHeaders,
        content: {
          [JSON_MEDIA_TYPE]: {
            schema:
              list.length === 1 && list[0] !== undefined
                ? ref(errorSchemaName(list[0]))
                : { oneOf: list.map((c) => ref(errorSchemaName(c))) },
          },
        },
      },
    ]),
  );
}

function operation(options: {
  operationId: string;
  summary: string;
  access: Access;
  request?: string;
  success: { status: string; description: string; schema?: string };
  errors?: readonly ApiErrorCode[];
  parameters?: unknown[];
}) {
  const writes = options.request !== undefined || options.success.status === '204';
  const codes: ApiErrorCode[] = [
    ...(options.request
      ? ([
          'invalid_request',
          'malformed_json',
          'payload_too_large',
          'unsupported_media_type',
        ] as const)
      : []),
    ...(writes || options.operationId === 'logout' ? (['csrf_rejected'] as const) : []),
    ...ACCESS_ERRORS[options.access],
    ...(options.errors ?? []),
    'internal_error',
    // Every API operation while a restored installation is in review (backup-restore.md §3.5).
    'maintenance',
    // Every operation but /reopen/* while it waits to be reopened (§3.13).
    ...(options.operationId.startsWith('reopen') ? [] : (['reopening'] as const)),
  ];
  return {
    operationId: options.operationId,
    summary: options.summary,
    'x-ruvee-access': options.access,
    ...(options.access === 'none'
      ? {}
      : {
          security: [
            ...(options.access === 'recovery'
              ? [{ recoveryCookie: [] }]
              : options.access === 'reopen'
                ? [{ reopenCookie: [] }]
                : [{ sessionCookie: [] }, { bearerToken: [] }]),
          ],
        }),
    ...(options.parameters ? { parameters: options.parameters } : {}),
    ...(options.request
      ? {
          requestBody: {
            required: true,
            content: { [JSON_MEDIA_TYPE]: { schema: ref(options.request) } },
          },
        }
      : {}),
    responses: {
      [options.success.status]: options.success.schema
        ? jsonResponse(options.success.description, ref(options.success.schema))
        : { description: options.success.description, headers: commonHeaders },
      ...errors([...new Set(codes)]),
    },
  };
}

/** The OpenAPI 3.1 document for the implemented endpoints, generated from the contract schemas. */
export function buildOpenApiDocument(): JsonSchema {
  const errorSchemas = Object.fromEntries(
    (Object.keys(errorResponseSchemas) as ApiErrorCode[]).map((code) => [
      errorSchemaName(code),
      jsonSchema(errorResponseSchemas[code]),
    ]),
  );

  return {
    openapi: '3.1.0',
    info: { title: 'Ruvee API', version: '0.0.0', description: DESCRIPTION },
    paths: {
      '/health/live': {
        get: {
          operationId: 'getLiveness',
          summary: 'The process is running. Does not check dependencies.',
          responses: {
            '200': jsonResponse('The process is running.', ref('LivenessResponse')),
            '500': errorResponse('internal_error'),
          },
        },
      },
      '/health/ready': {
        get: {
          operationId: 'getReadiness',
          summary: 'Every required dependency (the database) is reachable.',
          responses: {
            '200': jsonResponse('Ready to serve traffic.', ref('ReadyResponse')),
            '503': jsonResponse('The database is unreachable.', ref('NotReadyResponse')),
            '500': errorResponse('internal_error'),
          },
        },
      },
      '/api/v1/auth/register/start': {
        post: operation({
          operationId: 'registerStart',
          summary: 'OPAQUE registration step 1 for the first account, with the bootstrap token.',
          access: 'none',
          request: 'RegisterStartRequest',
          success: {
            status: '200',
            description: 'OPAQUE registration response.',
            schema: 'RegisterStartResponse',
          },
          errors: ['bootstrap_failed', 'not_found', 'rate_limited'],
        }),
      },
      '/api/v1/auth/register/finish': {
        post: operation({
          operationId: 'registerFinish',
          summary: 'Stores the account, key material, first device, session and empty vault.',
          access: 'none',
          request: 'RegisterFinishRequest',
          success: {
            status: '201',
            description: 'Account created; Set-Cookie carries the session.',
            schema: 'SessionResponse',
          },
          errors: ['bootstrap_failed', 'not_found', 'rate_limited'],
        }),
      },
      '/api/v1/auth/login/start': {
        post: operation({
          operationId: 'loginStart',
          summary:
            'OPAQUE login step 1. Unknown usernames get an indistinguishable simulated response.',
          access: 'none',
          request: 'LoginStartRequest',
          success: {
            status: '200',
            description: 'Login id (valid for 60 s, usable once) and OPAQUE response.',
            schema: 'LoginStartResponse',
          },
          errors: ['rate_limited'],
        }),
      },
      '/api/v1/auth/login/finish': {
        post: operation({
          operationId: 'loginFinish',
          summary: 'OPAQUE login step 2. Consumes the login id; creates a session on the device.',
          access: 'none',
          request: 'LoginFinishRequest',
          success: {
            status: '200',
            description: 'Logged in; Set-Cookie carries the session.',
            schema: 'SessionResponse',
          },
          errors: ['login_failed', 'device_revoked', 'rate_limited'],
        }),
      },
      '/api/v1/auth/refresh': {
        post: operation({
          operationId: 'refresh',
          summary:
            'Token clients: a new access and refresh token; a reused refresh token ends the session.',
          access: 'none',
          request: 'RefreshRequest',
          success: { status: '200', description: 'New tokens.', schema: 'TokenPair' },
          errors: ['unauthenticated', 'session_expired', 'device_revoked', 'rate_limited'],
        }),
      },
      '/api/v1/auth/logout': {
        post: operation({
          operationId: 'logout',
          summary: 'Revokes the current session and clears the cookie.',
          access: 'session',
          success: { status: '204', description: 'Logged out.' },
        }),
      },
      '/api/v1/auth/reauth/start': {
        post: operation({
          operationId: 'reauthStart',
          summary:
            'Step-up: OPAQUE again for the session account; the state is bound to this session.',
          access: 'active',
          request: 'ReauthStartRequest',
          success: {
            status: '200',
            description: 'Login id and OPAQUE response.',
            schema: 'LoginStartResponse',
          },
          errors: ['rate_limited'],
        }),
      },
      '/api/v1/auth/reauth/finish': {
        post: operation({
          operationId: 'reauthFinish',
          summary: 'Step-up: consumes the login id and refreshes auth_at for 5 minutes of step-up.',
          access: 'active',
          request: 'LoginFinishRequest',
          success: {
            status: '200',
            description: 'The new auth_at.',
            schema: 'ReauthFinishResponse',
          },
          errors: ['login_failed', 'rate_limited'],
        }),
      },
      '/api/v1/sessions': {
        get: operation({
          operationId: 'listSessions',
          summary: 'Live sessions of the account; the caller is marked current.',
          access: 'active',
          success: {
            status: '200',
            description: 'Sessions, most recently used first.',
            schema: 'SessionsResponse',
          },
        }),
      },
      '/api/v1/sessions/{sessionId}': {
        delete: operation({
          operationId: 'endSession',
          summary: 'Ends one session of the account.',
          access: 'active',
          parameters: [idParameter('sessionId', 'The session to end.')],
          success: { status: '204', description: 'Ended.' },
          errors: ['invalid_request', 'not_found'],
        }),
      },
      '/api/v1/devices/{deviceId}/revoke': {
        post: operation({
          operationId: 'revokeDevice',
          summary: 'Revokes another device and every session of it; cancels its pairings. Step-up.',
          access: 'step-up',
          parameters: [idParameter('deviceId', 'The device to revoke; never the caller.')],
          request: 'RevokeDeviceRequest',
          success: { status: '204', description: 'Revoked.' },
          errors: ['not_found', 'forbidden'],
        }),
      },
      '/api/v1/account/password/start': {
        post: operation({
          operationId: 'passwordChangeStart',
          summary: 'OPAQUE registration step 1 for a new master password. Step-up.',
          access: 'step-up',
          request: 'RecoveryPasswordStartRequest',
          success: {
            status: '200',
            description: 'OPAQUE registration response.',
            schema: 'RegisterStartResponse',
          },
        }),
      },
      '/api/v1/account/password/finish': {
        post: operation({
          operationId: 'passwordChangeFinish',
          summary:
            'Replaces the OPAQUE record and password wrap; ends every other session. Step-up.',
          access: 'step-up',
          request: 'PasswordChangeFinishRequest',
          success: { status: '204', description: 'Changed.' },
          errors: ['row_version_conflict'],
        }),
      },
      '/api/v1/account/events': {
        get: operation({
          operationId: 'getSecurityEvents',
          summary: 'Security events of the account, newest first, 50 per page.',
          access: 'active',
          parameters: [
            {
              name: 'cursor',
              in: 'query',
              required: false,
              schema: {
                type: 'string',
                pattern:
                  '^[0-9]{1,15}\\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
              },
            },
          ],
          success: {
            status: '200',
            description: 'One page of events.',
            schema: 'SecurityEventsResponse',
          },
        }),
      },
      '/api/v1/account/recovery': {
        put: operation({
          operationId: 'rotateRecoveryKey',
          summary:
            'Replaces the Recovery Key wrap and verifier; ends unfinished recoveries. Step-up.',
          access: 'step-up',
          request: 'RecoveryKeyRotateRequest',
          success: { status: '204', description: 'Rotated.' },
          errors: ['row_version_conflict'],
        }),
      },
      '/api/v1/account/secret-key': {
        post: operation({
          operationId: 'rotateSecretKey',
          summary:
            'Stores the next keyset version with a new SK and the password wrap under it. Step-up.',
          access: 'step-up',
          request: 'SecretKeyRotateRequest',
          success: { status: '204', description: 'Rotated.' },
          errors: ['row_version_conflict'],
        }),
      },
      '/api/v1/account': {
        get: operation({
          operationId: 'getAccount',
          summary: 'Account id, username and timestamps.',
          access: 'session',
          success: { status: '200', description: 'The account.', schema: 'AccountResponse' },
        }),
      },
      '/api/v1/account/keys': {
        get: operation({
          operationId: 'getAccountKeys',
          summary: 'Password wrap of AK, KDF salt and profile, and the encrypted keyset.',
          access: 'active',
          success: {
            status: '200',
            description: 'Key material; never the recovery wrap.',
            schema: 'AccountKeysResponse',
          },
          errors: ['not_found'],
        }),
      },
      '/api/v1/devices/current': {
        get: operation({
          operationId: 'getCurrentDevice',
          summary: 'The calling device, also while it is pending.',
          access: 'session',
          success: { status: '200', description: 'The device.', schema: 'Device' },
        }),
      },
      '/api/v1/devices': {
        get: operation({
          operationId: 'listDevices',
          summary: 'Every device of the account.',
          access: 'active',
          success: {
            status: '200',
            description: 'Devices, oldest first.',
            schema: 'DevicesResponse',
          },
        }),
      },
      '/api/v1/vault': {
        get: operation({
          operationId: 'getVault',
          summary: 'Vault id, current vault key id and current sequence number.',
          access: 'active',
          success: { status: '200', description: 'Vault state.', schema: 'VaultStateResponse' },
          errors: ['not_found'],
        }),
      },
      '/api/v1/sync/changes': {
        get: operation({
          operationId: 'getSyncChanges',
          summary: 'Items changed after a sequence number, and the manifests in the covered range.',
          access: 'active',
          parameters: [
            {
              name: 'since',
              in: 'query',
              required: true,
              schema: { type: 'string', pattern: '^(0|[1-9][0-9]{0,15})$' },
            },
            {
              name: 'limit',
              in: 'query',
              required: false,
              schema: { type: 'string', description: `${SYNC_PAGE_MIN} to ${SYNC_PAGE_MAX}` },
            },
          ],
          success: {
            status: '200',
            description: 'One page; follow nextCursor until it is absent.',
            schema: 'SyncChangesResponse',
          },
          errors: ['invalid_request', 'not_found'],
        }),
      },
      '/api/v1/sync/commits': {
        post: operation({
          operationId: 'postSyncCommit',
          summary: 'Applies a commit at baseSeq + 1, with structural checks only.',
          access: 'active',
          request: 'CommitRequest',
          success: {
            status: '200',
            description: 'The new sequence number (or the stored one for a retried commit id).',
            schema: 'CommitResponse',
          },
          errors: ['not_found', 'seq_conflict', 'revision_conflict', 'idempotency_mismatch'],
        }),
      },
      '/api/v1/recovery/start': {
        post: operation({
          operationId: 'recoveryStart',
          summary:
            'Proves possession of the Recovery Key with RAK; opens a 15-minute recovery session.',
          access: 'none',
          request: 'RecoveryStartRequest',
          success: {
            status: '200',
            description: 'Recovery session in Set-Cookie.',
            schema: 'RecoveryStartResponse',
          },
          errors: ['recovery_failed', 'rate_limited'],
        }),
      },
      '/api/v1/recovery/material': {
        get: operation({
          operationId: 'recoveryMaterial',
          summary: 'The recovery wrap of AK and the keyset. Recovery sessions only.',
          access: 'recovery',
          success: {
            status: '200',
            description: 'Recovery material.',
            schema: 'RecoveryMaterialResponse',
          },
          errors: ['recovery_failed'],
        }),
      },
      '/api/v1/recovery/password/start': {
        post: operation({
          operationId: 'recoveryPasswordStart',
          summary: 'OPAQUE registration step 1 for the new master password.',
          access: 'recovery',
          request: 'RecoveryPasswordStartRequest',
          success: {
            status: '200',
            description: 'OPAQUE registration response.',
            schema: 'RegisterStartResponse',
          },
        }),
      },
      '/api/v1/recovery/complete': {
        post: operation({
          operationId: 'recoveryComplete',
          summary:
            'Replaces the OPAQUE record, password wrap and rotated recovery wrap; ends every other session.',
          access: 'recovery',
          request: 'RecoveryCompleteRequest',
          success: {
            status: '200',
            description: 'A normal session in Set-Cookie.',
            schema: 'SessionResponse',
          },
          errors: ['row_version_conflict'],
        }),
      },
      '/api/v1/reopen/login/start': {
        post: operation({
          operationId: 'reopenLoginStart',
          summary:
            'Reopening, password path: the host-issued code and OPAQUE step 1 with the snapshot-time password.',
          access: 'none',
          request: 'ReopenLoginStartRequest',
          success: {
            status: '200',
            description: 'OPAQUE login response.',
            schema: 'LoginStartResponse',
          },
          errors: ['reopen_failed', 'rate_limited'],
        }),
      },
      '/api/v1/reopen/login/finish': {
        post: operation({
          operationId: 'reopenLoginFinish',
          summary:
            'OPAQUE step 3; consumes the code and opens one 30-minute reopen session (its own cookie).',
          access: 'none',
          request: 'LoginFinishRequest',
          success: {
            status: '200',
            description: 'Reopen session in Set-Cookie.',
            schema: 'ReopenStartResponse',
          },
          errors: ['reopen_failed', 'device_revoked', 'rate_limited'],
        }),
      },
      '/api/v1/reopen/recovery/start': {
        post: operation({
          operationId: 'reopenRecoveryStart',
          summary:
            'Reopening, Recovery Kit path: the code and RAK of the snapshot-time kit; consumes the code.',
          access: 'none',
          request: 'ReopenRecoveryStartRequest',
          success: {
            status: '200',
            description: 'Reopen session in Set-Cookie.',
            schema: 'ReopenStartResponse',
          },
          errors: ['reopen_failed', 'rate_limited'],
        }),
      },
      '/api/v1/reopen/material': {
        get: operation({
          operationId: 'reopenMaterial',
          summary: "The wrap of the session's own path, the keyset and ids. Reopen sessions only.",
          access: 'reopen',
          success: {
            status: '200',
            description: 'Encrypted material.',
            schema: 'ReopenMaterialResponse',
          },
        }),
      },
      '/api/v1/reopen/password/start': {
        post: operation({
          operationId: 'reopenPasswordStart',
          summary: 'OPAQUE registration step 1 for the new master password.',
          access: 'reopen',
          request: 'RecoveryPasswordStartRequest',
          success: {
            status: '200',
            description: 'OPAQUE registration response.',
            schema: 'RegisterStartResponse',
          },
        }),
      },
      '/api/v1/reopen/complete': {
        post: operation({
          operationId: 'reopenComplete',
          summary:
            'New password and new Recovery Kit in one transaction; revokes every session and code and opens the installation.',
          access: 'reopen',
          request: 'RecoveryCompleteRequest',
          success: {
            status: '200',
            description: 'A normal session in Set-Cookie.',
            schema: 'SessionResponse',
          },
          errors: ['row_version_conflict', 'reopen_failed'],
        }),
      },
      '/api/v1/pairings': {
        post: operation({
          operationId: 'createPairing',
          summary: 'Device A opens a pairing under pairing_id = MAC(S, …)[0..16]; 10 minutes.',
          access: 'active',
          request: 'CreatePairingRequest',
          success: { status: '201', description: 'Opened.', schema: 'PairingCreated' },
          errors: ['rate_limited', 'pairing_state'],
        }),
      },
      '/api/v1/pairings/{pairingId}': {
        get: operation({
          operationId: 'getPairing',
          summary:
            "State for the caller's role: A sees the request, B sees the reply after approval.",
          access: 'session',
          parameters: [PAIRING_ID_PARAMETER],
          success: { status: '200', description: 'Pairing state.', schema: 'PairingStateResponse' },
          errors: ['invalid_request', 'not_found'],
        }),
        delete: operation({
          operationId: 'cancelPairing',
          summary: 'Either device cancels; reason mac_failed records a failed request MAC.',
          access: 'session',
          parameters: [PAIRING_ID_PARAMETER],
          request: 'PairingCancelRequest',
          success: { status: '204', description: 'Cancelled.' },
          errors: ['not_found'],
        }),
      },
      '/api/v1/pairings/{pairingId}/request': {
        post: operation({
          operationId: 'requestPairing',
          summary: 'Device B (pending) sends epk, platform and req_mac; exactly one request.',
          access: 'session',
          parameters: [PAIRING_ID_PARAMETER],
          request: 'PairingJoinRequest',
          success: { status: '204', description: 'Stored; device_id_B comes from the session.' },
          errors: ['not_found', 'pairing_state', 'forbidden'],
        }),
      },
      '/api/v1/pairings/{pairingId}/approve': {
        post: operation({
          operationId: 'approvePairing',
          summary: 'Device A stores the sealed reply and resp_mac; B becomes active.',
          access: 'active',
          parameters: [PAIRING_ID_PARAMETER],
          request: 'PairingApproveRequest',
          success: { status: '204', description: 'Approved.' },
          errors: ['not_found', 'pairing_state'],
        }),
      },
      '/api/v1/pairings/{pairingId}/complete': {
        post: operation({
          operationId: 'completePairing',
          summary: 'Device B, now active, deletes the pairing after storing its keys.',
          access: 'active',
          parameters: [PAIRING_ID_PARAMETER],
          success: { status: '204', description: 'Completed.' },
          errors: ['not_found', 'pairing_state'],
        }),
      },
    },
    components: {
      securitySchemes: {
        sessionCookie: { type: 'apiKey', in: 'cookie', name: SESSION_COOKIE_SECURE },
        recoveryCookie: { type: 'apiKey', in: 'cookie', name: '__Host-ruvee_recovery' },
        reopenCookie: { type: 'apiKey', in: 'cookie', name: REOPEN_COOKIE_SECURE },
        bearerToken: { type: 'http', scheme: 'bearer', description: 'Token clients (extension).' },
      },
      schemas: {
        RegisterStartRequest: jsonSchema(registerStartRequestSchema),
        RegisterStartResponse: jsonSchema(registerStartResponseSchema),
        RegisterFinishRequest: jsonSchema(registerFinishRequestSchema),
        LoginStartRequest: jsonSchema(loginStartRequestSchema),
        LoginStartResponse: jsonSchema(loginStartResponseSchema),
        LoginFinishRequest: jsonSchema(loginFinishRequestSchema),
        SessionResponse: jsonSchema(sessionResponseSchema),
        RefreshRequest: jsonSchema(refreshRequestSchema),
        TokenPair: jsonSchema(tokenPairSchema),
        AccountResponse: jsonSchema(accountResponseSchema),
        AccountKeysResponse: jsonSchema(accountKeysResponseSchema),
        Device: jsonSchema(deviceSchema),
        DevicesResponse: jsonSchema(devicesResponseSchema),
        VaultStateResponse: jsonSchema(vaultStateResponseSchema),
        SyncChangesResponse: jsonSchema(syncChangesResponseSchema),
        CommitRequest: jsonSchema(commitRequestSchema),
        CommitResponse: jsonSchema(commitResponseSchema),
        CreatePairingRequest: jsonSchema(createPairingRequestSchema),
        ReauthStartRequest: jsonSchema(reauthStartRequestSchema),
        ReauthFinishResponse: jsonSchema(reauthFinishResponseSchema),
        SessionsResponse: jsonSchema(sessionsResponseSchema),
        RevokeDeviceRequest: jsonSchema(revokeDeviceRequestSchema),
        PasswordChangeFinishRequest: jsonSchema(passwordChangeFinishRequestSchema),
        SecretKeyRotateRequest: jsonSchema(secretKeyRotateRequestSchema),
        RecoveryKeyRotateRequest: jsonSchema(recoveryKeyRotateRequestSchema),
        SecurityEventsResponse: jsonSchema(securityEventsResponseSchema),
        RecoveryStartRequest: jsonSchema(recoveryStartRequestSchema),
        RecoveryStartResponse: jsonSchema(recoveryStartResponseSchema),
        RecoveryMaterialResponse: jsonSchema(recoveryMaterialResponseSchema),
        RecoveryPasswordStartRequest: jsonSchema(recoveryPasswordStartRequestSchema),
        RecoveryCompleteRequest: jsonSchema(recoveryCompleteRequestSchema),
        ReopenLoginStartRequest: jsonSchema(reopenLoginStartRequestSchema),
        ReopenRecoveryStartRequest: jsonSchema(reopenRecoveryStartRequestSchema),
        ReopenStartResponse: jsonSchema(reopenStartResponseSchema),
        ReopenMaterialResponse: jsonSchema(reopenMaterialResponseSchema),
        PairingCreated: {
          type: 'object',
          properties: { expiresAt: { type: 'string', format: 'date-time' } },
          required: ['expiresAt'],
          additionalProperties: false,
        },
        PairingStateResponse: jsonSchema(pairingStateResponseSchema),
        PairingJoinRequest: jsonSchema(pairingJoinRequestSchema),
        PairingApproveRequest: jsonSchema(pairingApproveRequestSchema),
        PairingCancelRequest: jsonSchema(pairingCancelRequestSchema),
        LivenessResponse: jsonSchema(livenessResponseSchema),
        ReadyResponse: jsonSchema(readyResponseSchema),
        NotReadyResponse: jsonSchema(notReadyResponseSchema),
        ErrorResponse: jsonSchema(errorResponseSchema),
        ...errorSchemas,
      },
      headers: {
        'X-Request-Id': {
          description: 'The request id, as echoed or generated by the server.',
          required: true,
          schema: jsonSchema(requestIdSchema),
        },
        'Cache-Control': {
          description: 'API responses are never cached.',
          required: true,
          schema: { type: 'string', const: 'no-store' },
        },
      },
    },
  };
}
