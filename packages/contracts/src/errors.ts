import { z } from 'zod';
import { requestIdSchema } from './http.js';
import { revisionConflictDetailsSchema, seqConflictDetailsSchema } from './sync.js';

/**
 * The closed list of error codes the API currently returns, with their status
 * and fixed message. Messages never include request input. Codes proposed for
 * later endpoints are added here only when an endpoint returns them.
 */
export const API_ERRORS = {
  invalid_request: { status: 400, message: 'The request does not match the expected format.' },
  malformed_json: { status: 400, message: 'The request body is not valid JSON.' },
  unauthenticated: { status: 401, message: 'Authentication is required.' },
  login_failed: { status: 401, message: 'Login failed.' },
  bootstrap_failed: { status: 401, message: 'The setup token is not valid.' },
  recovery_failed: { status: 401, message: 'Recovery failed.' },
  reopen_failed: { status: 401, message: 'Reopening failed.' },
  session_expired: { status: 401, message: 'The session has expired.' },
  device_revoked: { status: 401, message: 'This device has been revoked.' },
  forbidden: { status: 403, message: 'This request is not allowed.' },
  step_up_required: { status: 403, message: 'Confirm your password to continue.' },
  device_not_enrolled: { status: 403, message: 'This device is not enrolled yet.' },
  csrf_rejected: { status: 403, message: 'The request origin is not allowed.' },
  device_proof_required: {
    status: 403,
    message: 'This device must prove its key before it can do this.',
  },
  device_proof_failed: { status: 401, message: 'The device proof was not valid.' },
  device_key_mismatch: {
    status: 409,
    message: 'The account verification key does not match this account.',
  },
  not_found: { status: 404, message: 'The requested resource does not exist.' },
  seq_conflict: { status: 409, message: 'The vault has changed; pull and try again.' },
  revision_conflict: { status: 409, message: 'An item has changed on the server.' },
  idempotency_mismatch: {
    status: 409,
    message: 'This commit id was already used for a different request.',
  },
  row_version_conflict: { status: 409, message: 'The account keys have changed; refetch them.' },
  pairing_state: { status: 409, message: 'The pairing is not in the expected state.' },
  payload_too_large: { status: 413, message: 'The request body is too large.' },
  unsupported_media_type: {
    status: 415,
    message: 'Request bodies must be application/json encoded as UTF-8.',
  },
  rate_limited: { status: 429, message: 'Too many attempts; try again later.' },
  internal_error: { status: 500, message: 'An internal error occurred.' },
  maintenance: {
    status: 503,
    message: 'The server is being restored by its owner and is not available yet.',
  },
  reopening: {
    status: 503,
    message: 'The server was restored and waits for its owner to reopen it.',
  },
  server_unavailable: {
    status: 503,
    message: 'The server is not ready to serve requests.',
  },
} as const;

export type ApiErrorCode = keyof typeof API_ERRORS;

export const VALIDATION_ISSUE_CODES = [
  'invalid_type',
  'too_small',
  'too_big',
  'invalid_format',
  'invalid_value',
  'unknown_field',
  'invalid',
] as const;

export const MAX_VALIDATION_ISSUES = 20;
export const MAX_ISSUE_PATH_DEPTH = 16;

/** Path segments are schema field names or array indexes, never request-supplied keys. */
export const ISSUE_PATH_SEGMENT_PATTERN = /^[A-Za-z0-9_]{1,64}$/;

export const validationIssueSchema = z.strictObject({
  path: z
    .array(z.union([z.string().regex(ISSUE_PATH_SEGMENT_PATTERN), z.int().nonnegative()]))
    .max(MAX_ISSUE_PATH_DEPTH),
  code: z.enum(VALIDATION_ISSUE_CODES),
});

export type ValidationIssue = z.infer<typeof validationIssueSchema>;

export const validationDetailsSchema = z.strictObject({
  issues: z.array(validationIssueSchema).min(1).max(MAX_VALIDATION_ISSUES),
});

export type ValidationDetails = z.infer<typeof validationDetailsSchema>;

function errorBody<C extends ApiErrorCode>(code: C) {
  const { status, message } = API_ERRORS[code];
  return z.strictObject({
    statusCode: z.literal(status),
    error: z.literal(code),
    message: z.literal(message),
    requestId: requestIdSchema,
  });
}

const errorBodies = Object.fromEntries(
  (Object.keys(API_ERRORS) as ApiErrorCode[]).map((code) => [code, errorBody(code)]),
) as { [C in ApiErrorCode]: ReturnType<typeof errorBody<C>> };

/** Codes whose body carries `details`, with the schema of those details. */
export const ERROR_DETAILS = {
  invalid_request: validationDetailsSchema,
  seq_conflict: seqConflictDetailsSchema,
  revision_conflict: revisionConflictDetailsSchema,
} as const;

export type ErrorDetails = {
  [C in keyof typeof ERROR_DETAILS]: z.infer<(typeof ERROR_DETAILS)[C]>;
};

export const errorResponseSchemas = {
  ...errorBodies,
  invalid_request: errorBodies.invalid_request.extend({
    details: validationDetailsSchema.optional(),
  }),
  seq_conflict: errorBodies.seq_conflict.extend({ details: seqConflictDetailsSchema }),
  revision_conflict: errorBodies.revision_conflict.extend({
    details: revisionConflictDetailsSchema,
  }),
} as const satisfies Record<ApiErrorCode, z.ZodType>;

const errorSchemaList = Object.values(errorResponseSchemas);

export const errorResponseSchema = z.discriminatedUnion(
  'error',
  errorSchemaList as unknown as [
    (typeof errorSchemaList)[number],
    ...(typeof errorSchemaList)[number][],
  ],
);

export type ErrorResponse = z.infer<typeof errorResponseSchema>;
