import { z } from 'zod';
import { requestIdSchema } from './http.js';

/**
 * The closed list of error codes the API currently returns, with their status
 * and fixed message. Messages never include request input. Codes proposed for
 * later endpoints are added here only when an endpoint returns them.
 */
export const API_ERRORS = {
  invalid_request: { status: 400, message: 'The request does not match the expected format.' },
  malformed_json: { status: 400, message: 'The request body is not valid JSON.' },
  not_found: { status: 404, message: 'The requested resource does not exist.' },
  payload_too_large: { status: 413, message: 'The request body is too large.' },
  unsupported_media_type: {
    status: 415,
    message: 'Request bodies must be application/json encoded as UTF-8.',
  },
  internal_error: { status: 500, message: 'An internal error occurred.' },
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

export const errorResponseSchemas = {
  invalid_request: errorBody('invalid_request').extend({
    details: validationDetailsSchema.optional(),
  }),
  malformed_json: errorBody('malformed_json'),
  not_found: errorBody('not_found'),
  payload_too_large: errorBody('payload_too_large'),
  unsupported_media_type: errorBody('unsupported_media_type'),
  internal_error: errorBody('internal_error'),
} as const satisfies Record<ApiErrorCode, z.ZodType>;

export const errorResponseSchema = z.discriminatedUnion('error', [
  errorResponseSchemas.invalid_request,
  errorResponseSchemas.malformed_json,
  errorResponseSchemas.not_found,
  errorResponseSchemas.payload_too_large,
  errorResponseSchemas.unsupported_media_type,
  errorResponseSchemas.internal_error,
]);

export type ErrorResponse = z.infer<typeof errorResponseSchema>;
