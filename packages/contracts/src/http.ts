import { z } from 'zod';

/** Carries the request identifier in requests and responses. */
export const REQUEST_ID_HEADER = 'x-request-id';

/**
 * A caller-supplied request id is kept only if it matches this pattern;
 * otherwise the server replaces it with a generated UUID.
 */
export const REQUEST_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/;

export const requestIdSchema = z.string().regex(REQUEST_ID_PATTERN);

/** Largest accepted request body in bytes (api-design.md, Conventions). */
export const MAX_REQUEST_BODY_BYTES = 64 * 1024;

/** The only accepted request body media type. A `charset` parameter, if present, must be UTF-8. */
export const JSON_MEDIA_TYPE = 'application/json';
