import { z } from 'zod';

// Canonical unpadded base64url: the unused low bits of the last character must be zero,
// so every byte string has exactly one accepted encoding.
const BASE64URL_UNPADDED =
  /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-][AQgw]|[A-Za-z0-9_-]{2}[AEIMQUYcgkosw048])?$/;

/** Length of the unpadded base64url encoding of `bytes` bytes. */
export function base64urlLength(bytes: number): number {
  return Math.ceil((bytes * 4) / 3);
}

/**
 * A binary field sent as canonical unpadded base64url, whose decoded length
 * must lie within the bounds. The bounds are checked on the encoded length,
 * which maps one-to-one onto the decoded length, so nothing is decoded first.
 */
export function base64urlBytes(bounds: { length: number } | { min: number; max: number }) {
  const [min, max] = 'length' in bounds ? [bounds.length, bounds.length] : [bounds.min, bounds.max];
  if (!Number.isSafeInteger(min) || !Number.isSafeInteger(max) || min < 0 || max < min) {
    throw new RangeError('Byte bounds must be integers with 0 <= min <= max');
  }
  return z
    .string()
    .min(base64urlLength(min))
    .max(base64urlLength(max))
    .regex(BASE64URL_UNPADDED)
    .meta({ contentEncoding: 'base64url' });
}
