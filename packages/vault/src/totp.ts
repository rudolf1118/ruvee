import { z } from 'zod';

/**
 * Authenticator codes (TOTP, RFC 6238) for login items: the stored form, the parser for what a
 * user pastes, and the code generator (totp-authenticator.md §2 to §4, D-35).
 *
 * Nothing here logs, throws with or returns the secret except as the canonical stored value.
 */

export const TOTP_ALGORITHMS = ['SHA1', 'SHA256', 'SHA512'] as const;
export type TotpAlgorithm = (typeof TOTP_ALGORITHMS)[number];

/** Decoded secret length in bytes: 80 bits is the shortest real sites issue; 64 is SHA-512's block. */
export const TOTP_SECRET_BYTES = { min: 10, max: 64 } as const;
export const TOTP_PERIOD = { min: 10, max: 300 } as const;
export const TOTP_INPUT_MAX = 4096;

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Strict RFC 4648 base32 without padding: only `A-Z2-7`, a length that a whole number of bytes
 * produces, and zero bits after the last byte. Anything else is undefined, never a guess.
 */
export function decodeBase32(text: string): Uint8Array | undefined {
  if (!/^[A-Z2-7]*$/.test(text)) return undefined;
  if (![0, 2, 4, 5, 7].includes(text.length % 8)) return undefined;
  const out = new Uint8Array(Math.floor((text.length * 5) / 8));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of text) {
    buffer = ((buffer << 5) | BASE32.indexOf(char)) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[index++] = (buffer >> bits) & 0xff;
    }
  }
  if ((buffer & ((1 << bits) - 1)) !== 0) return undefined;
  return out;
}

function secretBytesOk(secret: string): boolean {
  const bytes = decodeBase32(secret);
  if (!bytes) return false;
  const ok = bytes.length >= TOTP_SECRET_BYTES.min && bytes.length <= TOTP_SECRET_BYTES.max;
  bytes.fill(0);
  return ok;
}

/** The stored form inside a login body (§2.1): canonical, every value written out. */
export const totpSchema = z.strictObject({
  secret: z
    .string()
    .min(16)
    .max(103)
    .regex(/^[A-Z2-7]+$/)
    .refine(secretBytesOk, { message: 'secret' }),
  algorithm: z.enum(TOTP_ALGORITHMS),
  digits: z.union([z.literal(6), z.literal(7), z.literal(8)]),
  period: z.int().min(TOTP_PERIOD.min).max(TOTP_PERIOD.max),
});
export type Totp = z.infer<typeof totpSchema>;

export type TotpInputError =
  | 'empty'
  | 'too_long'
  | 'not_base32'
  | 'secret_too_short'
  | 'secret_too_long'
  | 'hotp'
  | 'migration'
  | 'unsupported_scheme'
  | 'malformed_uri'
  | 'missing_secret'
  | 'duplicate_parameter'
  | 'unsupported_algorithm'
  | 'unsupported_digits'
  | 'unsupported_period'
  | 'steam';

export type TotpInputResult =
  | {
      readonly ok: true;
      readonly totp: Totp;
      /** From the URI, only to prefill an empty title; never stored as such. */
      readonly issuer?: string;
      /** From the URI label, only to prefill an empty username; never stored as such. */
      readonly account?: string;
    }
  | { readonly ok: false; readonly error: TotpInputError };

function fail(error: TotpInputError): TotpInputResult {
  return { ok: false, error };
}

function normaliseSecret(raw: string): { secret: string } | { error: TotpInputError } {
  const secret = raw.replace(/[\s-]/g, '').toUpperCase().replace(/=+$/, '');
  if (secret === '') return { error: 'missing_secret' };
  const bytes = decodeBase32(secret);
  if (!bytes) return { error: 'not_base32' };
  const length = bytes.length;
  bytes.fill(0);
  if (length < TOTP_SECRET_BYTES.min) return { error: 'secret_too_short' };
  if (length > TOTP_SECRET_BYTES.max) return { error: 'secret_too_long' };
  return { secret };
}

const PLAIN_NUMBER = /^[1-9][0-9]{0,3}$/;

function safeDecode(text: string): string | undefined {
  try {
    return decodeURIComponent(text);
  } catch {
    return undefined;
  }
}

/**
 * What the editor accepts (§3.2): an `otpauth://totp/` URI or a bare base32 secret. Returns the
 * canonical value or one error; never a partly defaulted value. Unknown URI parameters are
 * ignored, and nothing named in the URI (such as `image`) is ever fetched.
 */
export function parseTotpInput(input: string): TotpInputResult {
  if (input.length > TOTP_INPUT_MAX) return fail('too_long');
  const text = input.trim();
  if (text === '') return fail('empty');
  const scheme = /^([a-z][a-z0-9+.-]*):/i.exec(text)?.[1]?.toLowerCase();
  if (scheme === undefined) {
    const parsed = normaliseSecret(text);
    if ('error' in parsed) return fail(parsed.error === 'missing_secret' ? 'empty' : parsed.error);
    return { ok: true, totp: { secret: parsed.secret, algorithm: 'SHA1', digits: 6, period: 30 } };
  }
  if (scheme === 'otpauth-migration') return fail('migration');
  if (scheme !== 'otpauth') return fail('unsupported_scheme');

  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return fail('malformed_uri');
  }
  if (url.username !== '' || url.password !== '' || url.port !== '' || url.hash !== '')
    return fail('malformed_uri');
  const kind = url.hostname.toLowerCase();
  if (kind === 'hotp') return fail('hotp');
  if (kind !== 'totp') return fail('malformed_uri');

  const params = url.searchParams;
  const names = [...params.keys()].map((k) => k.toLowerCase());
  if (new Set(names).size !== names.length) return fail('duplicate_parameter');
  const get = (name: string): string | undefined => {
    for (const [key, value] of params) if (key.toLowerCase() === name) return value;
    return undefined;
  };

  if (get('encoder') !== undefined) return fail('steam');
  const rawSecret = get('secret');
  if (rawSecret === undefined) return fail('missing_secret');
  const parsed = normaliseSecret(rawSecret);
  if ('error' in parsed) return fail(parsed.error);

  const rawAlgorithm = get('algorithm');
  const algorithm = rawAlgorithm === undefined ? 'SHA1' : rawAlgorithm.toUpperCase();
  if (!(TOTP_ALGORITHMS as readonly string[]).includes(algorithm))
    return fail('unsupported_algorithm');

  const rawDigits = get('digits');
  if (rawDigits !== undefined && !PLAIN_NUMBER.test(rawDigits)) return fail('unsupported_digits');
  const digits = rawDigits === undefined ? 6 : Number(rawDigits);
  if (digits !== 6 && digits !== 7 && digits !== 8) return fail('unsupported_digits');

  const rawPeriod = get('period');
  if (rawPeriod !== undefined && !PLAIN_NUMBER.test(rawPeriod)) return fail('unsupported_period');
  const period = rawPeriod === undefined ? 30 : Number(rawPeriod);
  if (period < TOTP_PERIOD.min || period > TOTP_PERIOD.max) return fail('unsupported_period');

  // Label: "Issuer:account" or "account", percent-encoded. Only a hint for empty fields.
  const label = safeDecode(url.pathname.replace(/^\//, '')) ?? '';
  const colon = label.indexOf(':');
  const labelIssuer = colon >= 0 ? label.slice(0, colon).trim() : '';
  const account = (colon >= 0 ? label.slice(colon + 1) : label).trim();
  const issuer = (get('issuer') ?? labelIssuer).trim();

  return {
    ok: true,
    totp: {
      secret: parsed.secret,
      algorithm: algorithm as TotpAlgorithm,
      digits,
      period,
    },
    ...(issuer ? { issuer: issuer.slice(0, 200) } : {}),
    ...(account ? { account: account.slice(0, 500) } : {}),
  };
}

/** HMAC over a message; injected so a platform without WebCrypto can supply its own (§4.2). */
export type Hmac = (
  algorithm: TotpAlgorithm,
  key: Uint8Array,
  message: Uint8Array,
) => Promise<Uint8Array>;

const WEBCRYPTO_HASH: Record<TotpAlgorithm, string> = {
  SHA1: 'SHA-1',
  SHA256: 'SHA-256',
  SHA512: 'SHA-512',
};

/** `crypto.subtle` HMAC with a non-extractable key imported for this one call. */
export const webCryptoHmac: Hmac = async (algorithm, key, message) => {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key as Uint8Array<ArrayBuffer>,
    { name: 'HMAC', hash: WEBCRYPTO_HASH[algorithm] },
    false,
    ['sign'],
  );
  return new Uint8Array(
    await crypto.subtle.sign('HMAC', cryptoKey, message as Uint8Array<ArrayBuffer>),
  );
};

/** RFC 4226 §5.3: HMAC of the 8-byte big-endian counter, dynamic truncation, `digits` digits. */
export async function hotp(
  algorithm: TotpAlgorithm,
  key: Uint8Array,
  counter: number,
  digits: number,
  hmac: Hmac = webCryptoHmac,
): Promise<string> {
  if (!Number.isSafeInteger(counter) || counter < 0) throw new RangeError('counter');
  const message = new Uint8Array(8);
  new DataView(message.buffer).setBigUint64(0, BigInt(counter));
  const mac = await hmac(algorithm, key, message);
  const offset = (mac[mac.length - 1] ?? 0) & 0x0f;
  const binary =
    (((mac[offset] ?? 0) & 0x7f) << 24) |
    ((mac[offset + 1] ?? 0) << 16) |
    ((mac[offset + 2] ?? 0) << 8) |
    (mac[offset + 3] ?? 0);
  mac.fill(0);
  return String(binary % 10 ** digits).padStart(digits, '0');
}

export interface TotpCodes {
  readonly code: string;
  /** The code of the following period, for the last seconds of this one (§5). */
  readonly nextCode: string;
  /** When `code` stops being current, in Unix milliseconds. */
  readonly validUntilMs: number;
}

/** RFC 6238 with T0 = 0, from the given clock reading (the device clock, §4.3). */
export async function totpCodes(
  totp: Totp,
  nowMs: number,
  hmac: Hmac = webCryptoHmac,
): Promise<TotpCodes> {
  const key = decodeBase32(totp.secret);
  if (!key) throw new RangeError('secret');
  try {
    const counter = Math.floor(Math.floor(nowMs / 1000) / totp.period);
    const [code, nextCode] = await Promise.all([
      hotp(totp.algorithm, key, counter, totp.digits, hmac),
      hotp(totp.algorithm, key, counter + 1, totp.digits, hmac),
    ]);
    return { code, nextCode, validUntilMs: (counter + 1) * totp.period * 1000 };
  } finally {
    key.fill(0);
  }
}
