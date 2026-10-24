/**
 * Every failure leaves the package as a `RuveeCryptoError`. Messages are fixed per code, and the
 * only extra detail is a reason or field name from a closed set, so an error can never carry a
 * password, key, plaintext or library message.
 */
export const CRYPTO_ERROR_CODES = [
  'invalid_argument',
  'invalid_password',
  'unsupported_profile',
  'malformed_envelope',
  'unsupported_format',
  'wrong_purpose',
  'wrong_key',
  'integrity_failure',
  'malformed_plaintext',
  'library_failure',
] as const;

export type CryptoErrorCode = (typeof CRYPTO_ERROR_CODES)[number];

const MESSAGES: Record<CryptoErrorCode, string> = {
  invalid_argument: 'An argument has the wrong type, length or range.',
  invalid_password: 'The password does not meet the input rule.',
  unsupported_profile: 'The key-derivation profile is not supported by this client.',
  malformed_envelope: 'The envelope length is not valid for the expected purpose.',
  unsupported_format: 'The envelope format version or algorithm is not supported.',
  wrong_purpose: 'The envelope purpose is not the expected one.',
  wrong_key: 'The envelope was made with a different key.',
  integrity_failure: 'The envelope could not be authenticated.',
  malformed_plaintext: 'The decrypted plaintext is not valid for its purpose.',
  library_failure: 'The cryptographic library failed or is not the pinned version.',
};

export type PasswordRejection = 'not_a_string' | 'malformed_unicode' | 'empty' | 'too_long';
export type ProfileRejection = 'unknown' | 'reserved';
export type LibraryFailure =
  | 'initialization_failed'
  | 'version_mismatch'
  | 'missing_function'
  | 'operation_failed'
  | 'unexpected_output';

export type CryptoErrorReason = PasswordRejection | ProfileRejection | LibraryFailure;

export interface CryptoErrorDetail {
  /** Name of the offending argument for `invalid_argument`; never its value. */
  readonly field?: string;
  readonly reason?: CryptoErrorReason;
}

export class RuveeCryptoError extends Error {
  readonly code: CryptoErrorCode;
  readonly field: string | undefined;
  readonly reason: CryptoErrorReason | undefined;

  constructor(code: CryptoErrorCode, detail: CryptoErrorDetail = {}) {
    super(MESSAGES[code]);
    this.name = 'RuveeCryptoError';
    this.code = code;
    this.field = detail.field;
    this.reason = detail.reason;
  }
}

export function isRuveeCryptoError(value: unknown): value is RuveeCryptoError {
  return value instanceof RuveeCryptoError;
}
