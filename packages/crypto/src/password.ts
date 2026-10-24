import { RuveeCryptoError } from './errors.js';
import { utf8Encode } from './utf8.js';

/** Upper limit, in UTF-8 bytes of the NFC-normalized password (cryptographic-design §3.1, D-20). */
export const PASSWORD_MAX_BYTES = 4096;

/**
 * Work bound applied before normalization, in UTF-16 code units of the input. It only stops
 * oversized input from reaching `normalize()`; it can never reject a password that would pass
 * the byte limit. A valid result has at most 4,096 code points, NFC composes at most 4 code points
 * into one (the longest canonical decomposition), and a code point is at most 2 code units, so a
 * valid input has at most 32,768 code units. The bound doubles that.
 */
export const PASSWORD_MAX_INPUT_CODE_UNITS = 65_536;

function isWellFormed(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = i + 1 < text.length ? text.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return false;
      i++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function reject(reason: 'not_a_string' | 'malformed_unicode' | 'empty' | 'too_long'): never {
  throw new RuveeCryptoError('invalid_password', { reason });
}

/**
 * The single place where a typed password becomes `P`. In order:
 * 1. reject anything but a string, and strings over the pre-normalization work bound;
 * 2. reject strings with an unpaired surrogate;
 * 3. apply NFC, and nothing else: no trimming, case folding or truncation;
 * 4. require 1 to 4,096 UTF-8 bytes after NFC.
 * Strength and minimum-length policy belong to the UI (D-09), not here.
 */
function normalize(input: unknown): { text: string; bytes: Uint8Array } {
  if (typeof input !== 'string') reject('not_a_string');
  if (input.length > PASSWORD_MAX_INPUT_CODE_UNITS) reject('too_long');
  if (!isWellFormed(input)) reject('malformed_unicode');
  const text = input.normalize('NFC');
  const bytes = utf8Encode(text);
  if (bytes.length === 0) reject('empty');
  if (bytes.length > PASSWORD_MAX_BYTES) {
    bytes.fill(0);
    reject('too_long');
  }
  return { text, bytes };
}

/**
 * Returns the normalized password string, the form given to OPAQUE. JavaScript strings are
 * immutable, so neither the input nor this result can be erased from memory.
 */
export function normalizePassword(input: unknown): string {
  const { text, bytes } = normalize(input);
  bytes.fill(0);
  return text;
}

/** UTF-8 bytes of the normalized password, the form given to Argon2id. The caller wipes them. */
export function passwordBytes(input: unknown): Uint8Array {
  return normalize(input).bytes;
}
