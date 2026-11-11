import { isBytes } from './bytes.js';
import { RuveeCryptoError } from './errors.js';

export const UUID_BYTES = 16;
/** Canonical RFC 9562 text form, lowercase. */
export const UUID_TEXT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** The 16 raw bytes of a canonical lowercase UUID (cryptographic-design §2). */
export function uuidToBytes(text: unknown, field = 'uuid'): Uint8Array {
  if (typeof text !== 'string' || !UUID_TEXT.test(text))
    throw new RuveeCryptoError('invalid_argument', { field });
  const hex = text.replace(/-/g, '');
  return Uint8Array.from({ length: UUID_BYTES }, (_, i) =>
    parseInt(hex.slice(i * 2, i * 2 + 2), 16),
  );
}

export function uuidFromBytes(bytes: Uint8Array): string {
  if (!isBytes(bytes) || bytes.length !== UUID_BYTES)
    throw new RuveeCryptoError('invalid_argument', { field: 'uuid' });
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/** Sets the RFC 9562 version 4 and variant bits on 16 random bytes, in place. */
export function asUuidV4(random: Uint8Array): Uint8Array {
  random[6] = ((random[6] ?? 0) & 0x0f) | 0x40;
  random[8] = ((random[8] ?? 0) & 0x3f) | 0x80;
  return random;
}
