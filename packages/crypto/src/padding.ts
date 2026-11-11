import { isBytes } from './bytes.js';
import { RuveeCryptoError } from './errors.js';

/** ISO/IEC 7816-4 padding to a multiple of 256 bytes (cryptographic-design §5.2). */
export const PADDING_BLOCK_BYTES = 256;
export const PADDED_MAX_BYTES = 65_536;

/**
 * Appends `0x80` and then zeros up to the next multiple of 256; a full block is added when the
 * input is already a multiple. Same scheme as libsodium's `sodium_pad`, implemented here because
 * `react-native-libsodium` lacks it. Returns a new buffer; the input is not modified.
 */
export function padPlaintext(plaintext: Uint8Array): Uint8Array {
  if (!isBytes(plaintext) || plaintext.length > PADDED_MAX_BYTES - 1)
    throw new RuveeCryptoError('invalid_argument', { field: 'plaintext' });
  const padded = new Uint8Array(
    (Math.floor(plaintext.length / PADDING_BLOCK_BYTES) + 1) * PADDING_BLOCK_BYTES,
  );
  padded.set(plaintext);
  padded[plaintext.length] = 0x80;
  return padded;
}

/**
 * Removes the padding and returns a copy of the content. Malformed padding is
 * `malformed_plaintext`. It runs only on authenticated plaintext, so it is not constant-time.
 */
export function unpadPlaintext(padded: Uint8Array): Uint8Array {
  if (!isBytes(padded)) throw new RuveeCryptoError('invalid_argument', { field: 'padded' });
  if (
    padded.length === 0 ||
    padded.length > PADDED_MAX_BYTES ||
    padded.length % PADDING_BLOCK_BYTES !== 0
  )
    throw new RuveeCryptoError('malformed_plaintext');
  let end = padded.length - 1;
  const blockStart = padded.length - PADDING_BLOCK_BYTES;
  while (end >= blockStart && padded[end] === 0x00) end--;
  if (end < blockStart || padded[end] !== 0x80) throw new RuveeCryptoError('malformed_plaintext');
  return padded.slice(0, end);
}
