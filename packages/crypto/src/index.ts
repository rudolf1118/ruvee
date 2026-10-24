import { loadLibsodiumPrimitives } from './libsodium.js';
import { buildRuveeCrypto, randomNonces, type RuveeCrypto } from './operations.js';
import { guardPrimitives } from './primitives.js';

/**
 * Loads libsodium.js, checks that it is the pinned build, and returns the operations. Nothing is
 * loaded until this is called. The library instance is not exposed.
 */
export async function initRuveeCrypto(): Promise<RuveeCrypto> {
  const primitives = guardPrimitives(await loadLibsodiumPrimitives());
  return buildRuveeCrypto(primitives, randomNonces(primitives));
}

export { wipe } from './bytes.js';
export {
  CRYPTO_ERROR_CODES,
  isRuveeCryptoError,
  RuveeCryptoError,
  type CryptoErrorCode,
  type CryptoErrorReason,
} from './errors.js';
export { ACCOUNT_KEY_WRAP_BYTES, KEYSET_ENVELOPE_MAX_BYTES } from './envelope.js';
export { KEYSET_FORMAT_VERSION, type Keyset, type KeysetVault } from './keyset.js';
export type {
  AccountUnlockKeyInput,
  KeysetContext,
  OpenKeysetInput,
  PasswordWrapContext,
  RuveeCrypto,
  SealKeysetInput,
  UnwrapAccountKeyInput,
  WrapAccountKeyInput,
} from './operations.js';
export { padPlaintext, unpadPlaintext, PADDED_MAX_BYTES, PADDING_BLOCK_BYTES } from './padding.js';
export { normalizePassword, PASSWORD_MAX_BYTES } from './password.js';
export { DEFAULT_KDF_PROFILE } from './profiles.js';
