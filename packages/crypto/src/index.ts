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
export {
  ACCOUNT_KEY_WRAP_BYTES,
  ITEM_BODY_ENVELOPE_MAX_BYTES,
  ITEM_KEY_ENVELOPE_BYTES,
  KEYSET_ENVELOPE_MAX_BYTES,
  LOCAL_RECORD_ENVELOPE_MAX_BYTES,
  MANIFEST_ENVELOPE_BYTES,
} from './envelope.js';
export { uuidFromBytes, uuidToBytes, UUID_BYTES } from './ids.js';
export {
  ITEM_RECORD_MAX_BYTES,
  manifestStructureProblem,
  parseItemRecord,
  type DigestEntry,
  type Manifest,
  type RecordStructureProblem,
} from './vault-format.js';
export {
  ITEM_BODY_MAX_BYTES,
  ITEM_SCHEMA_VERSIONS,
  RECOVERY_KEY_BYTES,
  type LocalRecordContext,
  type OpenItemRecordInput,
  type OpenManifestInput,
  type RecoveryKeyMaterial,
  type RecoveryKeys,
  type RecoveryWrapContext,
  type SealItemRecordInput,
  type SealManifestInput,
  type VaultOperations,
} from './vault-operations.js';
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
