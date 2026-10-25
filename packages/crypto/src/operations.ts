import { ascii, concat, requireBytes, requireU32, u32be, u8 } from './bytes.js';
import { RuveeCryptoError } from './errors.js';
import {
  KEY_ID_BYTES,
  openEnvelope,
  PURPOSES,
  sealEnvelope,
  type NonceSource,
} from './envelope.js';
import { decodeKeyset, encodeKeyset, type Keyset } from './keyset.js';
import { passwordBytes } from './password.js';
import {
  KDF_CONTEXTS,
  KDF_SUBKEY_BYTES,
  KDF_SUBKEY_ID,
  KEY_BYTES,
  MAC_BYTES,
  NONCE_BYTES,
  SALT_BYTES,
  type Primitives,
} from './primitives.js';
import { resolveKdfProfile } from './profiles.js';
import { buildVaultOperations, type VaultOperations } from './vault-operations.js';

const ACCOUNT_ID_BYTES = 16;
const AUK_DOMAIN = ascii('ruvee/v1/auk');

export interface AccountUnlockKeyInput {
  /** The typed password; normalized here (D-20). */
  readonly password: string;
  /** `salt_pw`, 16 bytes. */
  readonly passwordSalt: Uint8Array;
  /** Argon2id profile id from the registry. */
  readonly profile: number;
  /** `SK`, 32 bytes. */
  readonly secretKey: Uint8Array;
  /** `account_id`, the 16 raw bytes of the account UUID. */
  readonly accountId: Uint8Array;
}

/** The `AK_WRAP_PASSWORD` context fields (cryptographic-design §4.3). */
export interface PasswordWrapContext {
  /** `AUK`, 32 bytes. */
  readonly accountUnlockKey: Uint8Array;
  readonly accountId: Uint8Array;
  /** `ak_id`, 16 bytes. */
  readonly accountKeyId: Uint8Array;
  /** `ak_epoch`, u32. */
  readonly accountKeyEpoch: number;
  readonly profile: number;
  readonly passwordSalt: Uint8Array;
}

export interface WrapAccountKeyInput extends PasswordWrapContext {
  /** `AK`, 32 bytes. */
  readonly accountKey: Uint8Array;
}

export interface UnwrapAccountKeyInput extends PasswordWrapContext {
  readonly envelope: Uint8Array;
}

/** The `KEYSET` context fields. `K_keyset` is derived from `AK` inside the call. */
export interface KeysetContext {
  readonly accountKey: Uint8Array;
  readonly accountKeyId: Uint8Array;
  readonly accountId: Uint8Array;
  /** `keyset_version`, u32. Rollback checks against the last seen version are the caller's. */
  readonly keysetVersion: number;
}

export interface SealKeysetInput extends KeysetContext {
  readonly keyset: Keyset;
}

export interface OpenKeysetInput extends KeysetContext {
  readonly envelope: Uint8Array;
}

/**
 * Ruvee operations: P2-03 (account key wraps and keyset) plus the recovery, item, manifest and
 * local-record formats in `VaultOperations`. Inputs are borrowed: they are read, never modified or
 * wiped. Every returned `Uint8Array` is a new buffer owned by the caller, who should `wipe()` key
 * material when done. Intermediate secrets (password bytes, `PwK`, the `AUK` input, `K_keyset`,
 * keyset plaintext bytes) are wiped before returning, on success and on failure.
 */
export interface RuveeCrypto extends VaultOperations {
  /** A new 32-byte key from the CSPRNG: `SK`, `AK` or `VK`. */
  generateKey(): Uint8Array;
  /** A new 16-byte key id from the CSPRNG: `ak_id` or `vk_id`. */
  generateKeyId(): Uint8Array;
  /** A new 16-byte `salt_pw`; use a fresh one for every password set. */
  generatePasswordSalt(): Uint8Array;
  /** `AUK = MAC(SK, "ruvee/v1/auk" ‖ account_id ‖ u8(profile) ‖ salt_pw ‖ PwK)`. */
  deriveAccountUnlockKey(input: AccountUnlockKeyInput): Uint8Array;
  /** The 93-byte `AK_WRAP_PASSWORD` envelope. */
  wrapAccountKey(input: WrapAccountKeyInput): Uint8Array;
  /** Returns `AK`. A wrong password surfaces as `integrity_failure` (§7). */
  unwrapAccountKey(input: UnwrapAccountKeyInput): Uint8Array;
  /** The `KEYSET` envelope, at most 16,445 bytes. */
  sealKeyset(input: SealKeysetInput): Uint8Array;
  openKeyset(input: OpenKeysetInput): Keyset;
}

function input(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null)
    throw new RuveeCryptoError('invalid_argument', { field: 'input' });
  return value as Record<string, unknown>;
}

function wrapContext(i: Record<string, unknown>) {
  const accountUnlockKey = requireBytes(i.accountUnlockKey, 'accountUnlockKey', KEY_BYTES);
  const accountId = requireBytes(i.accountId, 'accountId', ACCOUNT_ID_BYTES);
  const accountKeyId = requireBytes(i.accountKeyId, 'accountKeyId', KEY_ID_BYTES);
  const epoch = requireU32(i.accountKeyEpoch, 'accountKeyEpoch');
  const profile = resolveKdfProfile(i.profile);
  const passwordSalt = requireBytes(i.passwordSalt, 'passwordSalt', SALT_BYTES);
  return {
    key: accountUnlockKey,
    keyId: accountKeyId,
    context: concat(accountId, u32be(epoch), u8(profile.id), passwordSalt),
  };
}

function keysetContext(i: Record<string, unknown>) {
  const accountKey = requireBytes(i.accountKey, 'accountKey', KEY_BYTES);
  const accountKeyId = requireBytes(i.accountKeyId, 'accountKeyId', KEY_ID_BYTES);
  const accountId = requireBytes(i.accountId, 'accountId', ACCOUNT_ID_BYTES);
  const version = requireU32(i.keysetVersion, 'keysetVersion');
  return { accountKey, keyId: accountKeyId, context: concat(accountId, u32be(version)) };
}

export function buildRuveeCrypto(p: Primitives, nextNonce: NonceSource): RuveeCrypto {
  const keysetKey = (accountKey: Uint8Array) =>
    p.kdf(KDF_SUBKEY_BYTES, KDF_SUBKEY_ID, KDF_CONTEXTS.keyset, accountKey);

  return Object.freeze({
    ...buildVaultOperations(p, nextNonce),
    generateKey: () => p.randomBytes(KEY_BYTES),
    generateKeyId: () => p.randomBytes(KEY_ID_BYTES),
    generatePasswordSalt: () => p.randomBytes(SALT_BYTES),

    deriveAccountUnlockKey(value: AccountUnlockKeyInput): Uint8Array {
      const i = input(value);
      // Cheap checks first: nothing reaches Argon2id unless every input is valid.
      const profile = resolveKdfProfile(i.profile);
      const salt = requireBytes(i.passwordSalt, 'passwordSalt', SALT_BYTES);
      const secretKey = requireBytes(i.secretKey, 'secretKey', KEY_BYTES);
      const accountId = requireBytes(i.accountId, 'accountId', ACCOUNT_ID_BYTES);
      const password = passwordBytes(i.password);
      let passwordKey: Uint8Array | undefined;
      let message: Uint8Array | undefined;
      try {
        passwordKey = p.argon2id(password, salt, profile);
        message = concat(AUK_DOMAIN, accountId, u8(profile.id), salt, passwordKey);
        return p.mac(MAC_BYTES, message, secretKey);
      } finally {
        password.fill(0);
        passwordKey?.fill(0);
        message?.fill(0);
      }
    },

    wrapAccountKey(value: WrapAccountKeyInput): Uint8Array {
      const i = input(value);
      const { key, keyId, context } = wrapContext(i);
      const accountKey = requireBytes(i.accountKey, 'accountKey', KEY_BYTES);
      return sealEnvelope(p, nextNonce, {
        purpose: PURPOSES.AK_WRAP_PASSWORD,
        key,
        keyId,
        context,
        plaintext: accountKey,
      });
    },

    unwrapAccountKey(value: UnwrapAccountKeyInput): Uint8Array {
      const i = input(value);
      const { key, keyId, context } = wrapContext(i);
      return openEnvelope(p, {
        purpose: PURPOSES.AK_WRAP_PASSWORD,
        key,
        expectedKeyId: keyId,
        context,
        envelope: i.envelope,
      });
    },

    sealKeyset(value: SealKeysetInput): Uint8Array {
      const i = input(value);
      const { accountKey, keyId, context } = keysetContext(i);
      const plaintext = encodeKeyset(i.keyset);
      let key: Uint8Array | undefined;
      try {
        key = keysetKey(accountKey);
        return sealEnvelope(p, nextNonce, {
          purpose: PURPOSES.KEYSET,
          key,
          keyId,
          context,
          plaintext,
        });
      } finally {
        plaintext.fill(0);
        key?.fill(0);
      }
    },

    openKeyset(value: OpenKeysetInput): Keyset {
      const i = input(value);
      const { accountKey, keyId, context } = keysetContext(i);
      let key: Uint8Array | undefined;
      let plaintext: Uint8Array | undefined;
      try {
        key = keysetKey(accountKey);
        plaintext = openEnvelope(p, {
          purpose: PURPOSES.KEYSET,
          key,
          expectedKeyId: keyId,
          context,
          envelope: i.envelope,
        });
        return decodeKeyset(plaintext);
      } finally {
        key?.fill(0);
        plaintext?.fill(0);
      }
    },
  });
}

/** Production nonce source: 24 fresh bytes from the CSPRNG for every encryption (INV-02). */
export function randomNonces(p: Primitives): NonceSource {
  return () => p.randomBytes(NONCE_BYTES);
}
