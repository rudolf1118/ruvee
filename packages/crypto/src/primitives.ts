import { isBytes } from './bytes.js';
import { RuveeCryptoError } from './errors.js';
import { isRegisteredProfile, type KdfProfile } from './profiles.js';
import { PASSWORD_MAX_BYTES } from './password.js';

/**
 * The injected library interface: one method per libsodium function the package uses, with the
 * library's own argument order. Implementations do no validation of their own; production uses
 * `libsodiumPrimitives` and tests use recording fakes.
 */
export interface RawPrimitives {
  randombytesBuf(length: number): Uint8Array;
  /** `crypto_pwhash(..., crypto_pwhash_ALG_ARGON2ID13)`. */
  pwhashArgon2id13(
    outputLength: number,
    password: Uint8Array,
    salt: Uint8Array,
    opslimit: number,
    memlimit: number,
  ): Uint8Array;
  /** `crypto_generichash` (BLAKE2b). */
  genericHash(outputLength: number, message: Uint8Array, key: Uint8Array | null): Uint8Array;
  /** `crypto_kdf_derive_from_key`. */
  kdfDeriveFromKey(
    subkeyLength: number,
    subkeyId: number,
    context: string,
    key: Uint8Array,
  ): Uint8Array;
  /** `crypto_aead_xchacha20poly1305_ietf_encrypt` in combined mode. */
  aeadEncrypt(
    message: Uint8Array,
    additionalData: Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
  ): Uint8Array;
  /** As above for decryption; `null` for any authentication failure. */
  aeadDecrypt(
    ciphertext: Uint8Array,
    additionalData: Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
  ): Uint8Array | null;
}

export const KEY_BYTES = 32;
export const NONCE_BYTES = 24;
export const TAG_BYTES = 16;
export const SALT_BYTES = 16;
export const MAC_BYTES = 32;
export const KDF_SUBKEY_BYTES = 32;
export const KDF_SUBKEY_ID = 1;

/** Byte sizes the package ever asks the CSPRNG for: ids and salts, nonces, keys. */
const RANDOM_SIZES: ReadonlySet<number> = new Set([16, 24, 32]);

/**
 * KDF contexts implemented in P2-03. The other contexts in cryptographic-design §3.3
 * (`rvlocal1`, `rvdevlb1`, `rvmanif1`) belong to later milestones and are refused.
 */
export const KDF_CONTEXTS = { keyset: 'rvkeyst1' } as const;
const ALLOWED_KDF_CONTEXTS: ReadonlySet<string> = new Set(Object.values(KDF_CONTEXTS));

/** Largest message given to the MAC; the `AUK` input is 77 bytes. */
export const MAC_MESSAGE_MAX_BYTES = 1024;
/** Largest plaintext of an implemented purpose (`KEYSET`). */
export const AEAD_PLAINTEXT_MAX_BYTES = 16_384;
export const AEAD_ADDITIONAL_DATA_MAX_BYTES = 1024;

/**
 * The only route from package code to the library. Every argument is checked against Ruvee's
 * fixed sizes before the call, and every output length after it. The checks are stricter than
 * the library's documented ranges because libsodium.js 0.8.4 does not enforce all of them:
 * BLAKE2b accepts 1- to 15-byte keys and outputs, `crypto_kdf` accepts a non-ASCII context, and
 * `crypto_kdf_derive_from_key` returns stale WebAssembly memory for subkey lengths outside 16..64
 * (V-12, V-15). These checks contain those defects for Ruvee's callers; they do not fix them.
 */
export interface Primitives {
  randomBytes(length: number): Uint8Array;
  argon2id(password: Uint8Array, salt: Uint8Array, profile: KdfProfile): Uint8Array;
  mac(outputLength: number, message: Uint8Array, key: Uint8Array): Uint8Array;
  kdf(subkeyLength: number, subkeyId: number, context: string, key: Uint8Array): Uint8Array;
  aeadEncrypt(
    plaintext: Uint8Array,
    additionalData: Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
  ): Uint8Array;
  aeadDecrypt(
    ciphertext: Uint8Array,
    additionalData: Uint8Array,
    nonce: Uint8Array,
    key: Uint8Array,
  ): Uint8Array | null;
}

function invalid(field: string): never {
  throw new RuveeCryptoError('invalid_argument', { field });
}

function exactBytes(value: unknown, field: string, length: number): void {
  if (!isBytes(value) || value.length !== length) invalid(field);
}

function boundedBytes(value: unknown, field: string, min: number, max: number): void {
  if (!isBytes(value) || value.length < min || value.length > max) invalid(field);
}

function isPrintableAscii8(value: unknown): value is string {
  return typeof value === 'string' && /^[\x21-\x7e]{8}$/.test(value);
}

function call<T>(operation: () => T): T {
  try {
    return operation();
  } catch {
    throw new RuveeCryptoError('library_failure', { reason: 'operation_failed' });
  }
}

function expectLength(output: unknown, length: number): Uint8Array {
  if (!isBytes(output) || output.length !== length) {
    if (isBytes(output)) output.fill(0);
    throw new RuveeCryptoError('library_failure', { reason: 'unexpected_output' });
  }
  return output;
}

export function guardPrimitives(raw: RawPrimitives): Primitives {
  return Object.freeze({
    randomBytes(length: number): Uint8Array {
      if (typeof length !== 'number' || !RANDOM_SIZES.has(length)) invalid('length');
      return expectLength(
        call(() => raw.randombytesBuf(length)),
        length,
      );
    },

    argon2id(password: Uint8Array, salt: Uint8Array, profile: KdfProfile): Uint8Array {
      if (!isRegisteredProfile(profile)) invalid('profile');
      boundedBytes(password, 'password', 1, PASSWORD_MAX_BYTES);
      exactBytes(salt, 'salt', SALT_BYTES);
      return expectLength(
        call(() =>
          raw.pwhashArgon2id13(
            profile.outputBytes,
            password,
            salt,
            profile.opslimit,
            profile.memlimit,
          ),
        ),
        profile.outputBytes,
      );
    },

    mac(outputLength: number, message: Uint8Array, key: Uint8Array): Uint8Array {
      if (outputLength !== MAC_BYTES) invalid('outputLength');
      boundedBytes(message, 'message', 0, MAC_MESSAGE_MAX_BYTES);
      exactBytes(key, 'key', KEY_BYTES);
      return expectLength(
        call(() => raw.genericHash(MAC_BYTES, message, key)),
        MAC_BYTES,
      );
    },

    kdf(subkeyLength: number, subkeyId: number, context: string, key: Uint8Array): Uint8Array {
      if (subkeyLength !== KDF_SUBKEY_BYTES) invalid('subkeyLength');
      if (subkeyId !== KDF_SUBKEY_ID) invalid('subkeyId');
      if (!isPrintableAscii8(context) || !ALLOWED_KDF_CONTEXTS.has(context)) invalid('context');
      exactBytes(key, 'key', KEY_BYTES);
      return expectLength(
        call(() => raw.kdfDeriveFromKey(KDF_SUBKEY_BYTES, KDF_SUBKEY_ID, context, key)),
        KDF_SUBKEY_BYTES,
      );
    },

    aeadEncrypt(
      plaintext: Uint8Array,
      additionalData: Uint8Array,
      nonce: Uint8Array,
      key: Uint8Array,
    ): Uint8Array {
      boundedBytes(plaintext, 'plaintext', 0, AEAD_PLAINTEXT_MAX_BYTES);
      boundedBytes(additionalData, 'additionalData', 0, AEAD_ADDITIONAL_DATA_MAX_BYTES);
      exactBytes(nonce, 'nonce', NONCE_BYTES);
      exactBytes(key, 'key', KEY_BYTES);
      return expectLength(
        call(() => raw.aeadEncrypt(plaintext, additionalData, nonce, key)),
        plaintext.length + TAG_BYTES,
      );
    },

    aeadDecrypt(
      ciphertext: Uint8Array,
      additionalData: Uint8Array,
      nonce: Uint8Array,
      key: Uint8Array,
    ): Uint8Array | null {
      boundedBytes(ciphertext, 'ciphertext', TAG_BYTES, AEAD_PLAINTEXT_MAX_BYTES + TAG_BYTES);
      boundedBytes(additionalData, 'additionalData', 0, AEAD_ADDITIONAL_DATA_MAX_BYTES);
      exactBytes(nonce, 'nonce', NONCE_BYTES);
      exactBytes(key, 'key', KEY_BYTES);
      const plaintext = call(() => raw.aeadDecrypt(ciphertext, additionalData, nonce, key));
      return plaintext === null ? null : expectLength(plaintext, ciphertext.length - TAG_BYTES);
    },
  });
}
