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
  /** `crypto_hash_sha256`, used only for the recovery verifier `SHA-256(RAK)`. */
  sha256(message: Uint8Array): Uint8Array;
  /** `crypto_kdf_derive_from_key`. */
  kdfDeriveFromKey(
    subkeyLength: number,
    subkeyId: number,
    context: string,
    key: Uint8Array,
  ): Uint8Array;
  /** `crypto_box_keypair`: an X25519 key pair for one pairing. */
  boxKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array };
  /** `crypto_box_seal`. */
  boxSeal(message: Uint8Array, publicKey: Uint8Array): Uint8Array;
  /** `crypto_box_seal_open`; `null` when the box does not open. */
  boxSealOpen(
    ciphertext: Uint8Array,
    publicKey: Uint8Array,
    privateKey: Uint8Array,
  ): Uint8Array | null;
  /** `crypto_sign_keypair`: a random Ed25519 key pair (device-proof.md §2). */
  signKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array };
  /** `crypto_sign_seed_keypair`: the Ed25519 key pair of a 32-byte seed. */
  signSeedKeypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
  /** `crypto_sign_detached`. */
  signDetached(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
  /** `crypto_sign_verify_detached`; false for any invalid signature. */
  signVerifyDetached(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
  /** `sodium_memcmp`: constant-time equality of two equal-length buffers. */
  memcmp(a: Uint8Array, b: Uint8Array): boolean;
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
export const HASH_BYTES = 32;
export const SHA256_BYTES = 32;
/** `RK` is 16 bytes and keys BLAKE2b directly (§3.3); every other MAC key is 32 bytes. */
const MAC_KEY_SIZES: ReadonlySet<number> = new Set([16, 32]);
export const KDF_SUBKEY_BYTES = 32;
export const KDF_SUBKEY_ID = 1;

/** Byte sizes the package ever asks the CSPRNG for: ids and salts, nonces, keys. */
const RANDOM_SIZES: ReadonlySet<number> = new Set([16, 24, 32]);

/**
 * KDF contexts in use (cryptographic-design §3.3). `rvdevlb1` (device labels) waits for the
 * label plaintext rule and is refused.
 */
export const KDF_CONTEXTS = {
  keyset: 'rvkeyst1',
  local: 'rvlocal1',
  manifest: 'rvmanif1',
  /** The seed of `AVSK`, the `AK`-derived signing key (device-proof.md §2). */
  accountProof: 'rvakver1',
} as const;
const ALLOWED_KDF_CONTEXTS: ReadonlySet<string> = new Set(Object.values(KDF_CONTEXTS));

/**
 * Largest message given to the MAC: the pairing response MAC covers the sealed box (at most
 * 4,096 bytes) plus 67 bytes of labels and ids.
 */
export const MAC_MESSAGE_MAX_BYTES = 8192;
export const BOX_PUBLIC_KEY_BYTES = 32;
export const SIGN_PUBLIC_KEY_BYTES = 32;
/** libsodium's Ed25519 secret key: the 32-byte seed followed by the public key. */
export const SIGN_SECRET_KEY_BYTES = 64;
export const SIGN_SEED_BYTES = 32;
export const SIGNATURE_BYTES = 64;
/** The signed inputs of device-proof.md §4 are 151 bytes each; nothing larger is signed. */
export const SIGN_MESSAGE_MAX_BYTES = 256;
export const BOX_SEAL_OVERHEAD_BYTES = 48;
/** Largest sealed-box plaintext: the pairing payload (device-enrollment §3.2 step 8). */
export const BOX_PLAINTEXT_MAX_BYTES = 4096 - BOX_SEAL_OVERHEAD_BYTES;
/**
 * Largest message given to the unkeyed hash: `items_digest` over 57-byte entries. 8 MiB covers
 * about 147,000 items, far above the V1 vault size; a larger vault fails closed.
 */
export const HASH_MESSAGE_MAX_BYTES = 8 * 1024 * 1024;
/** Largest message given to SHA-256: `RAK` is 32 bytes. */
const SHA256_MESSAGE_MAX_BYTES = 64;
/** Largest plaintext of an implemented purpose (`LOCAL_RECORD`, 1 MiB). */
export const AEAD_PLAINTEXT_MAX_BYTES = 1024 * 1024;
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
  /** Unkeyed BLAKE2b-256, `H(msg)` in §2. */
  hash(message: Uint8Array): Uint8Array;
  sha256(message: Uint8Array): Uint8Array;
  boxKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array };
  boxSeal(message: Uint8Array, publicKey: Uint8Array): Uint8Array;
  boxSealOpen(
    ciphertext: Uint8Array,
    publicKey: Uint8Array,
    privateKey: Uint8Array,
  ): Uint8Array | null;
  /** Constant-time comparison of two 32-byte MACs. */
  macEqual(a: Uint8Array, b: Uint8Array): boolean;
  signKeypair(): { publicKey: Uint8Array; privateKey: Uint8Array };
  signSeedKeypair(seed: Uint8Array): { publicKey: Uint8Array; privateKey: Uint8Array };
  sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean;
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
      if (!isBytes(key) || !MAC_KEY_SIZES.has(key.length)) invalid('key');
      return expectLength(
        call(() => raw.genericHash(MAC_BYTES, message, key)),
        MAC_BYTES,
      );
    },

    hash(message: Uint8Array): Uint8Array {
      boundedBytes(message, 'message', 0, HASH_MESSAGE_MAX_BYTES);
      return expectLength(
        call(() => raw.genericHash(HASH_BYTES, message, null)),
        HASH_BYTES,
      );
    },

    sha256(message: Uint8Array): Uint8Array {
      boundedBytes(message, 'message', 0, SHA256_MESSAGE_MAX_BYTES);
      return expectLength(
        call(() => raw.sha256(message)),
        SHA256_BYTES,
      );
    },

    boxKeypair() {
      const pair = call(() => raw.boxKeypair());
      return {
        publicKey: expectLength(pair.publicKey, BOX_PUBLIC_KEY_BYTES),
        privateKey: expectLength(pair.privateKey, BOX_PUBLIC_KEY_BYTES),
      };
    },

    boxSeal(message: Uint8Array, publicKey: Uint8Array): Uint8Array {
      boundedBytes(message, 'message', 0, BOX_PLAINTEXT_MAX_BYTES);
      exactBytes(publicKey, 'publicKey', BOX_PUBLIC_KEY_BYTES);
      return expectLength(
        call(() => raw.boxSeal(message, publicKey)),
        message.length + BOX_SEAL_OVERHEAD_BYTES,
      );
    },

    boxSealOpen(ciphertext: Uint8Array, publicKey: Uint8Array, privateKey: Uint8Array) {
      boundedBytes(
        ciphertext,
        'ciphertext',
        BOX_SEAL_OVERHEAD_BYTES,
        BOX_PLAINTEXT_MAX_BYTES + BOX_SEAL_OVERHEAD_BYTES,
      );
      exactBytes(publicKey, 'publicKey', BOX_PUBLIC_KEY_BYTES);
      exactBytes(privateKey, 'privateKey', BOX_PUBLIC_KEY_BYTES);
      const plaintext = call(() => raw.boxSealOpen(ciphertext, publicKey, privateKey));
      return plaintext === null
        ? null
        : expectLength(plaintext, ciphertext.length - BOX_SEAL_OVERHEAD_BYTES);
    },

    signKeypair() {
      const pair = call(() => raw.signKeypair());
      return {
        publicKey: expectLength(pair.publicKey, SIGN_PUBLIC_KEY_BYTES),
        privateKey: expectLength(pair.privateKey, SIGN_SECRET_KEY_BYTES),
      };
    },

    signSeedKeypair(seed: Uint8Array) {
      exactBytes(seed, 'seed', SIGN_SEED_BYTES);
      const pair = call(() => raw.signSeedKeypair(seed));
      return {
        publicKey: expectLength(pair.publicKey, SIGN_PUBLIC_KEY_BYTES),
        privateKey: expectLength(pair.privateKey, SIGN_SECRET_KEY_BYTES),
      };
    },

    sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array {
      boundedBytes(message, 'message', 1, SIGN_MESSAGE_MAX_BYTES);
      exactBytes(privateKey, 'privateKey', SIGN_SECRET_KEY_BYTES);
      return expectLength(
        call(() => raw.signDetached(message, privateKey)),
        SIGNATURE_BYTES,
      );
    },

    verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean {
      exactBytes(signature, 'signature', SIGNATURE_BYTES);
      boundedBytes(message, 'message', 1, SIGN_MESSAGE_MAX_BYTES);
      exactBytes(publicKey, 'publicKey', SIGN_PUBLIC_KEY_BYTES);
      return call(() => raw.signVerifyDetached(signature, message, publicKey));
    },

    macEqual(a: Uint8Array, b: Uint8Array): boolean {
      exactBytes(a, 'mac', MAC_BYTES);
      exactBytes(b, 'mac', MAC_BYTES);
      return call(() => raw.memcmp(a, b));
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
