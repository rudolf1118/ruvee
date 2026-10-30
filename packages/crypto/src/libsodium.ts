import type { default as LibsodiumModule } from 'libsodium-wrappers-sumo';
import { RuveeCryptoError } from './errors.js';
import type { RawPrimitives } from './primitives.js';

type Libsodium = typeof LibsodiumModule;

/** The C library inside `libsodium-sumo` 0.8.4, validated by tools/crypto-validation. */
export const PINNED_LIBSODIUM_VERSION = '1.0.22';
/** Argon2id v1.3; checked against the library at load instead of trusting its constant. */
const ALG_ARGON2ID13 = 2;

const REQUIRED_FUNCTIONS = [
  'sodium_version_string',
  'randombytes_buf',
  'crypto_pwhash',
  'crypto_generichash',
  'crypto_hash_sha256',
  'crypto_box_keypair',
  'crypto_box_seal',
  'crypto_box_seal_open',
  'crypto_sign_keypair',
  'crypto_sign_seed_keypair',
  'crypto_sign_detached',
  'crypto_sign_verify_detached',
  'memcmp',
  'crypto_kdf_derive_from_key',
  'crypto_aead_xchacha20poly1305_ietf_encrypt',
  'crypto_aead_xchacha20poly1305_ietf_decrypt',
] as const;

/** Maps the raw interface onto libsodium.js. The instance never leaves this module. */
export function libsodiumPrimitives(sodium: Libsodium): RawPrimitives {
  const raw: RawPrimitives = {
    randombytesBuf: (length) => sodium.randombytes_buf(length),
    pwhashArgon2id13: (outputLength, password, salt, opslimit, memlimit) =>
      sodium.crypto_pwhash(outputLength, password, salt, opslimit, memlimit, ALG_ARGON2ID13),
    genericHash: (outputLength, message, key) =>
      sodium.crypto_generichash(outputLength, message, key),
    sha256: (message) => sodium.crypto_hash_sha256(message),
    boxKeypair: () => sodium.crypto_box_keypair(),
    boxSeal: (message, publicKey) => sodium.crypto_box_seal(message, publicKey),
    boxSealOpen: (ciphertext, publicKey, privateKey) => {
      try {
        return sodium.crypto_box_seal_open(ciphertext, publicKey, privateKey);
      } catch {
        return null;
      }
    },
    signKeypair: () => sodium.crypto_sign_keypair(),
    signSeedKeypair: (seed) => sodium.crypto_sign_seed_keypair(seed),
    signDetached: (message, privateKey) => sodium.crypto_sign_detached(message, privateKey),
    signVerifyDetached: (signature, message, publicKey) => {
      // A malformed signature raises in some builds; it is simply not valid.
      try {
        return sodium.crypto_sign_verify_detached(signature, message, publicKey);
      } catch {
        return false;
      }
    },
    memcmp: (a, b) => sodium.memcmp(a, b),
    kdfDeriveFromKey: (subkeyLength, subkeyId, context, key) =>
      sodium.crypto_kdf_derive_from_key(subkeyLength, subkeyId, context, key),
    aeadEncrypt: (message, additionalData, nonce, key) =>
      sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(message, additionalData, null, nonce, key),
    aeadDecrypt: (ciphertext, additionalData, nonce, key) => {
      // Authentication failures and too-short input raise different error types; neither may be
      // told apart by callers (cryptographic-design §4.4), so both become null.
      try {
        return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
          null,
          ciphertext,
          additionalData,
          nonce,
          key,
        );
      } catch {
        return null;
      }
    },
  };
  return Object.freeze(raw);
}

let loading: Promise<Libsodium> | undefined;

async function load(): Promise<Libsodium> {
  let sodium: Libsodium;
  try {
    sodium = (await import('libsodium-wrappers-sumo')).default;
    await sodium.ready;
  } catch {
    throw new RuveeCryptoError('library_failure', { reason: 'initialization_failed' });
  }
  for (const name of REQUIRED_FUNCTIONS)
    if (typeof sodium[name] !== 'function')
      throw new RuveeCryptoError('library_failure', { reason: 'missing_function' });
  if (
    sodium.sodium_version_string() !== PINNED_LIBSODIUM_VERSION ||
    sodium.crypto_pwhash_ALG_ARGON2ID13 !== ALG_ARGON2ID13
  )
    throw new RuveeCryptoError('library_failure', { reason: 'version_mismatch' });
  return sodium;
}

/** Loads and checks libsodium once per realm. A failed load can be retried. */
export async function loadLibsodiumPrimitives(): Promise<RawPrimitives> {
  loading ??= load();
  try {
    return libsodiumPrimitives(await loading);
  } catch (error) {
    loading = undefined;
    throw error;
  }
}
