import { equalBytes } from '@noble/ciphers/utils.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { sha256 } from '@noble/hashes/sha2.js';
import type { RawPrimitives } from '@ruvee/crypto-internal/primitives';
import { nativeArgon2id, nativeSodium as sodium } from './native-libsodium';

/**
 * Ruvee's injected primitive interface (packages/crypto `RawPrimitives`) for React Native.
 * Each function is the same algorithm with the same parameters as libsodium.js on the web;
 * packages/crypto's guard (`guardPrimitives`) checks every size before and after each call, as
 * it does on the web. Nothing here composes primitives or implements one.
 *
 * - Native libsodium 1.0.21 (react-native-libsodium 1.7.0): Argon2id, BLAKE2b, crypto_kdf,
 *   Ed25519, X25519 sealed boxes, the CSPRNG.
 * - @noble/ciphers 2.4.0: XChaCha20-Poly1305-IETF, because the native binding accepts only text
 *   additional data (native-libsodium.ts). noble is the repository's independent reference
 *   implementation (cryptographic-design §8) and passes the same published vectors on the device.
 * - @noble/hashes 2.4.0: SHA-256 (recovery verifier only); the binding has no crypto_hash_sha256.
 * - @noble/ciphers `equalBytes`: constant-time comparison; the binding has no sodium_memcmp.
 *
 * Every input array is copied before it reaches the binding, so a view into a larger buffer is
 * never passed as its whole buffer and the caller's bytes are never aliased by native code.
 */
export function mobilePrimitives(): RawPrimitives {
  const raw: RawPrimitives = {
    randombytesBuf: (length) => sodium.randombytes_buf(length),
    pwhashArgon2id13: (outputLength, password, salt, opslimit, memlimit) =>
      nativeArgon2id(outputLength, password, salt, opslimit, memlimit),
    genericHash: (outputLength, message, key) =>
      sodium.crypto_generichash(outputLength, message.slice(), key ? key.slice() : null),
    sha256: (message) => sha256(message),
    boxKeypair: () => {
      const { publicKey, privateKey } = sodium.crypto_box_keypair();
      return { publicKey, privateKey };
    },
    boxSeal: (message, publicKey) => sodium.crypto_box_seal(message.slice(), publicKey.slice()),
    boxSealOpen: (ciphertext, publicKey, privateKey) => {
      try {
        return sodium.crypto_box_seal_open(
          ciphertext.slice(),
          publicKey.slice(),
          privateKey.slice(),
        );
      } catch {
        return null;
      }
    },
    signKeypair: () => {
      const { publicKey, privateKey } = sodium.crypto_sign_keypair();
      return { publicKey, privateKey };
    },
    signSeedKeypair: (seed) => {
      const { publicKey, privateKey } = sodium.crypto_sign_seed_keypair(seed.slice());
      return { publicKey, privateKey };
    },
    signDetached: (message, privateKey) =>
      sodium.crypto_sign_detached(message.slice(), privateKey.slice()),
    signVerifyDetached: (signature, message, publicKey) => {
      try {
        return sodium.crypto_sign_verify_detached(
          signature.slice(),
          message.slice(),
          publicKey.slice(),
        );
      } catch {
        return false;
      }
    },
    memcmp: (a, b) => equalBytes(a, b),
    kdfDeriveFromKey: (subkeyLength, subkeyId, context, key) =>
      sodium.crypto_kdf_derive_from_key(subkeyLength, subkeyId, context, key.slice()),
    aeadEncrypt: (message, additionalData, nonce, key) =>
      xchacha20poly1305(key, nonce, additionalData).encrypt(message),
    aeadDecrypt: (ciphertext, additionalData, nonce, key) => {
      // Any failure (a bad tag, input shorter than the tag) is one indistinguishable null, as in
      // the libsodium.js adapter (cryptographic-design §4.4).
      try {
        return xchacha20poly1305(key, nonce, additionalData).decrypt(ciphertext);
      } catch {
        return null;
      }
    },
  };
  return Object.freeze(raw);
}
