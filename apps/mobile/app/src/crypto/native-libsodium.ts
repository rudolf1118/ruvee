import * as sodium from 'react-native-libsodium';

/**
 * Native libsodium through `react-native-libsodium` 1.7.0 (libsodium 1.0.21, prebuilt by the
 * package from the minisign-verified release tarball). Exposed only for the functions the app
 * may route to native code; every output is checked against libsodium.js on the device before
 * use (src/compat/native-checks.ts).
 *
 * Not used for AEAD: the package's `crypto_aead_xchacha20poly1305_ietf_*` takes the additional
 * data only as a JavaScript string and converts it to UTF-8 in C++
 * (`asString(runtime).utf8(runtime)`), so Ruvee's binary AAD cannot be passed. Recorded in
 * docs/mobile/native-compatibility.md.
 */

/** Argon2id v1.3 (`crypto_pwhash_ALG_ARGON2ID13`), checked at call time, not trusted. */
const ALG_ARGON2ID13 = 2;

export function nativeArgon2id(
  outputLength: number,
  password: Uint8Array,
  salt: Uint8Array,
  opslimit: number,
  memlimit: number,
): Uint8Array {
  if (sodium.crypto_pwhash_ALG_ARGON2ID13 !== ALG_ARGON2ID13)
    throw new Error('native libsodium: unexpected Argon2id algorithm id');
  // The package copies views that do not cover their whole buffer; copies here keep the caller's
  // arrays out of the binding entirely.
  return sodium.crypto_pwhash(
    outputLength,
    password.slice(),
    salt.slice(),
    opslimit,
    memlimit,
    ALG_ARGON2ID13,
  );
}

export const nativeSodium = sodium;
