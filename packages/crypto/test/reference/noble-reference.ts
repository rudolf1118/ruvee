// Independent reference for the provisional Ruvee protocol vectors, written from
// docs/security/cryptographic-design.md with @noble/* only. It must not import anything from
// src/: agreement with the package is only evidence if the two share no code.

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { argon2id } from '@noble/hashes/argon2.js';
import { blake2b } from '@noble/hashes/blake2.js';

const te = new TextEncoder();

function cat(...parts: readonly (Uint8Array | readonly number[])[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

function u32(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

function b64url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/** §3.1 with the platform's own well-formedness check (not the package's scan). */
export function refPasswordBytes(password: string): Uint8Array | 'rejected' {
  if (!(password as unknown as { isWellFormed(): boolean }).isWellFormed()) return 'rejected';
  const bytes = te.encode(password.normalize('NFC'));
  return bytes.length < 1 || bytes.length > 4096 ? 'rejected' : bytes;
}

/** §3.2 profile 1: m = 65,536 KiB, t = 3, p = 1, 32-byte output, Argon2id v1.3. */
export function refPasswordKey(passwordBytes: Uint8Array, salt: Uint8Array): Uint8Array {
  return argon2id(passwordBytes, salt, { t: 3, m: 65_536, p: 1, dkLen: 32, version: 0x13 });
}

/** §3.3 `AUK = MAC(SK, "ruvee/v1/auk" ‖ account_id ‖ u8(profile) ‖ salt_pw ‖ PwK)`. */
export function refAccountUnlockKey(
  secretKey: Uint8Array,
  accountId: Uint8Array,
  profile: number,
  salt: Uint8Array,
  passwordKey: Uint8Array,
): Uint8Array {
  return blake2b(cat(te.encode('ruvee/v1/auk'), accountId, [profile], salt, passwordKey), {
    key: secretKey,
    dkLen: 32,
  });
}

/**
 * §2 `KDF(key, ctx)`, from libsodium's documented definition of `crypto_kdf_derive_from_key`:
 * BLAKE2b(key, message = empty, salt = LE64(subkey id) ‖ 0^8, personal = ctx ‖ 0^8).
 */
export function refKdf(key: Uint8Array, context: string): Uint8Array {
  const salt = new Uint8Array(16);
  salt[0] = 1;
  return blake2b(new Uint8Array(0), {
    key,
    dkLen: 32,
    salt,
    personalization: cat(te.encode(context), new Uint8Array(8)),
  });
}

/** §4 envelope v1 with §4.1 AAD; the nonce is fixed only for vectors. */
export function refEnvelope(
  purpose: number,
  key: Uint8Array,
  keyId: Uint8Array,
  nonce: Uint8Array,
  context: Uint8Array,
  plaintext: Uint8Array,
): Uint8Array {
  const header = cat([0x52, 0x56, 0x01, 0x01, purpose], keyId, nonce);
  const aad = cat(te.encode('ruvee/v1/aad'), header, context);
  return cat(header, xchacha20poly1305(key, nonce, aad).encrypt(plaintext));
}

export function refWrapContext(
  accountId: Uint8Array,
  akEpoch: number,
  profile: number,
  salt: Uint8Array,
): Uint8Array {
  return cat(accountId, u32(akEpoch), [profile], salt);
}

export function refKeysetContext(accountId: Uint8Array, keysetVersion: number): Uint8Array {
  return cat(accountId, u32(keysetVersion));
}

/** §5.1 in compact form with the key order shown there. */
export function refKeysetPlaintext(
  secretKey: Uint8Array,
  vaultId: string,
  vkId: Uint8Array,
  vk: Uint8Array,
): Uint8Array {
  return te.encode(
    `{"v":1,"secretKey":"${b64url(secretKey)}","vaults":[{"vaultId":"${vaultId}","vkId":"${b64url(vkId)}","vk":"${b64url(vk)}"}]}`,
  );
}
