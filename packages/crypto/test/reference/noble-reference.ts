// Independent reference for the provisional Ruvee protocol vectors, written from
// docs/security/cryptographic-design.md with @noble/* only. It must not import anything from
// src/: agreement with the package is only evidence if the two share no code.

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { argon2id } from '@noble/hashes/argon2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { sha256 } from '@noble/hashes/sha2.js';

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

// ---- Recovery, items, manifests and local records (§3.3, §4.3, §5.2-§5.4) ----

function u64(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}

function u16(n: number): Uint8Array {
  return Uint8Array.of(n >>> 8, n & 0xff);
}

function h(...parts: readonly (Uint8Array | readonly number[])[]): Uint8Array {
  return blake2b(cat(...parts), { dkLen: 32 });
}

export function refRecoveryKeys(rk: Uint8Array): { rwk: Uint8Array; rak: Uint8Array } {
  return {
    rwk: blake2b(te.encode('ruvee/v1/recovery-wrap'), { key: rk, dkLen: 32 }),
    rak: blake2b(te.encode('ruvee/v1/recovery-auth'), { key: rk, dkLen: 32 }),
  };
}

export function refRecoveryVerifier(rak: Uint8Array): Uint8Array {
  return sha256(rak);
}

/** §5.4 with a Crockford base32 encoder written from the specification at crockford.com. */
export function refRecoveryKeyText(rk: Uint8Array): string {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const bytes = cat(rk, h(te.encode('ruvee/v1/rk-check'), rk).slice(0, 2));
  let bits = '';
  for (const b of bytes) bits += b.toString(2).padStart(8, '0');
  while (bits.length % 5 !== 0) bits += '0';
  let symbols = '';
  for (let i = 0; i < bits.length; i += 5)
    symbols += alphabet.charAt(parseInt(bits.slice(i, i + 5), 2));
  const groups: string[] = [];
  for (let i = 0; i < symbols.length; i += 5) groups.push(symbols.slice(i, i + 5));
  return ['RK1', ...groups].join('-');
}

export function refRecoveryWrapContext(
  accountId: Uint8Array,
  akId: Uint8Array,
  akEpoch: number,
): Uint8Array {
  return cat(accountId, akId, u32(akEpoch));
}

/** ISO/IEC 7816-4 to a multiple of 256, written independently of src/padding.ts. */
export function refPad(body: Uint8Array): Uint8Array {
  const out = new Uint8Array((Math.floor(body.length / 256) + 1) * 256);
  out.set(body);
  out[body.length] = 0x80;
  return out;
}

export function refItemRecord(args: {
  vk: Uint8Array;
  vkId: Uint8Array;
  vaultId: Uint8Array;
  itemId: Uint8Array;
  ik: Uint8Array;
  ikId: Uint8Array;
  revision: number;
  schemaVersion: number;
  body: Uint8Array;
  keyNonce: Uint8Array;
  bodyNonce: Uint8Array;
}): Uint8Array {
  const keyEnvelope = refEnvelope(
    0x04,
    args.vk,
    args.vkId,
    args.keyNonce,
    cat(args.vaultId, args.itemId, args.ikId),
    args.ik,
  );
  const bodyEnvelope = refEnvelope(
    0x05,
    args.ik,
    args.ikId,
    args.bodyNonce,
    cat(args.vaultId, args.itemId, u64(args.revision), u16(args.schemaVersion)),
    refPad(args.body),
  );
  return cat(
    te.encode('RVI'),
    [1],
    u32(keyEnvelope.length),
    keyEnvelope,
    u32(bodyEnvelope.length),
    bodyEnvelope,
  );
}

export function refRecordHash(record: Uint8Array): Uint8Array {
  return h(te.encode('ruvee/v1/record-hash'), record);
}

export function refItemsDigest(
  entries: readonly { itemId: Uint8Array; revision: number; recordHash: Uint8Array | null }[],
): Uint8Array {
  const sorted = [...entries].sort((a, b) => {
    for (let i = 0; i < 16; i++) {
      const d = (a.itemId[i] ?? 0) - (b.itemId[i] ?? 0);
      if (d !== 0) return d;
    }
    return 0;
  });
  return h(
    te.encode('ruvee/v1/items-digest'),
    u32(sorted.length),
    ...sorted.map((e) =>
      cat(e.itemId, u64(e.revision), [e.recordHash ? 1 : 2], e.recordHash ?? new Uint8Array(32)),
    ),
  );
}

export function refManifestPlaintext(m: {
  vaultId: Uint8Array;
  seq: number;
  prevManifestHash: Uint8Array;
  itemsDigest: Uint8Array;
  liveCount: number;
  tombstoneCount: number;
  authorDeviceId: Uint8Array;
  createdAtMs: number;
  commitId: Uint8Array;
}): Uint8Array {
  return cat(
    [1],
    m.vaultId,
    u64(m.seq),
    m.prevManifestHash,
    m.itemsDigest,
    u32(m.liveCount),
    u32(m.tombstoneCount),
    m.authorDeviceId,
    u64(m.createdAtMs),
    m.commitId,
  );
}

export function refManifestContext(vaultId: Uint8Array, seq: number): Uint8Array {
  return cat(vaultId, u64(seq));
}

export function refManifestHash(envelope: Uint8Array): Uint8Array {
  return h(te.encode('ruvee/v1/manifest-hash'), envelope);
}

export function refLocalContext(deviceId: Uint8Array, name: string): Uint8Array {
  const n = te.encode(name);
  return cat(deviceId, u32(n.length), n);
}
