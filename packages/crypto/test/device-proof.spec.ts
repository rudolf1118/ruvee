// Device proof of possession (docs/security/device-proof.md, D-31 A; not reviewed). The Ed25519
// mapping is checked against RFC 8032's published test vectors; the signed-byte layout and the
// payload encoding are checked against an independent noble BLAKE2b computation of §4.

import { blake2b } from '@noble/hashes/blake2.js';
import { initRuveeCrypto, PROOF_OPERATIONS, type RuveeCrypto } from '../src/index.js';
import { loadLibsodiumPrimitives } from '../src/libsodium.js';
import { guardPrimitives, KDF_CONTEXTS, type Primitives } from '../src/primitives.js';

const hex = (text: string) => Uint8Array.from(Buffer.from(text, 'hex'));
const te = new TextEncoder();
const cat = (...parts: (Uint8Array | number[])[]) => Uint8Array.from(parts.flatMap((p) => [...p]));
const lp = (bytes: Uint8Array) =>
  cat([0, 0, (bytes.length >> 8) & 0xff, bytes.length & 0xff], bytes);
const fill = (n: number, v: number) => new Uint8Array(n).fill(v);

let p: Primitives;
let crypto: RuveeCrypto;

beforeAll(async () => {
  p = guardPrimitives(await loadLibsodiumPrimitives());
  crypto = await initRuveeCrypto();
});

describe('Ed25519 through the guarded primitives (RFC 8032 §7.1)', () => {
  it('TEST 2 and TEST 3: seed → public key, and the deterministic signature', () => {
    for (const v of [
      {
        seed: '4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb',
        pk: '3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c',
        msg: '72',
        sig: '92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00',
      },
      {
        seed: 'c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7',
        pk: 'fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025',
        msg: 'af82',
        sig: '6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a',
      },
    ]) {
      const pair = p.signSeedKeypair(hex(v.seed));
      expect(pair.publicKey).toEqual(hex(v.pk));
      const sig = p.sign(hex(v.msg), pair.privateKey);
      expect(sig).toEqual(hex(v.sig));
      expect(p.verify(sig, hex(v.msg), hex(v.pk))).toBe(true);
      const bad = sig.slice();
      bad[0] = (bad[0] ?? 0) ^ 1;
      expect(p.verify(bad, hex(v.msg), hex(v.pk))).toBe(false);
    }
  });

  it('refuses keys, signatures and messages of the wrong size', () => {
    const pair = p.signKeypair();
    expect(() => p.sign(new Uint8Array(0), pair.privateKey)).toThrow();
    expect(() => p.sign(fill(257, 1), pair.privateKey)).toThrow();
    expect(() => p.sign(fill(8, 1), pair.privateKey.subarray(0, 32))).toThrow();
    expect(() => p.verify(fill(63, 0), fill(8, 1), pair.publicKey)).toThrow();
    expect(() => p.signSeedKeypair(fill(31, 0))).toThrow();
  });
});

describe('signed bytes of device-proof.md §4', () => {
  const accountId = fill(16, 0x0a);
  const deviceId = fill(16, 0x0d);
  const accountKeyId = fill(16, 0x0e);
  const binding = fill(32, 0xb1);
  const nonce = fill(32, 0x4e);
  const payload = fill(32, 0x9a);
  const base = { operation: 'password_change_v2' as const, accountId, binding, nonce, payload };

  it('the payload hash is H(domain ‖ u8(op) ‖ LP(f₁) ‖ …), as computed independently', () => {
    const fields = [fill(3, 1), { u8: 1 }, { u32: 7 }, { u64: 9 }, { text: 'lost' }, null];
    const expected = blake2b(
      cat(
        te.encode('ruvee/v1/proof-payload'),
        [PROOF_OPERATIONS.password_change_v2],
        lp(fill(3, 1)),
        lp(Uint8Array.of(1)),
        lp(Uint8Array.of(0, 0, 0, 7)),
        lp(Uint8Array.of(0, 0, 0, 0, 0, 0, 0, 9)),
        lp(te.encode('lost')),
        lp(new Uint8Array(0)),
      ),
      { dkLen: 32 },
    );
    expect(crypto.proofPayload('password_change_v2', fields)).toEqual(expected);
    // Length prefixes keep field boundaries: ("ab","c") ≠ ("a","bc"); the operation is covered.
    const ab = crypto.proofPayload('device_revoke', [te.encode('ab'), te.encode('c')]);
    expect(ab).not.toEqual(crypto.proofPayload('device_revoke', [te.encode('a'), te.encode('bc')]));
    expect(ab).not.toEqual(
      crypto.proofPayload('pairing_approve', [te.encode('ab'), te.encode('c')]),
    );
  });

  it('the bindings are domain-separated hashes of the login, setup and session ids', () => {
    const id = fill(16, 0x33);
    expect(crypto.loginBinding(id)).toEqual(
      blake2b(cat(te.encode('ruvee/v1/login-ref'), id), { dkLen: 32 }),
    );
    expect(crypto.sessionRef(id)).toEqual(
      blake2b(cat(te.encode('ruvee/v1/session-ref'), id), { dkLen: 32 }),
    );
    const token = fill(32, 0x44);
    expect(crypto.setupBinding(token)).toEqual(
      blake2b(cat(te.encode('ruvee/v1/setup-ref'), token), { dkLen: 32 }),
    );
  });

  it('a device signature covers every field, and only verifies with its own key', () => {
    const key = crypto.generateDeviceKey();
    const input = { ...base, deviceId };
    const signature = crypto.signDeviceProof({ ...input, secretKey: key.secretKey });
    // The signed input is exactly DSI: checked by verifying it as raw Ed25519.
    const dsi = cat(
      te.encode('ruvee/v1/device-proof'),
      [1, PROOF_OPERATIONS.password_change_v2],
      accountId,
      deviceId,
      binding,
      nonce,
      payload,
    );
    expect(dsi.length).toBe(151);
    expect(p.verify(signature, dsi, key.publicKey)).toBe(true);
    const ok = { ...input, publicKey: key.publicKey, signature };
    expect(crypto.verifyDeviceProof(ok)).toBe(true);
    for (const [label, over] of [
      ['operation', { operation: 'secret_key_rotate' }],
      ['account', { accountId: fill(16, 0x0b) }],
      ['device', { deviceId: fill(16, 0x0c) }],
      ['session or login', { binding: fill(32, 0xb2) }],
      ['nonce', { nonce: fill(32, 0x4f) }],
      ['payload', { payload: fill(32, 0x9b) }],
      ['substituted key', { publicKey: crypto.generateDeviceKey().publicKey }],
    ] as const)
      expect(crypto.verifyDeviceProof({ ...ok, ...over }), label).toBe(false);
  });

  it('the AK-derived key is deterministic, separate from K_local, and never verifies as a device', () => {
    const accountKey = crypto.generateKey();
    const avpk = crypto.accountProofPublicKey(accountKey);
    expect(crypto.accountProofPublicKey(accountKey)).toEqual(avpk);
    expect(crypto.accountProofPublicKey(crypto.generateKey())).not.toEqual(avpk);
    // seed = KDF(AK, "rvakver1"), which differs from every other AK derivation.
    const seed = p.kdf(32, 1, KDF_CONTEXTS.accountProof, accountKey);
    expect(p.signSeedKeypair(seed).publicKey).toEqual(avpk);
    expect(seed).not.toEqual(p.kdf(32, 1, KDF_CONTEXTS.local, accountKey));
    const input = { ...base, accountKeyId, accountKeyEpoch: 3 };
    const signature = crypto.signAccountProof({ ...input, accountKey });
    expect(crypto.verifyAccountProof({ ...input, publicKey: avpk, signature })).toBe(true);
    for (const [label, over] of [
      ['ak_id', { accountKeyId: fill(16, 0x0f) }],
      ['ak_epoch', { accountKeyEpoch: 4 }],
      ['payload', { payload: fill(32, 0x9b) }],
    ] as const)
      expect(
        crypto.verifyAccountProof({ ...input, ...over, publicKey: avpk, signature }),
        label,
      ).toBe(false);
    // Same 16 bytes in the device-id position: different domain, never accepted as a device.
    expect(
      crypto.verifyDeviceProof({ ...base, deviceId: accountKeyId, publicKey: avpk, signature }),
    ).toBe(false);
  });

  it('refuses unknown operations and malformed fields', () => {
    expect(() => crypto.proofPayload('delete_everything' as 'login', [])).toThrow();
    // Op 4, the password change before follow-up review F-4, is retired and signs nothing.
    expect(() => crypto.proofPayload('password_change' as 'login', [])).toThrow();
    expect(Object.values(PROOF_OPERATIONS)).not.toContain(4);
    expect(() => crypto.proofPayload('login', [{ u8: 256 }])).toThrow();
    expect(() => crypto.proofPayload('login', [{ u64: -1 }])).toThrow();
    const key = crypto.generateDeviceKey();
    expect(() =>
      crypto.signDeviceProof({ ...base, deviceId: fill(15, 1), secretKey: key.secretKey }),
    ).toThrow();
  });
});
