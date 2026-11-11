// Category 2: cross-implementation checks for operations with no published vectors, or with
// published vectors that do not reach the exact mode Ruvee proposes. Agreement between
// libsodium.js and @noble/* is evidence, not proof: both can share a defect or a misreading.

import { assert, base64Decode, concat, equal, hex, synthetic, te } from '../bytes.mjs';
import { defineCheck, MAX_KDF_MEMORY_KIB } from '../harness.mjs';

const C = 'cross-implementation';
const LENGTHS = [0, 1, 63, 64, 65, 127, 128, 129, 255, 256, 257, 1000, 65536];

function blake2bAgreement(keyLength) {
  return (ctx) => {
    let n = 0;
    for (const keyIndex of [0, 1, 2]) {
      const key = keyLength ? synthetic(`b2-key-${keyLength}-${keyIndex}`, keyLength) : null;
      for (const len of LENGTHS) {
        const msg = synthetic(`b2-msg-${len}`, len);
        const a = ctx.sodium.crypto_generichash(32, msg, key);
        const b = ctx.noble.blake2b(msg, key ? { dkLen: 32, key } : { dkLen: 32 });
        assert(equal(a, b), `mismatch keyLength=${keyLength} msgLength=${len}`, {
          libsodium: hex(a),
          noble: hex(b),
        });
        n++;
      }
      if (!keyLength) break;
    }
    return { cases: n, outputLength: 32, keyLength, messageLengths: LENGTHS };
  };
}

// libsodium documents crypto_kdf_derive_from_key as
// BLAKE2B-subkeylen(key=key, message={}, salt=subkey_id || {0}, personal=ctx || {0}),
// with subkey_id as 8 little-endian bytes and both salt and personal padded to 16 bytes.
function kdfReference(noble, subkeyLength, id, ctxString, key) {
  const salt = new Uint8Array(16);
  new DataView(salt.buffer).setBigUint64(0, BigInt(id), true);
  const personalization = new Uint8Array(16);
  personalization.set(te.encode(ctxString));
  return noble.blake2b(new Uint8Array(0), { key, dkLen: subkeyLength, salt, personalization });
}

// ISO/IEC 7816-4 padding as sodium_pad documents it: 0x80, then zeros to the next multiple of the
// block size; an exact multiple gains a whole block. Harness reference, not noble.
function isoPad(msg, block) {
  const out = new Uint8Array(msg.length + (block - (msg.length % block)));
  out.set(msg);
  out[msg.length] = 0x80;
  return out;
}

const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

export const crossImplementationChecks = [
  defineCheck({
    id: 'CROSS-BLAKE2B-256-UNKEYED',
    category: C,
    primitive: 'BLAKE2b-256 unkeyed (proposed H)',
    title: 'Unkeyed BLAKE2b-256 over block-boundary message lengths: libsodium equals noble',
    subject: ['libsodium.js crypto_generichash', '@noble/hashes blake2b'],
    expectedFrom: 'agreement only; published coverage is RFC 7693 Appendix E (six input lengths)',
    run: blake2bAgreement(0),
  }),

  defineCheck({
    id: 'CROSS-BLAKE2B-256-KEY16',
    category: C,
    primitive: 'Keyed BLAKE2b-256, 16-byte key (proposed MAC with RK)',
    title: 'Keyed BLAKE2b-256 with 16-byte keys: libsodium equals noble',
    subject: ['libsodium.js crypto_generichash', '@noble/hashes blake2b'],
    expectedFrom: 'agreement only; no published vector uses a 16-byte key',
    run: blake2bAgreement(16),
  }),

  defineCheck({
    id: 'CROSS-BLAKE2B-256-KEY32',
    category: C,
    primitive: 'Keyed BLAKE2b-256, 32-byte key (proposed MAC with SK)',
    title:
      'Keyed BLAKE2b-256 with 32-byte keys over more lengths than RFC 7693 Appendix E: libsodium equals noble',
    subject: ['libsodium.js crypto_generichash', '@noble/hashes blake2b'],
    expectedFrom: 'agreement only; published coverage is RFC 7693 Appendix E (six input lengths)',
    run: blake2bAgreement(32),
  }),

  defineCheck({
    id: 'CROSS-BLAKE2B-SALT-PERSONAL',
    category: C,
    primitive: 'BLAKE2b with salt and personalization',
    title:
      'crypto_generichash_blake2b_salt_personal (empty message) equals noble blake2b with salt and personalization',
    subject: ['libsodium.js crypto_generichash_blake2b_salt_personal', '@noble/hashes blake2b'],
    expectedFrom: 'agreement only; no published BLAKE2b vector uses salt or personalization',
    notes:
      'libsodium.js exposes this function without a message parameter; the message is always empty.',
    run: (ctx) => {
      let n = 0;
      for (const keyLength of [0, 16, 32, 64])
        for (const outLength of [16, 32, 64]) {
          const key = keyLength ? synthetic(`sp-key-${keyLength}`, keyLength) : null;
          const salt = synthetic(`sp-salt-${keyLength}-${outLength}`, 16);
          const personal = synthetic(`sp-pers-${keyLength}-${outLength}`, 16);
          const a = ctx.sodium.crypto_generichash_blake2b_salt_personal(
            outLength,
            key,
            salt,
            personal,
          );
          const opts = {
            dkLen: outLength,
            salt,
            personalization: personal,
            ...(key ? { key } : {}),
          };
          const b = ctx.noble.blake2b(new Uint8Array(0), opts);
          assert(equal(a, b), `mismatch keyLength=${keyLength} outLength=${outLength}`);
          n++;
        }
      return { cases: n };
    },
  }),

  defineCheck({
    id: 'CROSS-KDF-DERIVE-FROM-KEY',
    category: C,
    primitive: 'crypto_kdf_derive_from_key (BLAKE2b with salt and personalization)',
    title:
      'crypto_kdf_derive_from_key equals the documented BLAKE2b definition computed with noble',
    subject: ['libsodium.js crypto_kdf_derive_from_key', '@noble/hashes blake2b'],
    expectedFrom:
      'agreement with the definition in the libsodium documentation: BLAKE2B-subkeylen(key, message={}, salt=LE64(subkey_id)||0^8, personal=ctx||0^8)',
    notes:
      "libsodium's own test expectations for this function come from the implementation under test and are not used.",
    run: (ctx) => {
      const ids = [0, 1, 2, 2 ** 31 - 1, 2n ** 32n, 2n ** 63n, 2n ** 64n - 1n];
      let n = 0;
      for (const c of ['rvkeyst1', 'rvlocal1', 'rvdevlb1', 'rvmanif1', 'AAAAAAAA', '        '])
        for (const id of ids)
          for (const len of [16, 32, 64]) {
            const key = synthetic(`kdf-${c}`, 32);
            const a = ctx.sodium.crypto_kdf_derive_from_key(len, id, c, key);
            const b = kdfReference(ctx.noble, len, id, c, key);
            assert(equal(a, b), `mismatch ctx=${c} id=${id} len=${len}`);
            n++;
          }
      return {
        cases: n,
        proposedUse: 'length 32, subkey id 1, contexts rvkeyst1/rvlocal1/rvdevlb1/rvmanif1',
      };
    },
  }),

  defineCheck({
    id: 'CROSS-ARGON2ID-PWHASH',
    category: C,
    primitive: 'Argon2id v1.3 through crypto_pwhash',
    title:
      'crypto_pwhash(ALG_ARGON2ID13) equals noble argon2id with v=0x13, t=opslimit, m=memlimit/1024 KiB, p=1, including the 64 MiB t=3 shape of proposed profile 1',
    subject: ['libsodium.js crypto_pwhash', '@noble/hashes argon2id'],
    expectedFrom:
      'agreement only; noble is trusted for Argon2id only because it passes RFC 9106 §5.3 and the reference test.c vectors',
    heavy: true,
    run: (ctx) => {
      const cases = [
        { t: 1, mKiB: 8, out: 32 },
        { t: 1, mKiB: 8, out: 16 },
        { t: 2, mKiB: 1024, out: 64 },
        { t: 3, mKiB: 64 * 1024, out: 32 },
      ];
      const done = [];
      for (const c of cases) {
        assert(c.mKiB <= MAX_KDF_MEMORY_KIB, 'case exceeds the memory bound');
        for (const pw of [synthetic(`pw-${c.t}-${c.mKiB}`, 24), 'synthetic ascii password']) {
          const salt = synthetic(`salt-${c.t}-${c.mKiB}-${typeof pw}`, 16);
          const a = ctx.sodium.crypto_pwhash(
            c.out,
            pw,
            salt,
            c.t,
            c.mKiB * 1024,
            ctx.sodium.crypto_pwhash_ALG_ARGON2ID13,
          );
          const b = ctx.noble.argon2id(typeof pw === 'string' ? te.encode(pw) : pw, salt, {
            t: c.t,
            m: c.mKiB,
            p: 1,
            version: 0x13,
            dkLen: c.out,
          });
          assert(
            equal(a, b),
            `mismatch t=${c.t} m=${c.mKiB} KiB out=${c.out} password=${typeof pw}`,
          );
        }
        done.push(c);
      }
      return { cases: done, passwordForms: ['bytes', 'ASCII string'] };
    },
  }),

  defineCheck({
    id: 'CROSS-ARGON2ID-ENCODED',
    category: C,
    primitive: 'Argon2id v1.3 through crypto_pwhash_str',
    title:
      'The hash in a crypto_pwhash_str string equals noble with the parameters and salt in that string, and equals raw crypto_pwhash',
    subject: ['libsodium.js crypto_pwhash_str, crypto_pwhash', '@noble/hashes argon2id'],
    expectedFrom: 'agreement only',
    run: (ctx) => {
      const out = [];
      for (const [ops, mem] of [
        [1, 8192],
        [2, 1024 * 1024],
      ]) {
        const pw = 'synthetic encoded-string password';
        const encoded = ctx.sodium.crypto_pwhash_str(pw, ops, mem);
        const m = encoded.match(/^\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)\$([^$]+)\$([^$]+)$/);
        assert(m, `unexpected encoding ${encoded}`);
        const [v, mKiB, t, p] = m.slice(1, 5).map(Number);
        const salt = base64Decode(m[5]);
        const hash = base64Decode(m[6]);
        const nob = ctx.noble.argon2id(te.encode(pw), salt, {
          t,
          m: mKiB,
          p,
          version: v,
          dkLen: hash.length,
        });
        assert(equal(nob, hash), `noble disagrees for ${encoded}`);
        const raw = ctx.sodium.crypto_pwhash(
          hash.length,
          pw,
          salt,
          ops,
          mem,
          ctx.sodium.crypto_pwhash_ALG_ARGON2ID13,
        );
        assert(equal(raw, hash), `raw crypto_pwhash disagrees for ${encoded}`);
        out.push({
          opslimit: ops,
          memlimit: mem,
          encodedParameters: { v, mKiB, t, p },
          saltBytes: salt.length,
        });
      }
      return { cases: out };
    },
  }),

  defineCheck({
    id: 'CROSS-XCHACHA-POLY1305-SYNTHETIC',
    category: C,
    primitive: 'XChaCha20-Poly1305-IETF with associated data',
    title:
      'XChaCha20-Poly1305 over plaintext and AAD length grids: libsodium equals noble, each decrypts the other',
    subject: [
      'libsodium.js crypto_aead_xchacha20poly1305_ietf_*',
      '@noble/ciphers xchacha20poly1305',
    ],
    expectedFrom: 'agreement only; published coverage is the draft vector and Wycheproof',
    run: (ctx) => {
      const s = ctx.sodium;
      let n = 0;
      for (const ptLen of [0, 1, 15, 16, 17, 63, 64, 65, 1000, 65537])
        for (const adLen of [0, 1, 16, 17, 1000]) {
          const key = synthetic(`x-key-${ptLen}-${adLen}`, 32);
          const nonce = synthetic(`x-nonce-${ptLen}-${adLen}`, 24);
          const pt = synthetic(`x-pt-${ptLen}`, ptLen);
          const ad = synthetic(`x-ad-${adLen}`, adLen);
          const a = s.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, ad, null, nonce, key);
          const b = ctx.noble.xchacha20poly1305(key, nonce, ad).encrypt(pt);
          assert(equal(a, b), `encrypt mismatch pt=${ptLen} ad=${adLen}`);
          assert(
            equal(s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, b, ad, nonce, key), pt),
            `libsodium cannot open noble output pt=${ptLen} ad=${adLen}`,
          );
          assert(
            equal(ctx.noble.xchacha20poly1305(key, nonce, ad).decrypt(a), pt),
            `noble cannot open libsodium output pt=${ptLen} ad=${adLen}`,
          );
          n++;
        }
      return { cases: n };
    },
  }),

  defineCheck({
    id: 'CROSS-SEALED-BOX',
    category: C,
    primitive: 'crypto_box_seal (proposed pairing design only)',
    title:
      'crypto_box_seal and crypto_box_seal_open interoperate with a noble reconstruction of the documented construction',
    subject: [
      'libsodium.js crypto_box_seal(_open)',
      '@noble/curves x25519, @noble/ciphers hsalsa and xsalsa20poly1305, @noble/hashes blake2b',
    ],
    expectedFrom:
      'agreement with the documented construction: ephemeral_pk || crypto_box(m, nonce = BLAKE2b-192(ephemeral_pk || recipient_pk)); no published vector exists',
    run: (ctx) => {
      const { x25519, hsalsa, xsalsa20poly1305, blake2b } = ctx.noble;
      const boxKey = (sk, pk) => {
        const shared = x25519.getSharedSecret(sk, pk);
        const v = new DataView(shared.buffer, shared.byteOffset, 32);
        const k = Uint32Array.from({ length: 8 }, (_, i) => v.getUint32(i * 4, true));
        const out = new Uint32Array(8);
        hsalsa(SIGMA, k, new Uint32Array(4), out);
        const bytes = new Uint8Array(32);
        const w = new DataView(bytes.buffer);
        out.forEach((x, i) => w.setUint32(i * 4, x, true));
        return bytes;
      };
      const recipientSk = synthetic('seal-recipient-sk', 32);
      const recipientPk = ctx.sodium.crypto_scalarmult_base(recipientSk);
      let n = 0;
      for (const len of [0, 1, 32, 300]) {
        const msg = synthetic(`seal-msg-${len}`, len);
        const sealed = ctx.sodium.crypto_box_seal(msg, recipientPk);
        assert(sealed.length === len + 48, 'sealed length is not len + 48');
        const epk = sealed.subarray(0, 32);
        const nonce = blake2b(concat(epk, recipientPk), { dkLen: 24 });
        const opened = xsalsa20poly1305(boxKey(recipientSk, epk), nonce).decrypt(
          sealed.subarray(32),
        );
        assert(equal(opened, msg), `noble cannot open libsodium sealed box len=${len}`);
        const esk = synthetic(`seal-esk-${len}`, 32);
        const epk2 = x25519.getPublicKey(esk);
        const nonce2 = blake2b(concat(epk2, recipientPk), { dkLen: 24 });
        const sealed2 = concat(
          epk2,
          xsalsa20poly1305(boxKey(esk, recipientPk), nonce2).encrypt(msg),
        );
        assert(
          equal(ctx.sodium.crypto_box_seal_open(sealed2, recipientPk, recipientSk), msg),
          `libsodium cannot open noble sealed box len=${len}`,
        );
        n++;
      }
      return { cases: n };
    },
  }),

  defineCheck({
    id: 'CROSS-PAD-ISO7816',
    category: C,
    primitive: 'sodium_pad / sodium_unpad (ISO/IEC 7816-4)',
    title: 'sodium pad and unpad equal a harness reference of ISO/IEC 7816-4 padding',
    subject: ['libsodium.js pad, unpad', 'harness reference implementation'],
    expectedFrom:
      'agreement with a harness reference; padding is an encoding with no published vectors',
    run: (ctx) => {
      let n = 0;
      for (const block of [1, 16, 256])
        for (const len of [0, 1, 15, 16, 17, 255, 256, 257, 300]) {
          const msg = synthetic(`pad-${len}`, len);
          const p = ctx.sodium.pad(msg, block);
          assert(equal(p, isoPad(msg, block)), `pad mismatch block=${block} len=${len}`);
          assert(
            equal(ctx.sodium.unpad(p, block), msg),
            `unpad mismatch block=${block} len=${len}`,
          );
          n++;
        }
      return { cases: n };
    },
  }),
];
