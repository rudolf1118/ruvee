// Category 1: published known-answer tests. Every expected value comes from ctx.vectors, which is
// parsed from hash-verified published files. No expected value is computed here.

import { assert, attempt, base64Decode, concat, equal, hex, te } from '../bytes.mjs';
import { defineCheck, MAX_KDF_MEMORY_KIB } from '../harness.mjs';

const C = 'published-kat';
const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

function wordsLE(bytes) {
  const v = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return Uint32Array.from({ length: bytes.length / 4 }, (_, i) => v.getUint32(i * 4, true));
}
function bytesLE(words) {
  const out = new Uint8Array(words.length * 4);
  const v = new DataView(out.buffer);
  words.forEach((w, i) => v.setUint32(i * 4, w, true));
  return out;
}

function phcCasesWithinBound(vectors) {
  const run = vectors.argon2Phc.cases.filter((c) => c.mKiB <= MAX_KDF_MEMORY_KIB);
  const excluded = vectors.argon2Phc.cases
    .filter((c) => c.mKiB > MAX_KDF_MEMORY_KIB)
    .map((c) => `t=${c.t} m=${c.mKiB} KiB p=${c.p}: exceeds the ${MAX_KDF_MEMORY_KIB} KiB bound`);
  return { run, excluded };
}

function encodedHash(encoded) {
  return base64Decode(encoded.slice(encoded.lastIndexOf('$') + 1));
}

// AEAD decryption outcome: 'valid' with the plaintext, or 'rejected'.
function decryptOutcome(decrypt) {
  const r = attempt(decrypt);
  return r.threw
    ? { outcome: 'rejected', error: r.error }
    : { outcome: 'valid', plaintext: r.value };
}

function wycheproof(name, encrypt, decrypt) {
  return (ctx) => {
    const failures = [];
    const counts = { valid: 0, invalid: 0, invalidNonceSize: 0 };
    for (const t of ctx.vectors.wycheproof.tests) {
      const e = t.expected;
      const d = decryptOutcome(() => decrypt(ctx, t, concat(e.ct, e.tag)));
      if (e.valid) {
        counts.valid++;
        if (d.outcome !== 'valid' || !equal(d.plaintext, e.msg))
          failures.push({ tcId: t.tcId, expected: 'valid', got: d.outcome, error: d.error });
        const enc = attempt(() => encrypt(ctx, t, e.msg));
        if (enc.threw || !equal(enc.value, concat(e.ct, e.tag)))
          failures.push({
            tcId: t.tcId,
            expected: 'encrypt equals ct||tag',
            got: enc.error ?? 'mismatch',
          });
      } else {
        counts.invalid++;
        if (t.flags.includes('InvalidNonceSize')) counts.invalidNonceSize++;
        if (d.outcome !== 'rejected')
          failures.push({ tcId: t.tcId, expected: 'rejected', got: 'accepted', flags: t.flags });
      }
    }
    assert(failures.length === 0, `${name}: ${failures.length} Wycheproof tests failed`, {
      failures: failures.slice(0, 10),
    });
    return { tests: ctx.vectors.wycheproof.tests.length, ...counts };
  };
}

function x25519Kat(scalarMult) {
  return (ctx) => {
    const x = ctx.vectors.x25519;
    x.vectors.forEach((v, i) =>
      assert(
        equal(scalarMult(ctx, v.scalar, v.u), v.expected.out),
        `§5.2 vector ${i + 1} mismatch`,
      ),
    );
    let k = x.iterated.start;
    let u = x.iterated.start;
    for (let i = 1; i <= 1000; i++) {
      const next = scalarMult(ctx, k, u);
      u = k;
      k = next;
      if (i === 1) assert(equal(k, x.iterated.expected.one), 'after one iteration mismatch');
    }
    assert(equal(k, x.iterated.expected.thousand), 'after 1,000 iterations mismatch');
    const base = new Uint8Array(32);
    base[0] = 9;
    assert(
      equal(scalarMult(ctx, x.dh.a, base), x.dh.expected.A),
      "§6.1 Alice's public key mismatch",
    );
    assert(equal(scalarMult(ctx, x.dh.b, base), x.dh.expected.B), "§6.1 Bob's public key mismatch");
    assert(
      equal(scalarMult(ctx, x.dh.a, x.dh.expected.B), x.dh.expected.K),
      '§6.1 K (Alice) mismatch',
    );
    assert(
      equal(scalarMult(ctx, x.dh.b, x.dh.expected.A), x.dh.expected.K),
      '§6.1 K (Bob) mismatch',
    );
    return { notRun: `1,000,000 iterations (${x.iterated.notRun.reason})` };
  };
}

// RFC 7693 Appendix E, transcribed: deterministic inputs, keyed and unkeyed hashes over the
// published parameter sets, then a BLAKE2b hash of all results compared with blake2b_res.
function rfc7693Selftest(hash) {
  return (ctx) => {
    const s = ctx.vectors.blake2bSelftest;
    const seq = (len, seed) => {
      const out = new Uint8Array(len);
      let a = Math.imul(s.seedMultiplier, seed) >>> 0;
      let b = 1;
      for (let i = 0; i < len; i++) {
        const t = (a + b) >>> 0;
        a = b;
        b = t;
        out[i] = (t >>> 24) & 0xff;
      }
      return out;
    };
    const parts = [];
    for (const outlen of s.mdLengths)
      for (const inlen of s.inLengths) {
        const input = seq(inlen, inlen);
        parts.push(hash(ctx, outlen, input, null));
        parts.push(hash(ctx, outlen, input, seq(outlen, outlen)));
      }
    const grand = hash(ctx, s.grandHashLength, concat(...parts), null);
    assert(equal(grand, s.expected.grandHash), 'grand hash differs from blake2b_res', {
      got: hex(grand),
    });
    return {
      hashes: parts.length,
      outputLengths: s.mdLengths,
      inputLengths: s.inLengths,
      keyLengthsCovered: s.mdLengths,
      note: 'Keyed cases use key length = output length, so a 32-byte key with 32-byte output is covered; a 16-byte key is not.',
    };
  };
}

function blake2bKat(hash) {
  return (ctx) => {
    let i = 0;
    for (const e of ctx.vectors.blake2bKat.entries) {
      assert(
        equal(hash(ctx, 64, e.input, e.key), e.expected.hash),
        `entry ${i} (input ${e.input.length} bytes) mismatch`,
      );
      i++;
    }
    return { entries: i, keyLength: 64, outputLength: 64 };
  };
}

export const publishedKatChecks = [
  defineCheck({
    id: 'KAT-ARGON2ID-RFC9106-NOBLE',
    category: C,
    primitive: 'Argon2id v1.3',
    title: 'RFC 9106 §5.3 Argon2id vector through noble (validates the oracle)',
    subject: ['@noble/hashes argon2id'],
    expectedFrom: 'rfc9106 §5.3',
    vectors: ['argon2Rfc9106'],
    notes:
      'libsodium cannot run this vector: crypto_pwhash fixes p = 1 and has no secret or associated-data input.',
    run: (ctx) => {
      const v = ctx.vectors.argon2Rfc9106;
      assert(v.version === 0x13, `unexpected Argon2 version ${v.version}`);
      const tag = ctx.noble.argon2id(v.password, v.salt, {
        t: v.t,
        m: v.mKiB,
        p: v.p,
        version: v.version,
        key: v.secret,
        personalization: v.associatedData,
        dkLen: v.tagLength,
      });
      assert(equal(tag, v.expected.tag), 'tag mismatch', { got: hex(tag) });
      return { version: '0x13', t: v.t, mKiB: v.mKiB, p: v.p, secret: true, associatedData: true };
    },
  }),

  defineCheck({
    id: 'KAT-ARGON2ID-PHC-LIBSODIUM',
    category: C,
    primitive: 'Argon2id v1.3',
    title: 'Argon2 reference test.c Argon2id vectors through libsodium crypto_pwhash_str_verify',
    subject: ['libsodium.js crypto_pwhash_str_verify (Argon2id core)'],
    expectedFrom: 'phc-argon2-test (Argon2id hashtest() calls)',
    vectors: ['argon2Phc'],
    heavy: true,
    notes:
      'The vectors use 8-byte salts, which crypto_pwhash (16-byte salts only) cannot take, so the encoded-string verifier is used. It exercises the same Argon2id core with the parameters in the string, including p = 2.',
    run: (ctx) => {
      const { run, excluded } = phcCasesWithinBound(ctx.vectors);
      for (const c of run) {
        const label = `t=${c.t} m=${c.mKiB} p=${c.p} pwd=${c.password} salt=${c.salt}`;
        assert(c.version === 0x13, `${label}: unexpected version`);
        assert(
          equal(encodedHash(c.expected.encoded), c.expected.tag),
          `${label}: source hex and encoded tag differ`,
        );
        assert(
          ctx.sodium.crypto_pwhash_str_verify(c.expected.encoded, c.password) === true,
          `${label}: not verified`,
        );
      }
      return { verified: run.length, excluded };
    },
  }),

  defineCheck({
    id: 'KAT-ARGON2ID-PHC-NOBLE',
    category: C,
    primitive: 'Argon2id v1.3',
    title:
      'Argon2 reference test.c Argon2id vectors through noble (p = 1 and p = 2, no secret or AD)',
    subject: ['@noble/hashes argon2id'],
    expectedFrom: 'phc-argon2-test (Argon2id hashtest() calls)',
    vectors: ['argon2Phc'],
    heavy: true,
    run: (ctx) => {
      const { run, excluded } = phcCasesWithinBound(ctx.vectors);
      for (const c of run) {
        const label = `t=${c.t} m=${c.mKiB} p=${c.p} pwd=${c.password} salt=${c.salt}`;
        const tag = ctx.noble.argon2id(te.encode(c.password), te.encode(c.salt), {
          t: c.t,
          m: c.mKiB,
          p: c.p,
          version: c.version,
          dkLen: ctx.vectors.argon2Phc.outLength,
        });
        assert(equal(tag, c.expected.tag), `${label}: tag mismatch`, { got: hex(tag) });
        assert(equal(tag, encodedHash(c.expected.encoded)), `${label}: encoded tag mismatch`);
      }
      return { computed: run.length, excluded };
    },
  }),

  defineCheck({
    id: 'KAT-XCHACHA-DRAFT-A31-LIBSODIUM',
    category: C,
    primitive: 'XChaCha20-Poly1305-IETF',
    title: 'draft-irtf-cfrg-xchacha-03 §A.3.1 AEAD vector with AAD (libsodium encrypt and decrypt)',
    subject: ['libsodium.js crypto_aead_xchacha20poly1305_ietf_*'],
    expectedFrom: 'draft-xchacha-03 §A.3.1',
    vectors: ['xchachaDraft'],
    run: (ctx) => {
      const v = ctx.vectors.xchachaDraft;
      const want = concat(v.expected.ciphertext, v.expected.tag);
      const s = ctx.sodium;
      const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
        v.plaintext,
        v.aad,
        null,
        v.nonce,
        v.key,
      );
      assert(equal(ct, want), 'ciphertext||tag mismatch', { got: hex(ct) });
      const pt = s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, want, v.aad, v.nonce, v.key);
      assert(equal(pt, v.plaintext), 'decryption of the published ciphertext mismatch');
      return { plaintextBytes: v.plaintext.length, aadBytes: v.aad.length };
    },
  }),

  defineCheck({
    id: 'KAT-XCHACHA-DRAFT-A31-NOBLE',
    category: C,
    primitive: 'XChaCha20-Poly1305-IETF',
    title: 'draft-irtf-cfrg-xchacha-03 §A.3.1 AEAD vector with AAD (noble, validates the oracle)',
    subject: ['@noble/ciphers xchacha20poly1305'],
    expectedFrom: 'draft-xchacha-03 §A.3.1',
    vectors: ['xchachaDraft'],
    run: (ctx) => {
      const v = ctx.vectors.xchachaDraft;
      const want = concat(v.expected.ciphertext, v.expected.tag);
      const ct = ctx.noble.xchacha20poly1305(v.key, v.nonce, v.aad).encrypt(v.plaintext);
      assert(equal(ct, want), 'ciphertext||tag mismatch');
      const pt = ctx.noble.xchacha20poly1305(v.key, v.nonce, v.aad).decrypt(want);
      assert(equal(pt, v.plaintext), 'decryption mismatch');
    },
  }),

  defineCheck({
    id: 'KAT-HCHACHA20-DRAFT-221-LIBSODIUM',
    category: C,
    primitive: 'HChaCha20 (XChaCha20 subkey derivation)',
    title: 'draft-irtf-cfrg-xchacha-03 §2.2.1 HChaCha20 vector (libsodium crypto_core_hchacha20)',
    subject: ['libsodium.js crypto_core_hchacha20'],
    expectedFrom: 'draft-xchacha-03 §2.2.1',
    vectors: ['hchacha20'],
    run: (ctx) => {
      const v = ctx.vectors.hchacha20;
      const out = ctx.sodium.crypto_core_hchacha20(v.nonce, v.key, null);
      assert(equal(out, v.expected.subkey), 'subkey mismatch', { got: hex(out) });
    },
  }),

  defineCheck({
    id: 'KAT-HCHACHA20-DRAFT-221-NOBLE',
    category: C,
    primitive: 'HChaCha20 (XChaCha20 subkey derivation)',
    title: 'draft-irtf-cfrg-xchacha-03 §2.2.1 HChaCha20 vector (noble hchacha)',
    subject: ['@noble/ciphers hchacha'],
    expectedFrom: 'draft-xchacha-03 §2.2.1',
    vectors: ['hchacha20'],
    run: (ctx) => {
      const v = ctx.vectors.hchacha20;
      const out = new Uint32Array(8);
      ctx.noble.hchacha(SIGMA, wordsLE(v.key), wordsLE(v.nonce), out);
      assert(equal(bytesLE(out), v.expected.subkey), 'subkey mismatch');
    },
  }),

  defineCheck({
    id: 'KAT-XCHACHA-WYCHEPROOF-LIBSODIUM',
    category: C,
    primitive: 'XChaCha20-Poly1305-IETF',
    title: 'Wycheproof xchacha20_poly1305_test.json, all 315 tests (libsodium)',
    subject: ['libsodium.js crypto_aead_xchacha20poly1305_ietf_*'],
    expectedFrom: 'wycheproof-xchacha',
    vectors: ['wycheproof'],
    notes:
      'Invalid tests only expect rejection. No test asserts an error message or type, because the AEAD cannot report why authentication failed.',
    run: wycheproof(
      'libsodium',
      (ctx, t, msg) =>
        ctx.sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(msg, t.aad, null, t.iv, t.key),
      (ctx, t, ct) =>
        ctx.sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, t.aad, t.iv, t.key),
    ),
  }),

  defineCheck({
    id: 'KAT-XCHACHA-WYCHEPROOF-NOBLE',
    category: C,
    primitive: 'XChaCha20-Poly1305-IETF',
    title: 'Wycheproof xchacha20_poly1305_test.json, all 315 tests (noble)',
    subject: ['@noble/ciphers xchacha20poly1305'],
    expectedFrom: 'wycheproof-xchacha',
    vectors: ['wycheproof'],
    run: wycheproof(
      'noble',
      (ctx, t, msg) => ctx.noble.xchacha20poly1305(t.key, t.iv, t.aad).encrypt(msg),
      (ctx, t, ct) => ctx.noble.xchacha20poly1305(t.key, t.iv, t.aad).decrypt(ct),
    ),
  }),

  defineCheck({
    id: 'KAT-BLAKE2B-RFC7693-A-LIBSODIUM',
    category: C,
    primitive: 'BLAKE2b unkeyed',
    title: 'RFC 7693 Appendix A BLAKE2b-512("abc") (libsodium crypto_generichash)',
    subject: ['libsodium.js crypto_generichash'],
    expectedFrom: 'rfc7693 Appendix A',
    vectors: ['blake2bAbc'],
    run: (ctx) => {
      const v = ctx.vectors.blake2bAbc;
      assert(
        equal(ctx.sodium.crypto_generichash(v.outLength, v.input, null), v.expected.hash),
        'mismatch',
      );
    },
  }),

  defineCheck({
    id: 'KAT-BLAKE2B-RFC7693-A-NOBLE',
    category: C,
    primitive: 'BLAKE2b unkeyed',
    title: 'RFC 7693 Appendix A BLAKE2b-512("abc") (noble)',
    subject: ['@noble/hashes blake2b'],
    expectedFrom: 'rfc7693 Appendix A',
    vectors: ['blake2bAbc'],
    run: (ctx) => {
      const v = ctx.vectors.blake2bAbc;
      assert(
        equal(ctx.noble.blake2b(v.input, { dkLen: v.outLength }), v.expected.hash),
        'mismatch',
      );
    },
  }),

  defineCheck({
    id: 'KAT-BLAKE2B-RFC7693-E-LIBSODIUM',
    category: C,
    primitive: 'BLAKE2b unkeyed and keyed, outputs 20/32/48/64',
    title:
      'RFC 7693 Appendix E self-test grand hash (libsodium), covers BLAKE2b-256 unkeyed and with a 32-byte key',
    subject: ['libsodium.js crypto_generichash'],
    expectedFrom: 'rfc7693 Appendix E (blake2b_res)',
    vectors: ['blake2bSelftest'],
    notes:
      'The published value is a hash of 48 results, so a failure does not identify which case differs.',
    run: rfc7693Selftest((ctx, outlen, input, key) =>
      ctx.sodium.crypto_generichash(outlen, input, key),
    ),
  }),

  defineCheck({
    id: 'KAT-BLAKE2B-RFC7693-E-NOBLE',
    category: C,
    primitive: 'BLAKE2b unkeyed and keyed, outputs 20/32/48/64',
    title: 'RFC 7693 Appendix E self-test grand hash (noble)',
    subject: ['@noble/hashes blake2b'],
    expectedFrom: 'rfc7693 Appendix E (blake2b_res)',
    vectors: ['blake2bSelftest'],
    run: rfc7693Selftest((ctx, outlen, input, key) =>
      ctx.noble.blake2b(input, key ? { dkLen: outlen, key } : { dkLen: outlen }),
    ),
  }),

  defineCheck({
    id: 'KAT-BLAKE2B-REFKAT-LIBSODIUM',
    category: C,
    primitive: 'BLAKE2b keyed, 64-byte key, 64-byte output',
    title: 'BLAKE2 reference blake2b-kat.txt, 256 entries (libsodium)',
    subject: ['libsodium.js crypto_generichash'],
    expectedFrom: 'blake2b-kat',
    vectors: ['blake2bKat'],
    run: blake2bKat((ctx, outlen, input, key) => ctx.sodium.crypto_generichash(outlen, input, key)),
  }),

  defineCheck({
    id: 'KAT-BLAKE2B-REFKAT-NOBLE',
    category: C,
    primitive: 'BLAKE2b keyed, 64-byte key, 64-byte output',
    title: 'BLAKE2 reference blake2b-kat.txt, 256 entries (noble)',
    subject: ['@noble/hashes blake2b'],
    expectedFrom: 'blake2b-kat',
    vectors: ['blake2bKat'],
    run: blake2bKat((ctx, outlen, input, key) => ctx.noble.blake2b(input, { dkLen: outlen, key })),
  }),

  defineCheck({
    id: 'KAT-X25519-RFC7748-LIBSODIUM',
    category: C,
    primitive: 'X25519 (proposed pairing design only)',
    title:
      'RFC 7748 §5.2 vectors, 1 and 1,000 iterations, §6.1 Diffie-Hellman (libsodium crypto_scalarmult)',
    subject: ['libsodium.js crypto_scalarmult'],
    expectedFrom: 'rfc7748 §5.2, §6.1',
    vectors: ['x25519'],
    run: x25519Kat((ctx, k, u) => ctx.sodium.crypto_scalarmult(k, u)),
  }),

  defineCheck({
    id: 'KAT-X25519-RFC7748-NOBLE',
    category: C,
    primitive: 'X25519 (proposed pairing design only)',
    title: 'RFC 7748 §5.2 vectors, 1 and 1,000 iterations, §6.1 Diffie-Hellman (noble)',
    subject: ['@noble/curves x25519'],
    expectedFrom: 'rfc7748 §5.2, §6.1',
    vectors: ['x25519'],
    run: x25519Kat((ctx, k, u) => ctx.noble.x25519.scalarMult(k, u)),
  }),
];
