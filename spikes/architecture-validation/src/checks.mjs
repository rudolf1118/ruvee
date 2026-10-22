// Compatibility checks shared by every runtime (Node, browser page, Web Worker,
// MV3 service worker). Synthetic inputs only. Nothing here is Ruvee production code
// and nothing here defines Ruvee protocol vectors.

import sodiumModule from 'libsodium-wrappers-sumo';
import * as opaque from '@serenity-kit/opaque';
import { argon2id as nobleArgon2id } from '@noble/hashes/argon2.js';
import { blake2b as nobleBlake2b } from '@noble/hashes/blake2.js';
import { xchacha20poly1305 as nobleXChaCha } from '@noble/ciphers/chacha.js';
import { hsalsa, xsalsa20poly1305 } from '@noble/ciphers/salsa.js';
import { x25519 as nobleX25519 } from '@noble/curves/ed25519.js';

const MiB = 1024 * 1024;
const now = () => globalThis.performance.now();
const te = new TextEncoder();

function hex(u8) {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
}
function unhex(s) {
  const clean = s.replace(/[^0-9a-fA-F]/g, '');
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}
function eq(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}
function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}
// Deterministic synthetic bytes (not random, not secret): BLAKE2b-based counter stream.
function synthetic(label, length) {
  const out = new Uint8Array(length);
  let filled = 0;
  for (let i = 0; filled < length; i++) {
    const block = nobleBlake2b(te.encode(`ruvee-spike/${label}/${i}`), { dkLen: 64 });
    out.set(block.subarray(0, Math.min(64, length - filled)), filled);
    filled += 64;
  }
  return out;
}
function median(xs) {
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}
function errText(e) {
  return e instanceof Error ? `${e.name}: ${e.message}` : String(e);
}

export async function runChecks({ kat, bench = {}, log = () => {} } = {}) {
  const results = [];
  const record = (id, name, status, detail = {}) => {
    results.push({ id, name, status, ...detail });
    log(`${status.toUpperCase().padEnd(4)} ${id} ${name}`);
  };
  async function check(id, name, fn) {
    const t0 = now();
    try {
      const detail = (await fn()) ?? {};
      record(id, name, detail.status ?? 'pass', { ms: Math.round(now() - t0), ...detail });
    } catch (e) {
      record(id, name, 'fail', { ms: Math.round(now() - t0), error: errText(e) });
    }
  }

  const tInit = now();
  await sodiumModule.ready;
  const sodium = sodiumModule;
  const sodiumInitMs = Math.round(now() - tInit);
  const tOpaque = now();
  await opaque.ready;
  const opaqueInitMs = Math.round(now() - tOpaque);

  const env = {
    userAgent: globalThis.navigator?.userAgent ?? null,
    node: globalThis.process?.versions?.node ?? null,
    v8: globalThis.process?.versions?.v8 ?? null,
    scope:
      typeof globalThis.ServiceWorkerGlobalScope !== 'undefined' &&
      globalThis instanceof globalThis.ServiceWorkerGlobalScope
        ? 'service-worker'
        : typeof globalThis.WorkerGlobalScope !== 'undefined' &&
            globalThis instanceof globalThis.WorkerGlobalScope
          ? 'worker'
          : typeof globalThis.document !== 'undefined'
            ? 'window'
            : 'node',
    hardwareConcurrency: globalThis.navigator?.hardwareConcurrency ?? null,
    deviceMemoryGiB: globalThis.navigator?.deviceMemory ?? null,
    sodiumVersion: sodium.sodium_version_string(),
    sodiumLibraryVersion: `${sodium.SODIUM_LIBRARY_VERSION_MAJOR}.${sodium.SODIUM_LIBRARY_VERSION_MINOR}`,
    sodiumInitMs,
    opaqueInitMs,
  };

  // ---------------------------------------------------------------- libsodium surface
  await check('LS-01', 'libsodium constants and required functions', () => {
    const required = [
      'crypto_pwhash',
      'crypto_generichash',
      'crypto_generichash_blake2b_salt_personal',
      'crypto_kdf_derive_from_key',
      'crypto_aead_xchacha20poly1305_ietf_encrypt',
      'crypto_aead_xchacha20poly1305_ietf_decrypt',
      'crypto_box_keypair',
      'crypto_box_seal',
      'crypto_box_seal_open',
      'crypto_scalarmult',
      'crypto_scalarmult_base',
      'crypto_hash_sha256',
      'randombytes_buf',
      'randombytes_uniform',
      'memzero',
      'memcmp',
      'pad',
      'unpad',
    ];
    const missing = required.filter((f) => typeof sodium[f] !== 'function');
    const hkdfExports = Object.keys(sodium).filter((k) => /hkdf/i.test(k));
    const constants = {
      crypto_pwhash_ALG_ARGON2ID13: sodium.crypto_pwhash_ALG_ARGON2ID13,
      crypto_pwhash_ALG_DEFAULT: sodium.crypto_pwhash_ALG_DEFAULT,
      crypto_pwhash_SALTBYTES: sodium.crypto_pwhash_SALTBYTES,
      crypto_pwhash_OPSLIMIT_MIN: sodium.crypto_pwhash_OPSLIMIT_MIN,
      crypto_pwhash_MEMLIMIT_MIN: sodium.crypto_pwhash_MEMLIMIT_MIN,
      crypto_pwhash_MEMLIMIT_MAX: sodium.crypto_pwhash_MEMLIMIT_MAX,
      crypto_pwhash_OPSLIMIT_MODERATE: sodium.crypto_pwhash_OPSLIMIT_MODERATE,
      crypto_pwhash_MEMLIMIT_MODERATE: sodium.crypto_pwhash_MEMLIMIT_MODERATE,
      crypto_generichash_KEYBYTES_MIN: sodium.crypto_generichash_KEYBYTES_MIN,
      crypto_generichash_KEYBYTES_MAX: sodium.crypto_generichash_KEYBYTES_MAX,
      crypto_kdf_CONTEXTBYTES: sodium.crypto_kdf_CONTEXTBYTES,
      crypto_kdf_KEYBYTES: sodium.crypto_kdf_KEYBYTES,
      crypto_aead_xchacha20poly1305_ietf_NPUBBYTES:
        sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES,
      crypto_aead_xchacha20poly1305_ietf_ABYTES: sodium.crypto_aead_xchacha20poly1305_ietf_ABYTES,
      crypto_box_SEALBYTES: sodium.crypto_box_SEALBYTES,
    };
    return { status: missing.length ? 'fail' : 'pass', missing, hkdfExports, constants };
  });

  // ---------------------------------------------------------------- XChaCha20-Poly1305
  const xc = {
    pt: unhex(
      '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e',
    ),
    aad: unhex('50515253c0c1c2c3c4c5c6c7'),
    key: unhex('808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'),
    nonce: unhex('404142434445464748494a4b4c4d4e4f5051525354555657'),
    ct: unhex(
      'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e',
    ),
    tag: unhex('c0875924c1c7987947deafd8780acf49'),
  };
  await check(
    'LS-02',
    'XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 A.3.1 (libsodium and noble)',
    () => {
      const want = concat(xc.ct, xc.tag);
      const lib = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        xc.pt,
        xc.aad,
        null,
        xc.nonce,
        xc.key,
      );
      const nob = nobleXChaCha(xc.key, xc.nonce, xc.aad).encrypt(xc.pt);
      const back = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        null,
        want,
        xc.aad,
        xc.nonce,
        xc.key,
      );
      const ok = eq(lib, want) && eq(nob, want) && eq(back, xc.pt);
      return { status: ok ? 'pass' : 'fail' };
    },
  );

  await check(
    'LS-03',
    'XChaCha20-Poly1305: Wycheproof xchacha20_poly1305_test.json (libsodium)',
    () => {
      if (!kat?.wycheproof) return { status: 'skip', reason: 'vector file not loaded' };
      let passed = 0;
      const failures = [];
      for (const group of kat.wycheproof.testGroups) {
        for (const t of group.tests) {
          let got = 'invalid';
          try {
            const out = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
              null,
              concat(unhex(t.ct), unhex(t.tag)),
              unhex(t.aad),
              unhex(t.iv),
              unhex(t.key),
            );
            got = eq(out, unhex(t.msg)) ? 'valid' : 'mismatch';
          } catch {
            got = 'invalid';
          }
          const expectValid = t.result === 'valid' || t.result === 'acceptable';
          if ((expectValid && got === 'valid') || (!expectValid && got === 'invalid')) passed++;
          else failures.push({ tcId: t.tcId, expected: t.result, got, comment: t.comment });
        }
      }
      return { status: failures.length ? 'fail' : 'pass', passed, failures: failures.slice(0, 10) };
    },
  );

  await check(
    'LS-04',
    'XChaCha20-Poly1305: tampering is detected and reported only as one generic failure',
    () => {
      const ctTag = concat(xc.ct, xc.tag);
      const cases = {
        ciphertextBit: () => {
          const c = ctTag.slice();
          c[0] ^= 1;
          return [c, xc.aad, xc.nonce];
        },
        tagBit: () => {
          const c = ctTag.slice();
          c[c.length - 1] ^= 1;
          return [c, xc.aad, xc.nonce];
        },
        aadBit: () => {
          const a = xc.aad.slice();
          a[0] ^= 1;
          return [ctTag, a, xc.nonce];
        },
        aadEmpty: () => [ctTag, new Uint8Array(0), xc.nonce],
        nonceBit: () => {
          const n = xc.nonce.slice();
          n[23] ^= 1;
          return [ctTag, xc.aad, n];
        },
        truncated: () => [ctTag.subarray(0, 15), xc.aad, xc.nonce],
      };
      const messages = {};
      let allRejected = true;
      for (const [name, make] of Object.entries(cases)) {
        const [c, a, n] = make();
        try {
          sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, c, a, n, xc.key);
          allRejected = false;
          messages[name] = 'ACCEPTED';
        } catch (e) {
          messages[name] = errText(e);
        }
      }
      return { status: allRejected ? 'pass' : 'fail', messages };
    },
  );

  // ---------------------------------------------------------------- BLAKE2b
  await check('LS-05', 'BLAKE2b: RFC 7693 Appendix A, BLAKE2b-512("abc")', () => {
    const want = unhex(
      'BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D17D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923',
    );
    const lib = sodium.crypto_generichash(64, te.encode('abc'), null);
    const nob = nobleBlake2b(te.encode('abc'));
    return { status: eq(lib, want) && eq(nob, want) ? 'pass' : 'fail' };
  });

  await check('LS-06', 'BLAKE2b keyed: BLAKE2 reference blake2b-kat.txt (libsodium)', () => {
    if (!kat?.blake2bKat) return { status: 'skip', reason: 'vector file not loaded' };
    const blocks = kat.blake2bKat.trim().split(/\n\s*\n/);
    let passed = 0;
    let failed = 0;
    for (const b of blocks) {
      const f = Object.fromEntries(b.split('\n').map((l) => l.split(':\t').map((s) => s.trim())));
      const out = sodium.crypto_generichash(64, unhex(f.in ?? ''), unhex(f.key));
      if (eq(out, unhex(f.hash))) passed++;
      else failed++;
    }
    return { status: failed || passed !== 256 ? 'fail' : 'pass', passed, failed };
  });

  await check(
    'LS-07',
    'Keyed BLAKE2b-256 (proposed MAC) with 16- and 32-byte keys: libsodium equals noble',
    () => {
      let n = 0;
      for (const keyLen of [16, 32, 64]) {
        for (const msgLen of [0, 1, 31, 32, 33, 127, 128, 129, 1000]) {
          const key = synthetic(`mac-key-${keyLen}`, keyLen);
          const msg = synthetic(`mac-msg-${msgLen}`, msgLen);
          const a = sodium.crypto_generichash(32, msg, key);
          const b = nobleBlake2b(msg, { key, dkLen: 32 });
          if (!eq(a, b)) throw new Error(`mismatch keyLen=${keyLen} msgLen=${msgLen}`);
          n++;
        }
      }
      let shortKeyError = null;
      try {
        sodium.crypto_generichash(32, new Uint8Array(1), new Uint8Array(15));
      } catch (e) {
        shortKeyError = errText(e);
      }
      return { cases: n, fifteenByteKey: shortKeyError ?? 'ACCEPTED' };
    },
  );

  await check(
    'LS-08',
    'crypto_kdf_derive_from_key equals BLAKE2b(key, salt=LE64(id)||0^8, personal=ctx||0^8, empty input)',
    () => {
      let n = 0;
      for (const ctx of ['rvkeyst1', 'rvlocal1', 'rvdevlb1', 'rvmanif1']) {
        for (const id of [0, 1, 2, 0xffffffffn, 2n ** 64n - 1n]) {
          for (const len of [16, 32, 64]) {
            const key = synthetic(`kdf-key-${ctx}`, 32);
            const a = sodium.crypto_kdf_derive_from_key(len, id, ctx, key);
            const salt = new Uint8Array(16);
            new DataView(salt.buffer).setBigUint64(0, BigInt(id) & (2n ** 64n - 1n), true);
            const personalization = new Uint8Array(16);
            personalization.set(te.encode(ctx));
            const b = nobleBlake2b(new Uint8Array(0), { key, dkLen: len, salt, personalization });
            if (!eq(a, b)) throw new Error(`mismatch ctx=${ctx} id=${id} len=${len}`);
            n++;
          }
        }
      }
      let badContext = null;
      try {
        sodium.crypto_kdf_derive_from_key(32, 1, 'short', new Uint8Array(32));
      } catch (e) {
        badContext = errText(e);
      }
      let largeNumberId = null;
      try {
        sodium.crypto_kdf_derive_from_key(32, 2 ** 31, 'rvkeyst1', new Uint8Array(32));
      } catch (e) {
        largeNumberId = errText(e);
      }
      return {
        cases: n,
        fiveByteContext: badContext ?? 'ACCEPTED',
        numberIdAtOrAbove2pow31: largeNumberId ?? 'ACCEPTED',
      };
    },
  );

  // ---------------------------------------------------------------- Argon2id
  await check(
    'LS-09a',
    'Argon2id: RFC 9106 §5.3 KAT validates the independent implementation (noble)',
    () => {
      const tag = nobleArgon2id(new Uint8Array(32).fill(1), new Uint8Array(16).fill(2), {
        t: 3,
        m: 32,
        p: 4,
        key: new Uint8Array(8).fill(3),
        personalization: new Uint8Array(12).fill(4),
        dkLen: 32,
      });
      const want = unhex('0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659');
      return {
        status: eq(tag, want) ? 'pass' : 'fail',
        note: 'libsodium cannot run this KAT: its API fixes p=1 and has no secret or associated-data input',
      };
    },
  );

  await check(
    'LS-09b',
    'Argon2id: libsodium crypto_pwhash parameter mapping equals noble (v=0x13, m=memlimit/1024 KiB, t=opslimit, p=1)',
    () => {
      const cases = [
        { t: 1, mKiB: 8 },
        { t: 2, mKiB: 19 * 1024 },
        { t: 3, mKiB: 64 * 1024 },
      ];
      const out = [];
      for (const c of cases) {
        const pw = synthetic(`pw-${c.t}-${c.mKiB}`, 24);
        const salt = synthetic(`salt-${c.t}-${c.mKiB}`, 16);
        const a = sodium.crypto_pwhash(
          32,
          pw,
          salt,
          c.t,
          c.mKiB * 1024,
          sodium.crypto_pwhash_ALG_ARGON2ID13,
        );
        const t0 = now();
        const b = nobleArgon2id(pw, salt, { t: c.t, m: c.mKiB, p: 1, dkLen: 32, version: 0x13 });
        const nobleMs = Math.round(now() - t0);
        if (!eq(a, b)) throw new Error(`mismatch t=${c.t} m=${c.mKiB}KiB`);
        out.push({ ...c, nobleMs });
      }
      const pw = synthetic('pw-alg', 24);
      const salt = synthetic('salt-alg', 16);
      const id = sodium.crypto_pwhash(32, pw, salt, 3, 8192, sodium.crypto_pwhash_ALG_ARGON2ID13);
      const i = sodium.crypto_pwhash(32, pw, salt, 3, 8192, sodium.crypto_pwhash_ALG_ARGON2I13);
      return {
        cases: out,
        argon2iDiffers: !eq(id, i),
        parallelism: 'crypto_pwhash has no parallelism parameter; p=1 is implied',
      };
    },
  );

  await check(
    'LS-09c',
    'Argon2id input handling: strings are UTF-8 encoded without normalization; salt length enforced',
    () => {
      const salt = synthetic('salt-norm', 16);
      const nfc = 'caf\u00e9';
      const nfd = 'cafe\u0301';
      const kNfc = sodium.crypto_pwhash(
        32,
        nfc,
        salt,
        1,
        8192,
        sodium.crypto_pwhash_ALG_ARGON2ID13,
      );
      const kNfd = sodium.crypto_pwhash(
        32,
        nfd,
        salt,
        1,
        8192,
        sodium.crypto_pwhash_ALG_ARGON2ID13,
      );
      const kNfdNormalized = sodium.crypto_pwhash(
        32,
        nfd.normalize('NFC'),
        salt,
        1,
        8192,
        sodium.crypto_pwhash_ALG_ARGON2ID13,
      );
      const kBytes = sodium.crypto_pwhash(
        32,
        te.encode(nfc),
        salt,
        1,
        8192,
        sodium.crypto_pwhash_ALG_ARGON2ID13,
      );
      const lone = sodium.crypto_pwhash(
        32,
        'a\ud800b',
        salt,
        1,
        8192,
        sodium.crypto_pwhash_ALG_ARGON2ID13,
      );
      const replacement = sodium.crypto_pwhash(
        32,
        'a\ufffdb',
        salt,
        1,
        8192,
        sodium.crypto_pwhash_ALG_ARGON2ID13,
      );
      let shortSalt = null;
      try {
        sodium.crypto_pwhash(
          32,
          'x',
          new Uint8Array(8),
          1,
          8192,
          sodium.crypto_pwhash_ALG_ARGON2ID13,
        );
      } catch (e) {
        shortSalt = errText(e);
      }
      return {
        nfcDiffersFromNfd: !eq(kNfc, kNfd),
        explicitNormalizationMatches: eq(kNfc, kNfdNormalized),
        stringEqualsUtf8Bytes: eq(kNfc, kBytes),
        loneSurrogateCollidesWithReplacementChar: eq(lone, replacement),
        eightByteSalt: shortSalt ?? 'ACCEPTED',
      };
    },
  );

  // ---------------------------------------------------------------- X25519 and sealed box
  await check('LS-10', 'X25519: RFC 7748 §6.1 (libsodium and noble)', () => {
    const a = unhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
    const b = unhex('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
    const A = unhex('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a');
    const B = unhex('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f');
    const K = unhex('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742');
    const ok =
      eq(sodium.crypto_scalarmult_base(a), A) &&
      eq(sodium.crypto_scalarmult_base(b), B) &&
      eq(sodium.crypto_scalarmult(a, B), K) &&
      eq(nobleX25519.getSharedSecret(b, A), K);
    return { status: ok ? 'pass' : 'fail' };
  });

  // Independent reconstruction of crypto_box_seal from its documented definition:
  // ephemeral X25519 key pair, nonce = BLAKE2b-192(epk || pk), box = XSalsa20-Poly1305 under
  // HSalsa20(X25519(esk, pk), 0^16). Output epk || tag || ciphertext.
  const sigma = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  const toWords = (u8) =>
    new Uint32Array(u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.length));
  function boxKey(secret, publicKey) {
    const shared = nobleX25519.getSharedSecret(secret, publicKey);
    const out = new Uint32Array(8);
    hsalsa(sigma, toWords(shared), new Uint32Array(4), out);
    return new Uint8Array(out.buffer);
  }
  function independentSealOpen(sealed, pk, sk) {
    const epk = sealed.subarray(0, 32);
    const nonce = nobleBlake2b(concat(epk, pk), { dkLen: 24 });
    return xsalsa20poly1305(boxKey(sk, epk), nonce).decrypt(sealed.subarray(32));
  }
  function independentSeal(msg, pk) {
    const esk = synthetic('seal-esk', 32);
    const epk = nobleX25519.getPublicKey(esk);
    const nonce = nobleBlake2b(concat(epk, pk), { dkLen: 24 });
    return concat(epk, xsalsa20poly1305(boxKey(esk, pk), nonce).encrypt(msg));
  }

  await check(
    'LS-11',
    'crypto_box_seal: libsodium and an independent reconstruction interoperate both ways',
    () => {
      const { publicKey, privateKey } = sodium.crypto_box_keypair();
      const msg = synthetic('seal-msg', 300);
      const sealed = sodium.crypto_box_seal(msg, publicKey);
      const opened = independentSealOpen(sealed, publicKey, privateKey);
      const sealed2 = independentSeal(msg, publicKey);
      const opened2 = sodium.crypto_box_seal_open(sealed2, publicKey, privateKey);
      const tampered = sealed.slice();
      tampered[40] ^= 1;
      let tamperRejected = false;
      try {
        sodium.crypto_box_seal_open(tampered, publicKey, privateKey);
      } catch {
        tamperRejected = true;
      }
      const ok =
        eq(opened, msg) && eq(opened2, msg) && sealed.length === msg.length + 48 && tamperRejected;
      return {
        status: ok ? 'pass' : 'fail',
        note: 'no published sealed-box KAT exists; this checks the documented construction',
      };
    },
  );

  await check('LS-12', 'pad/unpad (ISO/IEC 7816-4, block 256), memzero, randombytes', () => {
    const msg = synthetic('pad', 300);
    const padded = sodium.pad(msg, 256);
    const ok1 =
      padded.length === 512 && padded[300] === 0x80 && padded.subarray(301).every((x) => x === 0);
    const ok2 = eq(sodium.unpad(padded, 256), msg);
    const exact = sodium.pad(synthetic('pad2', 256), 256);
    const ok3 = exact.length === 512 && exact[256] === 0x80;
    const buf = synthetic('mz', 32);
    sodium.memzero(buf);
    const ok4 = buf.every((x) => x === 0);
    const r1 = sodium.randombytes_buf(32);
    const r2 = sodium.randombytes_buf(32);
    const ok5 = r1.length === 32 && !eq(r1, r2);
    return { status: ok1 && ok2 && ok3 && ok4 && ok5 ? 'pass' : 'fail', fullBlockAddsBlock: ok3 };
  });

  // ---------------------------------------------------------------- OPAQUE
  const username = 'synthetic-user';
  const instanceId = '00000000-0000-4000-8000-000000000001';
  const identifiers = { client: username, server: instanceId };
  const password = 'correct horse battery staple (synthetic)';
  const serverSetup = opaque.server.createSetup();
  const serverPublicKey = opaque.server.getPublicKey(serverSetup);

  function register(pw, { setup = serverSetup, ids = identifiers, keyStretching } = {}) {
    const { clientRegistrationState, registrationRequest } = opaque.client.startRegistration({
      password: pw,
    });
    const { registrationResponse } = opaque.server.createRegistrationResponse({
      serverSetup: setup,
      userIdentifier: username,
      registrationRequest,
    });
    const t0 = now();
    const fin = opaque.client.finishRegistration({
      clientRegistrationState,
      registrationResponse,
      password: pw,
      identifiers: ids,
      ...(keyStretching ? { keyStretching } : {}),
    });
    return { ...fin, registrationRequest, registrationResponse, finishMs: now() - t0 };
  }
  function login(
    pw,
    record,
    { setup = serverSetup, clientIds = identifiers, serverIds = identifiers, keyStretching } = {},
  ) {
    const { clientLoginState, startLoginRequest } = opaque.client.startLogin({ password: pw });
    const { serverLoginState, loginResponse } = opaque.server.startLogin({
      serverSetup: setup,
      registrationRecord: record,
      startLoginRequest,
      userIdentifier: username,
      identifiers: serverIds,
    });
    const t0 = now();
    const client = opaque.client.finishLogin({
      clientLoginState,
      loginResponse,
      password: pw,
      identifiers: clientIds,
      ...(keyStretching ? { keyStretching } : {}),
    });
    const clientFinishMs = now() - t0;
    return { client, serverLoginState, loginResponse, startLoginRequest, clientFinishMs };
  }

  let reg;
  await check('OP-01', 'OPAQUE registration and login round trip (default key stretching)', () => {
    reg = register(password);
    const l = login(password, reg.registrationRecord);
    if (!l.client) throw new Error('client finishLogin returned undefined');
    const s = opaque.server.finishLogin({
      serverLoginState: l.serverLoginState,
      finishLoginRequest: l.client.finishLoginRequest,
      identifiers,
    });
    const sizes = (s64) => Math.round((s64.length * 3) / 4);
    return {
      status: s.sessionKey === l.client.sessionKey ? 'pass' : 'fail',
      serverKeyReturnedMatchesSetup:
        l.client.serverStaticPublicKey === serverPublicKey &&
        reg.serverStaticPublicKey === serverPublicKey,
      approxBytes: {
        serverSetup: sizes(serverSetup),
        registrationRequest: sizes(reg.registrationRequest),
        registrationResponse: sizes(reg.registrationResponse),
        registrationRecord: sizes(reg.registrationRecord),
        startLoginRequest: sizes(l.startLoginRequest),
        loginResponse: sizes(l.loginResponse),
        finishLoginRequest: sizes(l.client.finishLoginRequest),
      },
      registrationFinishMs: Math.round(reg.finishMs),
      loginClientFinishMs: Math.round(l.clientFinishMs),
    };
  });

  await check(
    'OP-02',
    'OPAQUE default key stretching equals "memory-constrained"; a different preset does not log in',
    () => {
      const explicit = login(password, reg.registrationRecord, {
        keyStretching: 'memory-constrained',
      });
      const p1 = login(password, reg.registrationRecord, {
        keyStretching: { 'argon2id-custom': { iterations: 3, memory: 65536, parallelism: 1 } },
      });
      return {
        status: explicit.client && !p1.client ? 'pass' : 'fail',
        explicitMemoryConstrainedLogsIn: Boolean(explicit.client),
        sameMemoryAndTimeButP1LogsIn: Boolean(p1.client),
        explicitClientFinishMs: Math.round(explicit.clientFinishMs),
      };
    },
  );

  await check('OP-03', 'OPAQUE wrong password: client finishLogin returns undefined', () => {
    const l = login('wrong password (synthetic)', reg.registrationRecord);
    return { status: l.client === undefined ? 'pass' : 'fail' };
  });

  await check(
    'OP-04',
    'OPAQUE identifier mismatch (other server identifier) fails at the client',
    () => {
      const l = login(password, reg.registrationRecord, {
        clientIds: { client: username, server: 'another-instance' },
        serverIds: { client: username, server: 'another-instance' },
      });
      return { status: l.client === undefined ? 'pass' : 'fail' };
    },
  );

  await check(
    'OP-05',
    'OPAQUE server key substitution: a different server setup with the stolen record cannot authenticate',
    () => {
      const otherSetup = opaque.server.createSetup();
      const l = login(password, reg.registrationRecord, { setup: otherSetup });
      return { status: l.client === undefined ? 'pass' : 'fail' };
    },
  );

  await check(
    'OP-06',
    'OPAQUE unknown user: simulated response has the same length; client fails',
    () => {
      const real = login(password, reg.registrationRecord);
      const fake = login(password, null);
      return {
        status:
          fake.client === undefined && fake.loginResponse.length === real.loginResponse.length
            ? 'pass'
            : 'fail',
        realLen: real.loginResponse.length,
        fakeLen: fake.loginResponse.length,
        note: 'length only; timing indistinguishability must be tested at the HTTP layer in Phase 2',
      };
    },
  );

  await check('OP-07', 'OPAQUE malformed or tampered messages', () => {
    const out = {};
    const attempt = (name, fn) => {
      try {
        const r = fn();
        out[name] = r === undefined ? 'returned undefined' : 'ACCEPTED';
      } catch (e) {
        out[name] = `threw ${errText(e).slice(0, 120)}`;
      }
    };
    const l = login(password, reg.registrationRecord);
    const flip = (b64) => {
      const c = b64.split('');
      const i = 10;
      c[i] = c[i] === 'A' ? 'B' : 'A';
      return c.join('');
    };
    attempt('server.startLogin garbage request', () =>
      opaque.server.startLogin({
        serverSetup,
        registrationRecord: reg.registrationRecord,
        startLoginRequest: 'AAAA',
        userIdentifier: username,
      }),
    );
    attempt('server.startLogin garbage record', () =>
      opaque.server.startLogin({
        serverSetup,
        registrationRecord: 'AAAA',
        startLoginRequest: l.startLoginRequest,
        userIdentifier: username,
      }),
    );
    attempt('client.finishLogin truncated response', () =>
      opaque.client.finishLogin({
        clientLoginState: opaque.client.startLogin({ password }).clientLoginState,
        loginResponse: l.loginResponse.slice(0, 40),
        password,
        identifiers,
      }),
    );
    attempt('client.finishLogin bit-flipped response', () => {
      const s = opaque.client.startLogin({ password });
      const r = opaque.server.startLogin({
        serverSetup,
        registrationRecord: reg.registrationRecord,
        startLoginRequest: s.startLoginRequest,
        userIdentifier: username,
        identifiers,
      });
      return opaque.client.finishLogin({
        clientLoginState: s.clientLoginState,
        loginResponse: flip(r.loginResponse),
        password,
        identifiers,
      });
    });
    attempt('client.finishLogin byte flipped inside the masked response', () => {
      const s = opaque.client.startLogin({ password });
      const r = opaque.server.startLogin({
        serverSetup,
        registrationRecord: reg.registrationRecord,
        startLoginRequest: s.startLoginRequest,
        userIdentifier: username,
        identifiers,
      });
      const bytes = Uint8Array.from(
        atob(r.loginResponse.replace(/-/g, '+').replace(/_/g, '/')),
        (ch) => ch.charCodeAt(0),
      );
      bytes[200] ^= 1;
      const b64 = btoa(String.fromCharCode(...bytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
      return opaque.client.finishLogin({
        clientLoginState: s.clientLoginState,
        loginResponse: b64,
        password,
        identifiers,
      });
    });
    attempt('server.finishLogin bit-flipped finalization', () =>
      opaque.server.finishLogin({
        serverLoginState: l.serverLoginState,
        finishLoginRequest: flip(l.client.finishLoginRequest),
        identifiers,
      }),
    );
    attempt('server.finishLogin replay of state and finalization', () => {
      const ll = login(password, reg.registrationRecord);
      opaque.server.finishLogin({
        serverLoginState: ll.serverLoginState,
        finishLoginRequest: ll.client.finishLoginRequest,
        identifiers,
      });
      return opaque.server.finishLogin({
        serverLoginState: ll.serverLoginState,
        finishLoginRequest: ll.client.finishLoginRequest,
        identifiers,
      });
    });
    const tamperedRejected =
      out['client.finishLogin bit-flipped response'] !== 'ACCEPTED' &&
      out['client.finishLogin byte flipped inside the masked response'] !== 'ACCEPTED' &&
      out['server.finishLogin bit-flipped finalization'] !== 'ACCEPTED';
    return { status: tamperedRejected ? 'pass' : 'fail', outcomes: out };
  });

  await check('OP-08', 'OPAQUE password input is a JS string: lone surrogate vs U+FFFD', () => {
    const r = register('a\ud800b');
    const l = login('a\ufffdb', r.registrationRecord);
    const nfc = register('caf\u00e9');
    const lNfd = login('cafe\u0301', nfc.registrationRecord);
    return {
      loneSurrogateLogsInAsReplacementChar: Boolean(l.client),
      nfdLogsInToNfcRegistration: Boolean(lNfd.client),
    };
  });

  // ---------------------------------------------------------------- KDF timing
  const benchmarks = [];
  if (bench.runs) {
    const profiles = bench.profiles ?? [{ label: 'profile-1 64MiB t=3', t: 3, mem: 64 * MiB }];
    for (const p of profiles) {
      const samples = [];
      let error = null;
      for (let i = 0; i < bench.runs; i++) {
        const pw = synthetic(`bench-pw-${i}`, 20);
        const salt = synthetic(`bench-salt-${i}`, 16);
        const t0 = now();
        try {
          sodium.crypto_pwhash(32, pw, salt, p.t, p.mem, sodium.crypto_pwhash_ALG_ARGON2ID13);
        } catch (e) {
          error = errText(e);
          break;
        }
        samples.push(now() - t0);
      }
      const row = {
        kind: 'libsodium crypto_pwhash',
        label: p.label,
        t: p.t,
        memMiB: p.mem / MiB,
        p: 1,
        runs: samples.length,
        error,
      };
      if (samples.length)
        Object.assign(row, {
          medianMs: Math.round(median(samples)),
          minMs: Math.round(Math.min(...samples)),
          maxMs: Math.round(Math.max(...samples)),
        });
      benchmarks.push(row);
      log(
        `BENCH ${row.label} median=${row.medianMs}ms runs=${row.runs}${error ? ' error=' + error : ''}`,
      );
    }
    const ok = [];
    for (let i = 0; i < Math.min(bench.runs, 5); i++)
      ok.push(login(password, reg.registrationRecord).clientFinishMs);
    benchmarks.push({
      kind: 'OPAQUE client finishLogin',
      label: 'memory-constrained 64MiB t=3 p=4',
      runs: ok.length,
      medianMs: Math.round(median(ok)),
      minMs: Math.round(Math.min(...ok)),
      maxMs: Math.round(Math.max(...ok)),
    });
    log(`BENCH OPAQUE finishLogin median=${Math.round(median(ok))}ms`);
  }

  return { env, results, benchmarks };
}
