// Category 3: what the pinned libsodium.js build does at its edges. These checks record observed
// behavior. Where the library does not enforce a documented limit, the check asserts that it does
// not, so a future library change is noticed; it never implies the library protects Ruvee.

import { assert, attempt, concat, equal, flipBit, hex, synthetic, te } from '../bytes.mjs';
import { defineCheck, ENFORCEMENT } from '../harness.mjs';

const C = 'library-behavior';

// Internal Emscripten heap of libsodium.js. Undocumented; used only to observe whether a rejected
// call grew WebAssembly memory.
function heapBytes(sodium) {
  const n = sodium.libsodium?.HEAPU8?.length;
  assert(typeof n === 'number' && n > 0, 'cannot observe the libsodium.js WebAssembly heap');
  return n;
}

function aeadFixture() {
  return {
    key: synthetic('tamper-key', 32),
    nonce: synthetic('tamper-nonce', 24),
    pt: synthetic('tamper-pt', 100),
    ad: synthetic('tamper-ad', 20),
  };
}

export const libraryBehaviorChecks = [
  defineCheck({
    id: 'LB-AEAD-TAMPER-REJECTED',
    category: C,
    primitive: 'XChaCha20-Poly1305-IETF',
    title:
      'Modified ciphertext, tag, nonce or associated data, and a wrong key, are rejected without returning plaintext',
    subject: ['libsodium.js crypto_aead_xchacha20poly1305_ietf_decrypt'],
    expectedFrom: 'AEAD security property; observed error text is recorded, not asserted',
    enforcement: ENFORCEMENT.library,
    run: (ctx) => {
      const s = ctx.sodium;
      const f = aeadFixture();
      const c = s.crypto_aead_xchacha20poly1305_ietf_encrypt(f.pt, f.ad, null, f.nonce, f.key);
      const tagAt = c.length - 16;
      const cases = {
        'ciphertext first byte': [flipBit(c, 0), f.ad, f.nonce, f.key],
        'ciphertext middle byte, high bit': [flipBit(c, 50, 7), f.ad, f.nonce, f.key],
        'ciphertext last byte': [flipBit(c, tagAt - 1), f.ad, f.nonce, f.key],
        'tag first byte': [flipBit(c, tagAt), f.ad, f.nonce, f.key],
        'tag last byte': [flipBit(c, c.length - 1), f.ad, f.nonce, f.key],
        'nonce first byte': [c, f.ad, flipBit(f.nonce, 0), f.key],
        'nonce last byte (XChaCha extension part)': [c, f.ad, flipBit(f.nonce, 23), f.key],
        'AAD one bit': [c, flipBit(f.ad, 5), f.nonce, f.key],
        'AAD omitted': [c, null, f.nonce, f.key],
        'AAD truncated by one byte': [c, f.ad.subarray(0, 19), f.nonce, f.key],
        'AAD extended by one byte': [c, concat(f.ad, Uint8Array.of(0)), f.nonce, f.key],
        'wrong key (one bit)': [c, f.ad, f.nonce, flipBit(f.key, 31)],
        'wrong key (unrelated)': [c, f.ad, f.nonce, synthetic('other-key', 32)],
        'ciphertext and tag swapped in order': [
          concat(c.subarray(tagAt), c.subarray(0, tagAt)),
          f.ad,
          f.nonce,
          f.key,
        ],
      };
      const observed = {};
      for (const [name, [ct, ad, nonce, key]] of Object.entries(cases)) {
        const r = attempt(() =>
          s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, ad, nonce, key),
        );
        assert(r.threw, `${name}: decryption returned output`);
        observed[name] = r.error;
      }
      assert(
        equal(s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, c, f.ad, f.nonce, f.key), f.pt),
        'unmodified input no longer decrypts',
      );
      return {
        cases: Object.keys(cases).length,
        observedErrors: [...new Set(Object.values(observed))],
      };
    },
  }),

  defineCheck({
    id: 'LB-AEAD-TRUNCATED-MALFORMED',
    category: C,
    primitive: 'XChaCha20-Poly1305-IETF',
    title:
      'Truncated, extended and malformed ciphertext inputs are rejected; length errors and authentication errors are distinguishable',
    subject: ['libsodium.js crypto_aead_xchacha20poly1305_ietf_decrypt'],
    expectedFrom: 'observed behavior',
    enforcement: ENFORCEMENT.library,
    notes:
      'The wrapper throws TypeError for inputs shorter than the tag and Error for authentication failure. A caller that exposed that difference would leak which check failed; Ruvee maps both to one integrity_failure (cryptographic-design §4.4, P2-03).',
    run: (ctx) => {
      const s = ctx.sodium;
      const f = aeadFixture();
      const c = s.crypto_aead_xchacha20poly1305_ietf_encrypt(f.pt, f.ad, null, f.nonce, f.key);
      const dec = (ct) =>
        attempt(() => s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, f.ad, f.nonce, f.key));
      const cases = {
        'empty ciphertext': new Uint8Array(0),
        '1 byte': c.subarray(0, 1),
        '15 bytes (shorter than the tag)': c.subarray(0, 15),
        '16 bytes (tag-sized prefix)': c.subarray(0, 16),
        'last byte removed': c.subarray(0, c.length - 1),
        'one byte appended': concat(c, Uint8Array.of(0)),
        'ciphertext of another message': s.crypto_aead_xchacha20poly1305_ietf_encrypt(
          synthetic('other', 100),
          f.ad,
          null,
          f.nonce,
          synthetic('k2', 32),
        ),
        'null ciphertext': null,
        'array instead of Uint8Array': Array.from(c),
      };
      const observed = {};
      for (const [name, ct] of Object.entries(cases)) {
        const r = dec(ct);
        assert(r.threw, `${name}: accepted`);
        observed[name] = r.error;
      }
      const empty = s.crypto_aead_xchacha20poly1305_ietf_encrypt(
        new Uint8Array(0),
        f.ad,
        null,
        f.nonce,
        f.key,
      );
      assert(empty.length === 16, 'empty plaintext does not give a 16-byte output');
      assert(
        dec(empty).threw === false && dec(empty).value.length === 0,
        'tag-only ciphertext of empty plaintext does not open',
      );
      assert(
        /^TypeError/.test(observed['15 bytes (shorter than the tag)']),
        'short input error type changed',
      );
      assert(/^Error/.test(observed['last byte removed']), 'authentication error type changed');
      return { observedErrors: observed };
    },
  }),

  defineCheck({
    id: 'LB-AEAD-KEY-NONCE-LENGTHS',
    category: C,
    primitive: 'XChaCha20-Poly1305-IETF',
    title:
      'Keys other than 32 bytes and nonces other than 24 bytes are rejected by encrypt and decrypt',
    subject: ['libsodium.js crypto_aead_xchacha20poly1305_ietf_*'],
    expectedFrom: 'observed behavior',
    enforcement: ENFORCEMENT.library,
    run: (ctx) => {
      const s = ctx.sodium;
      const f = aeadFixture();
      const c = s.crypto_aead_xchacha20poly1305_ietf_encrypt(f.pt, f.ad, null, f.nonce, f.key);
      const observed = new Set();
      for (const n of [0, 16, 31, 33, 64]) {
        for (const r of [
          attempt(() =>
            s.crypto_aead_xchacha20poly1305_ietf_encrypt(
              f.pt,
              f.ad,
              null,
              f.nonce,
              new Uint8Array(n),
            ),
          ),
          attempt(() =>
            s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, c, f.ad, f.nonce, new Uint8Array(n)),
          ),
        ]) {
          assert(r.threw, `key length ${n} accepted`);
          observed.add(r.error);
        }
      }
      for (const n of [0, 8, 12, 23, 25, 32]) {
        for (const r of [
          attempt(() =>
            s.crypto_aead_xchacha20poly1305_ietf_encrypt(
              f.pt,
              f.ad,
              null,
              new Uint8Array(n),
              f.key,
            ),
          ),
          attempt(() =>
            s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, c, f.ad, new Uint8Array(n), f.key),
          ),
        ]) {
          assert(r.threw, `nonce length ${n} accepted`);
          observed.add(r.error);
        }
      }
      return { observedErrors: [...observed] };
    },
  }),

  defineCheck({
    id: 'LB-INPUT-TYPE-COERCION',
    category: C,
    primitive: 'libsodium.js argument handling',
    title:
      'JavaScript strings are accepted as keys, messages and AAD and silently UTF-8 encoded; Buffers are accepted; Arrays, ArrayBuffers and other typed arrays are rejected',
    subject: ['libsodium.js wrappers'],
    expectedFrom: 'observed behavior',
    enforcement: ENFORCEMENT.notEnforced,
    notes:
      'A 32-character string is accepted as a 32-byte key. Nothing in the library stops a passphrase or identifier from being used as a key; only a caller-side type check can.',
    run: (ctx) => {
      const s = ctx.sodium;
      const f = aeadFixture();
      const enc = (key, pt = f.pt, ad = f.ad) =>
        attempt(() => s.crypto_aead_xchacha20poly1305_ietf_encrypt(pt, ad, null, f.nonce, key));
      const stringKey = 'k'.repeat(32);
      const r = enc(stringKey);
      assert(!r.threw, 'string key rejected');
      assert(equal(r.value, enc(te.encode(stringKey)).value), 'string key is not its UTF-8 bytes');
      assert(!enc(f.key, 'text plaintext').threw, 'string plaintext rejected');
      assert(!enc(f.key, f.pt, 'text aad').threw, 'string AAD rejected');
      assert(
        !attempt(() => s.crypto_generichash(32, 'm', 'k'.repeat(16))).threw,
        'string BLAKE2b key rejected',
      );
      const hasBuffer = typeof globalThis.Buffer === 'function';
      if (hasBuffer) assert(!enc(globalThis.Buffer.from(f.key)).threw, 'Buffer key rejected');
      for (const [name, key] of [
        ['Array', Array.from(f.key)],
        ['ArrayBuffer', f.key.slice().buffer],
        ['Uint16Array', new Uint16Array(16)],
        ['DataView', new DataView(f.key.slice().buffer)],
      ])
        assert(enc(key).threw, `${name} key accepted`);
      return { stringKeyAccepted: true, bufferChecked: hasBuffer };
    },
  }),

  defineCheck({
    id: 'LB-BLAKE2B-KEY-LENGTH',
    category: C,
    primitive: 'Keyed BLAKE2b (crypto_generichash)',
    title:
      'Keys of 1 to 15 bytes are accepted although crypto_generichash_KEYBYTES_MIN is 16; 65-byte keys are rejected',
    subject: ['libsodium.js crypto_generichash'],
    expectedFrom: 'observed behavior; finding V-12',
    enforcement: ENFORCEMENT.notEnforced,
    notes:
      "BLAKE2 itself allows keys of 0 to 64 bytes, and the short-key output matches noble, so the output is correct BLAKE2b. What is missing is enforcement of libsodium's documented minimum.",
    run: (ctx) => {
      const s = ctx.sodium;
      assert(s.crypto_generichash_KEYBYTES_MIN === 16, 'KEYBYTES_MIN changed');
      assert(s.crypto_generichash_KEYBYTES_MAX === 64, 'KEYBYTES_MAX changed');
      const msg = synthetic('b2-keylen', 40);
      const accepted = [];
      for (let n = 1; n <= 15; n++) {
        const key = synthetic(`short-key-${n}`, n);
        const r = attempt(() => s.crypto_generichash(32, msg, key));
        assert(!r.threw, `key length ${n} rejected: the library now enforces its minimum`);
        assert(
          equal(r.value, ctx.noble.blake2b(msg, { key, dkLen: 32 })),
          `key length ${n}: output is not BLAKE2b with that key`,
        );
        accepted.push(n);
      }
      for (const n of [16, 32, 64])
        assert(
          !attempt(() => s.crypto_generichash(32, msg, new Uint8Array(n))).threw,
          `key length ${n} rejected`,
        );
      assert(
        attempt(() => s.crypto_generichash(32, msg, new Uint8Array(65))).threw,
        'key length 65 accepted',
      );
      return { acceptedBelowDocumentedMinimum: accepted };
    },
  }),

  defineCheck({
    id: 'LB-BLAKE2B-OUTPUT-LENGTH',
    category: C,
    primitive: 'BLAKE2b (crypto_generichash)',
    title:
      'Output lengths of 1 to 15 bytes are accepted although crypto_generichash_BYTES_MIN is 16; 0 and 65 are rejected',
    subject: ['libsodium.js crypto_generichash'],
    expectedFrom: 'observed behavior',
    enforcement: ENFORCEMENT.notEnforced,
    run: (ctx) => {
      const s = ctx.sodium;
      assert(
        s.crypto_generichash_BYTES_MIN === 16 && s.crypto_generichash_BYTES_MAX === 64,
        'BYTES_MIN/MAX changed',
      );
      const msg = synthetic('b2-outlen', 10);
      for (const n of [1, 8, 15]) {
        const r = attempt(() => s.crypto_generichash(n, msg, null));
        assert(!r.threw, `output length ${n} rejected`);
        assert(
          equal(r.value, ctx.noble.blake2b(msg, { dkLen: n })),
          `output length ${n} is not BLAKE2b-${n * 8}`,
        );
      }
      assert(attempt(() => s.crypto_generichash(0, msg, null)).threw, 'output length 0 accepted');
      assert(attempt(() => s.crypto_generichash(65, msg, null)).threw, 'output length 65 accepted');
    },
  }),

  defineCheck({
    id: 'LB-KDF-ARGUMENTS',
    category: C,
    primitive: 'crypto_kdf_derive_from_key',
    title:
      'Context, key and subkey-id handling: wrong context or key lengths are rejected, but an 8-byte non-ASCII context is accepted; numeric ids stop at 2^31 - 1',
    subject: ['libsodium.js crypto_kdf_derive_from_key'],
    expectedFrom: 'observed behavior',
    enforcement: `${ENFORCEMENT.library} (lengths, id range); ${ENFORCEMENT.notEnforced} (ASCII-only context)`,
    run: (ctx) => {
      const s = ctx.sodium;
      const key = synthetic('kdf-args', 32);
      const k = (len, id, c, kk = key) =>
        attempt(() => s.crypto_kdf_derive_from_key(len, id, c, kk));
      for (const c of ['', 'rvkeyst', 'rvkeyst12', 'rvkeys\u00e91'])
        assert(k(32, 1, c).threw, `context ${JSON.stringify(c)} accepted`);
      assert(k(32, 1, new Uint8Array(8)).threw, 'Uint8Array context accepted');
      const nonAscii = k(32, 1, 'rvkeys\u00e9');
      assert(!nonAscii.threw, '7-character context with an 8-byte UTF-8 encoding rejected');
      for (const n of [0, 16, 31, 33])
        assert(k(32, 1, 'rvkeyst1', new Uint8Array(n)).threw, `key length ${n} accepted`);
      assert(!k(32, 2 ** 31 - 1, 'rvkeyst1').threw, 'numeric id 2^31 - 1 rejected');
      assert(k(32, 2 ** 31, 'rvkeyst1').threw, 'numeric id 2^31 accepted');
      assert(!k(32, 2n ** 64n - 1n, 'rvkeyst1').threw, 'bigint id 2^64 - 1 rejected');
      for (const id of [-1, 1.5, 2n ** 64n, -1n])
        assert(k(32, id, 'rvkeyst1').threw, `id ${String(id)} accepted`);
      return { nonAsciiContextAccepted: true, contextLengthIsMeasuredIn: 'UTF-8 bytes' };
    },
  }),

  defineCheck({
    id: 'LB-KDF-SUBKEY-LENGTH-STALE-MEMORY',
    category: C,
    primitive: 'crypto_kdf_derive_from_key',
    title:
      "Subkey lengths outside 16..64 are not rejected and return uninitialized WebAssembly heap memory, including a previous derivation's output (finding V-15)",
    subject: ['libsodium.js 0.8.4 crypto_kdf_derive_from_key'],
    expectedFrom:
      'observed behavior; upstream issue jedisct1/libsodium.js#370, fixed on master by commit 86ea6ed (2026-04-29) and not in any npm release as of 2026-10-22',
    enforcement: ENFORCEMENT.notEnforced,
    notes:
      'This check is a tripwire. It fails when a pinned release starts rejecting these lengths, which is the signal to update the finding and the pin. Ruvee must never pass a subkey length other than 32 (see the proposed length rule).',
    run: (ctx) => {
      const s = ctx.sodium;
      assert(
        s.crypto_kdf_BYTES_MIN === 16 && s.crypto_kdf_BYTES_MAX === 64,
        'documented range changed',
      );
      const keyA = synthetic('stale-key-A', 32);
      const keyB = synthetic('stale-key-B', 32);
      const subkeyA = s.crypto_kdf_derive_from_key(64, 1, 'rvkeyst1', keyA);
      const r65 = attempt(() => s.crypto_kdf_derive_from_key(65, 1, 'rvkeyst1', keyB));
      assert(!r65.threw, 'length 65 rejected: the pinned release fixed issue #370');
      const expectedB = ctx.noble.blake2b(new Uint8Array(0), {
        key: keyB,
        dkLen: 64,
        salt: Uint8Array.of(1, ...new Uint8Array(15)),
        personalization: concat(te.encode('rvkeyst1'), new Uint8Array(8)),
      });
      const prefix = r65.value.subarray(0, 64);
      assert(!equal(prefix, expectedB), 'length 65 output is a real derivation from key B');
      assert(
        equal(prefix, subkeyA),
        'length 65 output does not reproduce the earlier subkey from key A',
      );
      const r15 = attempt(() => s.crypto_kdf_derive_from_key(15, 1, 'rvkeyst1', keyB));
      assert(!r15.threw, 'length 15 rejected: the pinned release fixed issue #370');
      const real15 = ctx.noble.blake2b(new Uint8Array(0), {
        key: keyB,
        dkLen: 15,
        salt: Uint8Array.of(1, ...new Uint8Array(15)),
        personalization: concat(te.encode('rvkeyst1'), new Uint8Array(8)),
      });
      assert(!equal(r15.value, real15), 'length 15 output is a real BLAKE2b-120 derivation');
      return {
        length65ReturnedEarlierSubkeyFromAnotherKey: true,
        length15ReturnedNonDerivedBytes: hex(r15.value),
      };
    },
  }),

  defineCheck({
    id: 'LB-ARGON2-INVALID-REJECTED-WITHOUT-ALLOCATION',
    category: C,
    primitive: 'Argon2id (crypto_pwhash)',
    title:
      'Invalid opslimit, memlimit, output length, salt length and algorithm are rejected without a large allocation, and the library stays usable',
    subject: ['libsodium.js crypto_pwhash'],
    expectedFrom:
      'observed behavior; heap size read from an undocumented internal (libsodium.HEAPU8)',
    enforcement: ENFORCEMENT.library,
    notes:
      'Two layers reject. The JavaScript wrapper rejects non-integers and values of 2^31 or more with TypeError and never grows the heap. Values that pass that type check but are out of range (memlimit 2^31 - 1, output length 2^31 - 1, opslimit 0, memlimit below 8192, unknown algorithm) reach the C library; in a fresh module the memlimit 2^31 - 1 case grew the heap by about 832 KiB before "invalid usage", and output length 2^31 - 1 throws a plain object ("_malloc() failed"), not an Error. Growth is recorded per case.',
    run: (ctx) => {
      const s = ctx.sodium;
      const ALG = s.crypto_pwhash_ALG_ARGON2ID13;
      const salt = synthetic('rej-salt', 16);
      const call = (o) =>
        s.crypto_pwhash(o.out ?? 32, 'pw', o.salt ?? salt, o.ops ?? 1, o.mem ?? 8192, o.alg ?? ALG);
      const reference = call({});
      // wrapper: rejected by the JavaScript type checks; native: rejected inside libsodium.
      const cases = [
        ['opslimit 0', { ops: 0 }, 'native'],
        ['opslimit -1', { ops: -1 }, 'wrapper'],
        ['opslimit 1.5', { ops: 1.5 }, 'wrapper'],
        ['opslimit NaN', { ops: NaN }, 'wrapper'],
        ['opslimit 2^31', { ops: 2 ** 31 }, 'wrapper'],
        ['opslimit 2^32 + 1', { ops: 2 ** 32 + 1 }, 'wrapper'],
        ['memlimit 0', { mem: 0 }, 'native'],
        ['memlimit 8191', { mem: 8191 }, 'native'],
        ['memlimit -1', { mem: -1 }, 'wrapper'],
        ['memlimit 1.5', { mem: 1.5 }, 'wrapper'],
        ['memlimit 2^31 - 1', { mem: 2 ** 31 - 1 }, 'native'],
        ['memlimit 2^31', { mem: 2 ** 31 }, 'wrapper'],
        ['memlimit 2^32 + 8192', { mem: 2 ** 32 + 8192 }, 'wrapper'],
        ['output length 0', { out: 0 }, 'native'],
        ['output length 15', { out: 15 }, 'native'],
        ['output length 2^31 - 1', { out: 2 ** 31 - 1 }, 'native'],
        ['output length 2^32 + 32', { out: 2 ** 32 + 32 }, 'wrapper'],
        ['salt 0 bytes', { salt: new Uint8Array(0) }, 'wrapper'],
        ['salt 15 bytes', { salt: new Uint8Array(15) }, 'wrapper'],
        ['salt 17 bytes', { salt: new Uint8Array(17) }, 'wrapper'],
        ['algorithm 0', { alg: 0 }, 'native'],
        ['algorithm 3', { alg: 3 }, 'native'],
      ];
      const NATIVE_GROWTH_LIMIT = 1024 * 1024;
      const observed = {};
      for (const [name, o, layer] of cases) {
        const before = heapBytes(s);
        const t0 = globalThis.performance.now();
        const r = attempt(() => call(o));
        const ms = globalThis.performance.now() - t0;
        const growth = heapBytes(s) - before;
        assert(r.threw, `${name}: accepted`);
        if (layer === 'wrapper') {
          assert(
            /^TypeError/.test(r.error),
            `${name}: not rejected by the wrapper type check (${r.error})`,
          );
          assert(growth === 0, `${name}: wrapper rejection grew the heap by ${growth} bytes`);
        } else {
          assert(!/^TypeError/.test(r.error), `${name}: now rejected by the wrapper; reclassify`);
          assert(
            growth <= NATIVE_GROWTH_LIMIT,
            `${name}: heap grew by ${growth} bytes before rejection`,
          );
        }
        assert(equal(call({}), reference), `${name}: library output changed afterwards`);
        observed[name] = {
          layer,
          error: r.error,
          isError: r.isError,
          heapGrowthBytes: growth,
          ms: Math.round(ms * 10) / 10,
        };
      }
      return { cases: cases.length, nativeGrowthLimitBytes: NATIVE_GROWTH_LIMIT, observed };
    },
  }),

  defineCheck({
    id: 'LB-ARGON2-SILENT-ADJUSTMENTS',
    category: C,
    primitive: 'Argon2id (crypto_pwhash)',
    title:
      'memlimit is silently floored to whole KiB, outputs above 64 bytes are accepted, and ALG_DEFAULT is currently Argon2id v1.3',
    subject: ['libsodium.js crypto_pwhash'],
    expectedFrom: 'observed behavior',
    enforcement: ENFORCEMENT.notEnforced,
    notes:
      'There is no library-side ceiling below the WebAssembly limit: during development a 1 GiB memlimit was accepted and allocated about 1 GiB in Node. The harness does not run that case. Only a caller-side profile check prevents excessive parameters.',
    run: (ctx) => {
      const s = ctx.sodium;
      const ALG = s.crypto_pwhash_ALG_ARGON2ID13;
      const salt = synthetic('adj-salt', 16);
      const at = (mem, out = 32) => s.crypto_pwhash(out, 'pw', salt, 1, mem, ALG);
      const base = at(8192);
      assert(equal(at(8193), base), 'memlimit 8193 differs from 8192');
      assert(equal(at(9215), base), 'memlimit 9215 differs from 8192');
      assert(!equal(at(9216), base), 'memlimit 9216 equals 8192');
      assert(at(8192, 65).length === 65, 'output length 65 rejected');
      assert(
        s.crypto_pwhash_ALG_ARGON2ID13 === 2 && s.crypto_pwhash_ALG_DEFAULT === 2,
        'algorithm constants changed',
      );
      assert(s.crypto_pwhash_ALG_ARGON2I13 === 1, 'ARGON2I13 constant changed');
      assert(
        !equal(
          s.crypto_pwhash(32, 'pw', salt, 3, 8192, s.crypto_pwhash_ALG_ARGON2I13),
          s.crypto_pwhash(32, 'pw', salt, 3, 8192, ALG),
        ),
        'Argon2i equals Argon2id',
      );
      return { memlimitGranularity: '1 KiB (floor)', defaultAlgorithm: 'ARGON2ID13 (2)' };
    },
  }),

  defineCheck({
    id: 'LB-ARGON2-ENCODED-PARAMETERS',
    category: C,
    primitive: 'Argon2id (crypto_pwhash_str)',
    title:
      'libsodium reports its own parameter mapping in crypto_pwhash_str: $argon2id$v=19, m = memlimit/1024, t = opslimit, p = 1',
    subject: ['libsodium.js crypto_pwhash_str'],
    expectedFrom: 'observed behavior (the library describing itself)',
    enforcement: ENFORCEMENT.library,
    run: (ctx) => {
      const s = ctx.sodium;
      const out = [];
      for (const [ops, mem] of [
        [1, 8192],
        [3, 1024 * 1024],
        [4, 2 * 1024 * 1024],
      ]) {
        const e = s.crypto_pwhash_str('pw', ops, mem);
        const want = `$argon2id$v=19$m=${mem / 1024},t=${ops},p=1$`;
        assert(e.startsWith(want), `expected prefix ${want}, got ${e.slice(0, 40)}`);
        out.push(e.slice(0, want.length));
      }
      return { prefixes: out };
    },
  }),

  defineCheck({
    id: 'LB-CONSTANTS',
    category: C,
    primitive: 'libsodium.js constants',
    title:
      'Constants above 2^31 - 1 read as negative numbers; the documented sizes Ruvee relies on have their expected values',
    subject: ['libsodium.js constants'],
    expectedFrom: 'observed behavior; finding V-12',
    enforcement: ENFORCEMENT.notEnforced,
    notes: 'Ruvee must not read limits from library constants.',
    run: (ctx) => {
      const s = ctx.sodium;
      const expected = {
        crypto_pwhash_MEMLIMIT_MAX: -2147483648,
        crypto_pwhash_OPSLIMIT_MAX: -1,
        crypto_pwhash_BYTES_MAX: -1,
        crypto_pwhash_PASSWD_MAX: -1,
        crypto_pwhash_MEMLIMIT_MIN: 8192,
        crypto_pwhash_OPSLIMIT_MIN: 1,
        crypto_pwhash_BYTES_MIN: 16,
        crypto_pwhash_SALTBYTES: 16,
        crypto_generichash_KEYBYTES_MIN: 16,
        crypto_generichash_KEYBYTES_MAX: 64,
        crypto_generichash_BYTES_MIN: 16,
        crypto_generichash_BYTES_MAX: 64,
        crypto_kdf_BYTES_MIN: 16,
        crypto_kdf_BYTES_MAX: 64,
        crypto_kdf_CONTEXTBYTES: 8,
        crypto_kdf_KEYBYTES: 32,
        crypto_aead_xchacha20poly1305_ietf_KEYBYTES: 32,
        crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: 24,
        crypto_aead_xchacha20poly1305_ietf_ABYTES: 16,
        crypto_box_SEALBYTES: 48,
      };
      const wrong = Object.entries(expected)
        .filter(([k, v]) => s[k] !== v)
        .map(([k, v]) => `${k}: expected ${v}, got ${s[k]}`);
      assert(wrong.length === 0, 'constants differ', { wrong });
      assert(
        s.sodium_version_string() === '1.0.22',
        `sodium_version_string changed: ${s.sodium_version_string()}`,
      );
      return {
        checked: Object.keys(expected).length,
        sodiumVersionString: s.sodium_version_string(),
        libraryVersion: `${s.SODIUM_LIBRARY_VERSION_MAJOR}.${s.SODIUM_LIBRARY_VERSION_MINOR}`,
      };
    },
  }),

  defineCheck({
    id: 'LB-STRING-ENCODING',
    category: C,
    primitive: 'Password and message strings (crypto_pwhash, crypto_generichash)',
    title:
      'Strings are UTF-8 encoded without normalization: NFC and NFD differ, and a lone surrogate collides with U+FFFD',
    subject: ['libsodium.js crypto_pwhash, crypto_generichash'],
    expectedFrom: 'observed behavior; finding V-05',
    enforcement: ENFORCEMENT.notEnforced,
    run: (ctx) => {
      const s = ctx.sodium;
      const salt = synthetic('str-salt', 16);
      const pw = (x) => s.crypto_pwhash(32, x, salt, 1, 8192, s.crypto_pwhash_ALG_ARGON2ID13);
      const h = (x) => s.crypto_generichash(32, x, null);
      const nfc = 'caf\u00e9';
      const nfd = 'cafe\u0301';
      for (const [name, f] of [
        ['crypto_pwhash', pw],
        ['crypto_generichash', h],
      ]) {
        assert(!equal(f(nfc), f(nfd)), `${name}: NFC equals NFD (library normalizes)`);
        assert(equal(f(nfc), f(te.encode(nfc))), `${name}: string is not its UTF-8 bytes`);
        assert(
          equal(f('a\ud800b'), f('a\ufffdb')),
          `${name}: lone high surrogate no longer collides with U+FFFD`,
        );
        assert(
          equal(f('a\udc00b'), f('a\ufffdb')),
          `${name}: lone low surrogate no longer collides with U+FFFD`,
        );
      }
      return { normalization: 'none', loneSurrogate: 'replaced by U+FFFD (EF BF BD)' };
    },
  }),
];
