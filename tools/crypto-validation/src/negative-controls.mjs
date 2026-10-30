// Negative controls: deliberate faults injected at run time, never by editing sources. Each
// control passes only if the targeted check FAILS. A control that cannot make its check fail
// means that check is vacuous, and the whole run fails.

import { runChecks, verifyCompleteness } from './harness.mjs';
import { createRules } from './proposed-rules.mjs';
import { loadVerifiedSources } from './sources.mjs';
import { ALL_CHECKS } from './suite.mjs';
import { expectedFieldPaths, mutateAt } from './vectors.mjs';

const byId = Object.fromEntries(ALL_CHECKS.map((c) => [c.id, c]));

function override(target, replacements) {
  return new Proxy(target, {
    get(t, prop) {
      return Object.hasOwn(replacements, prop) ? replacements[prop] : t[prop];
    },
  });
}

async function expectFailure(checkId, ctx) {
  const [r] = await runChecks([byId[checkId]], ctx);
  return { checkId, targetFailed: r.status === 'fail', targetError: r.error };
}

function faults(ctx) {
  const s = ctx.sodium;
  const n = ctx.noble;
  const aeadIgnoringTag = override(s, {
    crypto_aead_xchacha20poly1305_ietf_decrypt: (nsec, c) => {
      if (!(c instanceof Uint8Array) || c.length < 16)
        throw new TypeError('ciphertext is too short');
      return c.slice(0, c.length - 16);
    },
  });
  return [
    {
      id: 'NC-AEAD-IGNORES-TAG',
      fault: 'libsodium AEAD decrypt replaced by one that never checks the tag',
      ctx: { ...ctx, sodium: aeadIgnoringTag },
      targets: [
        'LB-AEAD-TAMPER-REJECTED',
        'LB-AEAD-TRUNCATED-MALFORMED',
        'KAT-XCHACHA-WYCHEPROOF-LIBSODIUM',
        'KAT-XCHACHA-DRAFT-A31-LIBSODIUM',
        'CROSS-XCHACHA-POLY1305-SYNTHETIC',
      ],
    },
    {
      id: 'NC-AEAD-ACCEPTS-BAD-LENGTHS',
      fault: 'libsodium AEAD functions replaced by ones that accept any key and nonce length',
      ctx: {
        ...ctx,
        sodium: override(s, {
          crypto_aead_xchacha20poly1305_ietf_encrypt: (m) => new Uint8Array((m?.length ?? 0) + 16),
          crypto_aead_xchacha20poly1305_ietf_decrypt: () => new Uint8Array(0),
        }),
      },
      targets: ['LB-AEAD-KEY-NONCE-LENGTHS'],
    },
    {
      id: 'NC-NOBLE-BLAKE2B-IGNORES-SALT-PERSONAL',
      fault: 'noble blake2b replaced by one that drops salt and personalization',
      ctx: {
        ...ctx,
        noble: {
          ...n,
          blake2b: (m, o = {}) =>
            n.blake2b(m, { dkLen: o.dkLen, ...(o.key ? { key: o.key } : {}) }),
        },
      },
      targets: ['CROSS-KDF-DERIVE-FROM-KEY', 'CROSS-BLAKE2B-SALT-PERSONAL'],
    },
    {
      id: 'NC-KDF-WRONG-SUBKEY-ID',
      fault: 'crypto_kdf_derive_from_key replaced by one that derives subkey id + 1',
      ctx: {
        ...ctx,
        sodium: override(s, {
          crypto_kdf_derive_from_key: (len, id, c, k) =>
            s.crypto_kdf_derive_from_key(len, BigInt(id) + 1n, c, k),
        }),
      },
      targets: ['CROSS-KDF-DERIVE-FROM-KEY'],
    },
    {
      id: 'NC-BLAKE2B-ONE-BIT',
      fault: 'crypto_generichash output has its last bit flipped',
      ctx: {
        ...ctx,
        sodium: override(s, {
          crypto_generichash: (...a) => {
            const o = s.crypto_generichash(...a);
            o[o.length - 1] ^= 1;
            return o;
          },
        }),
      },
      targets: [
        'CROSS-BLAKE2B-256-UNKEYED',
        'CROSS-BLAKE2B-256-KEY16',
        'CROSS-BLAKE2B-256-KEY32',
        'KAT-BLAKE2B-RFC7693-E-LIBSODIUM',
        'KAT-BLAKE2B-REFKAT-LIBSODIUM',
        'KAT-BLAKE2B-RFC7693-A-LIBSODIUM',
      ],
    },
    {
      id: 'NC-PWHASH-ONE-BIT',
      fault: 'crypto_pwhash output has its last bit flipped',
      ctx: {
        ...ctx,
        sodium: override(s, {
          crypto_pwhash: (...a) => {
            const o = s.crypto_pwhash(...a);
            o[o.length - 1] ^= 1;
            return o;
          },
        }),
      },
      targets: ['CROSS-ARGON2ID-PWHASH', 'CROSS-ARGON2ID-ENCODED'],
    },
    {
      id: 'NC-PWHASH-STR-VERIFY-ALWAYS-FALSE',
      fault: 'crypto_pwhash_str_verify replaced by one that always returns false',
      ctx: { ...ctx, sodium: override(s, { crypto_pwhash_str_verify: () => false }) },
      targets: ['KAT-ARGON2ID-PHC-LIBSODIUM'],
    },
    {
      id: 'NC-LIBRARY-FIXES-KDF-LENGTH',
      fault:
        'crypto_kdf_derive_from_key replaced by one that rejects lengths outside 16..64 (a fixed release)',
      ctx: {
        ...ctx,
        sodium: override(s, {
          crypto_kdf_derive_from_key: (len, ...rest) => {
            if (len < 16 || len > 64) throw new TypeError('invalid subkey length');
            return s.crypto_kdf_derive_from_key(len, ...rest);
          },
        }),
      },
      targets: ['LB-KDF-SUBKEY-LENGTH-STALE-MEMORY'],
    },
    {
      id: 'NC-LIBRARY-ENFORCES-BLAKE2B-KEY-MINIMUM',
      fault: 'crypto_generichash replaced by one that rejects keys shorter than 16 bytes',
      ctx: {
        ...ctx,
        sodium: override(s, {
          crypto_generichash: (len, m, k) => {
            if (k && k.length < 16) throw new TypeError('invalid key length');
            return s.crypto_generichash(len, m, k);
          },
        }),
      },
      targets: ['LB-BLAKE2B-KEY-LENGTH'],
    },
    {
      id: 'NC-PWHASH-GROWS-HEAP-ON-REJECT',
      fault: 'crypto_pwhash replaced by one that grows the WebAssembly heap before rejecting',
      ctx: (() => {
        let grown = 0;
        const fakeHeap = {
          get length() {
            return s.libsodium.HEAPU8.length + grown;
          },
        };
        return {
          ...ctx,
          sodium: override(s, {
            libsodium: { HEAPU8: fakeHeap },
            crypto_pwhash: (len, pw, salt, ops, mem, alg) => {
              if (
                ops === 1 &&
                mem === 8192 &&
                len === 32 &&
                salt?.length === 16 &&
                alg === s.crypto_pwhash_ALG_ARGON2ID13
              )
                return s.crypto_pwhash(len, pw, salt, ops, mem, alg);
              grown += 65536;
              throw new Error('invalid usage');
            },
          }),
        };
      })(),
      targets: ['LB-ARGON2-INVALID-REJECTED-WITHOUT-ALLOCATION'],
    },
    {
      id: 'NC-STRINGS-NORMALIZED-BY-LIBRARY',
      fault:
        'crypto_generichash and crypto_pwhash replaced by ones that NFC-normalize and reject lone surrogates',
      ctx: (() => {
        const norm = (x) => {
          if (typeof x !== 'string') return x;
          if (!x.isWellFormed?.() && /[\ud800-\udfff]/.test(x)) throw new TypeError('ill-formed');
          return x.normalize('NFC');
        };
        return {
          ...ctx,
          sodium: override(s, {
            crypto_generichash: (len, m, k) => s.crypto_generichash(len, norm(m), k),
            crypto_pwhash: (len, pw, ...rest) => s.crypto_pwhash(len, norm(pw), ...rest),
          }),
        };
      })(),
      targets: ['LB-STRING-ENCODING'],
    },
    {
      id: 'NC-RULES-PERMISSIVE',
      fault: 'proposed rules replaced by ones that validate nothing',
      ctx: { ...ctx, rules: createRules('permissive') },
      targets: ['PR-PASSWORD-INPUT', 'PR-KEY-AND-LENGTH-GUARDS', 'PR-KDF-PROFILE-REGISTRY'],
    },
    {
      id: 'NC-RULES-VALIDATE-AFTER-LIBRARY-CALL',
      fault: 'proposed rules that reject correctly, but only after calling the library',
      ctx: { ...ctx, rules: createRules('late') },
      targets: ['PR-PASSWORD-INPUT', 'PR-KEY-AND-LENGTH-GUARDS', 'PR-KDF-PROFILE-REGISTRY'],
    },
  ];
}

async function sourceControls(manifest, readBytes) {
  const out = [];
  for (const meta of manifest.sources) {
    const corrupted = async (file) => {
      const b = (await readBytes(file)).slice();
      if (file === meta.file) b[Math.floor(b.length / 2)] ^= 0x01;
      return b;
    };
    const r = await loadVerifiedSources(manifest, corrupted).then(
      () => ({ rejected: false }),
      (e) => ({ rejected: e.name === 'SourceIntegrityError', error: e.message }),
    );
    out.push({
      id: `NC-SOURCE-CORRUPTED-${meta.id}`,
      fault: `one byte flipped in ${meta.file}`,
      passed: r.rejected,
      detail: r.error,
    });
  }
  const missing = await loadVerifiedSources(manifest, async (file) => {
    if (file === manifest.sources[0].file) throw new Error('ENOENT');
    return readBytes(file);
  }).then(
    () => false,
    (e) => e.name === 'SourceIntegrityError',
  );
  out.push({
    id: 'NC-SOURCE-MISSING',
    fault: `${manifest.sources[0].file} unreadable`,
    passed: missing,
  });
  const badManifest = await loadVerifiedSources(
    { ...manifest, sources: [{ ...manifest.sources[0], sha256: 'not-a-hash' }] },
    readBytes,
  ).then(
    () => false,
    (e) => e.name === 'SourceIntegrityError',
  );
  out.push({
    id: 'NC-SOURCE-MANIFEST-HASH-INVALID',
    fault: 'manifest entry without a valid SHA-256',
    passed: badManifest,
  });
  return out;
}

function completenessControls() {
  const ids = ['A', 'B'];
  const cases = [
    ['NC-COMPLETENESS-MISSING', 'a registered check did not report', [{ id: 'A', status: 'pass' }]],
    [
      'NC-COMPLETENESS-SKIP',
      'a check reported "skip"',
      [
        { id: 'A', status: 'pass' },
        { id: 'B', status: 'skip' },
      ],
    ],
    [
      'NC-COMPLETENESS-DUPLICATE',
      'a check reported twice',
      [
        { id: 'A', status: 'pass' },
        { id: 'A', status: 'pass' },
        { id: 'B', status: 'pass' },
      ],
    ],
    [
      'NC-COMPLETENESS-UNKNOWN',
      'an unregistered check reported',
      [
        { id: 'A', status: 'pass' },
        { id: 'B', status: 'pass' },
        { id: 'C', status: 'pass' },
      ],
    ],
  ];
  return cases.map(([id, fault, results]) => ({
    id,
    fault,
    passed: verifyCompleteness(results, ids).length > 0,
  }));
}

export async function runNegativeControls({ ctx, manifest, readBytes, log = () => {} }) {
  const controls = [];
  const record = (c) => {
    controls.push(c);
    log(
      `${c.passed ? 'PASS' : 'FAIL'} ${c.id}${c.passed ? '' : ' (the target check did not fail)'}`,
    );
  };

  for (const check of ALL_CHECKS.filter((c) => c.vectors)) {
    for (const key of check.vectors) {
      for (const path of expectedFieldPaths(ctx.vectors[key])) {
        const mutated = { ...ctx.vectors, [key]: mutateAt(ctx.vectors[key], path) };
        const r = await expectFailure(check.id, { ...ctx, vectors: mutated });
        record({
          id: `NC-EXPECTED-${check.id}-${path.join('.')}`,
          fault: `expected value ${key}.${path.join('.')} changed by one bit`,
          passed: r.targetFailed,
          targetError: r.targetError,
        });
      }
    }
  }

  for (const f of faults(ctx))
    for (const target of f.targets) {
      const r = await expectFailure(target, f.ctx);
      record({
        id: `${f.id}:${target}`,
        fault: f.fault,
        passed: r.targetFailed,
        targetError: r.targetError,
      });
    }

  for (const c of await sourceControls(manifest, readBytes)) record(c);
  for (const c of completenessControls()) record(c);
  return controls;
}
