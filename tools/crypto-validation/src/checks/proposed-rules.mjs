// Category 4: PROPOSED Ruvee input-validation rules, not approved. Expected outcomes are the
// proposal's, and NFC results follow the Unicode canonical mappings (UnicodeData.txt,
// CompositionExclusions.txt). These checks show what the caller must supply, because the library
// checks in category 3 show the library does not.

import { assert, attempt, equal, hex, synthetic, te } from '../bytes.mjs';
import { defineCheck, ENFORCEMENT } from '../harness.mjs';
import { isWellFormedUtf16, recordingProxy } from '../proposed-rules.mjs';

const C = 'proposed-rule';
const STATUS = 'Proposed';

function rejectionReason(r) {
  return r.threw ? r.error.replace(/^RuleRejection: /, '') : null;
}

// crypto_pwhash is always stubbed here: rule checks only observe whether, and with which
// arguments, the library would be called. No real derivation runs, whatever the rules do.
function pwhashSpy(sodium) {
  return recordingProxy(sodium, { crypto_pwhash: (len) => new Uint8Array(len) });
}

export const proposedRuleChecks = [
  defineCheck({
    id: 'PR-PASSWORD-INPUT',
    category: C,
    primitive: 'Password input to Argon2id (and, later, OPAQUE)',
    title:
      'Proposed password rule: reject strings that are not well formed, apply NFC, require 1 to 4,096 UTF-8 bytes; rejected input never reaches the library',
    subject: ['harness reference predicate'],
    expectedFrom: 'the proposal; NFC results from Unicode canonical mappings',
    proposal: 'D-20; cryptographic-design.md §3.1; finding V-05',
    status: STATUS,
    enforcement: ENFORCEMENT.harness,
    run: (ctx) => {
      const r = ctx.rules;
      const accept = [
        ['ASCII', 'correct horse battery staple', 'correct horse battery staple'],
        ['spaces are kept', '  padded  ', '  padded  '],
        ['case is kept', 'Pa55WORD', 'Pa55WORD'],
        ['precomposed é', 'caf\u00e9', 'caf\u00e9'],
        ['decomposed é becomes precomposed', 'cafe\u0301', 'caf\u00e9'],
        ['ANGSTROM SIGN becomes U+00C5', '\u212b', '\u00c5'],
        ['Hangul jamo compose', '\u1100\u1161', '\uac00'],
        ['ligature unchanged (NFC, not NFKC)', '\ufb01', '\ufb01'],
        ['composition exclusion stays decomposed', '\u0958', '\u0915\u093c'],
        ['astral character (surrogate pair)', '\u{1f511}', '\u{1f511}'],
        ['4,096 ASCII bytes', 'a'.repeat(4096), 'a'.repeat(4096)],
        [
          '4,095 + 1 bytes of 3-byte characters',
          '\u20ac'.repeat(1365) + 'a',
          '\u20ac'.repeat(1365) + 'a',
        ],
      ];
      for (const [name, input, nfc] of accept) {
        const out = attempt(() => r.normalizePassword(input));
        assert(!out.threw, `${name}: rejected (${out.error})`);
        assert(equal(out.value.bytes, te.encode(nfc)), `${name}: wrong normalized bytes`, {
          got: hex(out.value.bytes).slice(0, 64),
        });
      }
      const rejectCases = [
        ['empty', '', 'password_empty'],
        ['4,097 ASCII bytes', 'a'.repeat(4097), 'password_too_long'],
        ['4,098 bytes of 3-byte characters', '\u20ac'.repeat(1366), 'password_too_long'],
        [
          'limit applies after NFC (4,095 bytes become 8,190)',
          '\u0958'.repeat(1365),
          'password_too_long',
        ],
        ['lone high surrogate', 'a\ud800b', 'password_not_well_formed'],
        ['lone low surrogate', 'a\udc00b', 'password_not_well_formed'],
        ['reversed surrogate pair', '\udc00\ud800', 'password_not_well_formed'],
        ['trailing high surrogate', 'abc\ud83d', 'password_not_well_formed'],
        ['bytes instead of a string', te.encode('abc'), 'password_not_a_string'],
        ['null', null, 'password_not_a_string'],
      ];
      const salt = synthetic('pr-salt', 16);
      for (const [name, input, reason] of rejectCases) {
        assert(
          rejectionReason(attempt(() => r.normalizePassword(input))) === reason,
          `${name}: not rejected as ${reason}`,
        );
        const { proxy, calls } = pwhashSpy(ctx.sodium);
        const d = attempt(() => r.pwhash(proxy, 1, input, salt));
        assert(d.threw && calls.length === 0, `${name}: reached the library before rejection`);
      }
      const { proxy, calls } = pwhashSpy(ctx.sodium);
      r.pwhash(proxy, 1, 'cafe\u0301', salt);
      assert(
        calls.length === 1 && equal(calls[0].args[1], te.encode('caf\u00e9')),
        'the library did not receive the NFC UTF-8 bytes',
      );
      const native = typeof String.prototype.isWellFormed === 'function';
      if (native)
        for (const s of ['ok', 'a\ud800b', 'a\udc00b', '\u{1f511}', '\udc00\ud800', 'abc\ud83d'])
          assert(
            s.isWellFormed() === isWellFormedUtf16(s),
            `harness scan disagrees with String.prototype.isWellFormed for ${JSON.stringify(s)}`,
          );
      return {
        accepted: accept.length,
        rejected: rejectCases.length,
        nativeIsWellFormed: native,
        unicodeVersion: 'not determined; see README gaps',
      };
    },
  }),

  defineCheck({
    id: 'PR-KEY-AND-LENGTH-GUARDS',
    category: C,
    primitive: 'Keyed BLAKE2b-256 and crypto_kdf call shapes',
    title:
      'Proposed length rule: exact Uint8Array lengths for MAC keys (16 or 32) and KDF keys (32), 8 printable-ASCII context bytes, subkey length exactly 32; checked before any library call',
    subject: ['harness reference predicate'],
    expectedFrom: 'the proposal',
    proposal: 'cryptographic-design.md §2 and §3.3; findings V-12 and V-15',
    status: STATUS,
    enforcement: ENFORCEMENT.harness,
    notes:
      'These are the inputs that LB-BLAKE2B-KEY-LENGTH, LB-INPUT-TYPE-COERCION, LB-KDF-ARGUMENTS and LB-KDF-SUBKEY-LENGTH-STALE-MEMORY show the library accepts.',
    run: (ctx) => {
      const r = ctx.rules;
      const msg = synthetic('pr-msg', 50);
      const rejected = [
        ['15-byte MAC key', (s) => r.mac(s, synthetic('k15', 15), msg, 16)],
        ['17-byte MAC key declared as 16', (s) => r.mac(s, synthetic('k17', 17), msg, 16)],
        ['31-byte MAC key declared as 32', (s) => r.mac(s, synthetic('k31', 31), msg, 32)],
        ['24-byte MAC key length', (s) => r.mac(s, synthetic('k24', 24), msg, 24)],
        ['string MAC key', (s) => r.mac(s, 'k'.repeat(32), msg, 32)],
        ['string MAC message', (s) => r.mac(s, synthetic('k32', 32), 'text', 32)],
        ['KDF subkey length 15', (s) => r.kdf(s, synthetic('kk', 32), 'rvkeyst1', 15)],
        ['KDF subkey length 65', (s) => r.kdf(s, synthetic('kk', 32), 'rvkeyst1', 65)],
        ['KDF subkey length 64', (s) => r.kdf(s, synthetic('kk', 32), 'rvkeyst1', 64)],
        ['KDF non-ASCII context', (s) => r.kdf(s, synthetic('kk', 32), 'rvkeys\u00e9')],
        ['KDF 7-byte context', (s) => r.kdf(s, synthetic('kk', 32), 'rvkeyst')],
        ['KDF 31-byte key', (s) => r.kdf(s, synthetic('kk31', 31), 'rvkeyst1')],
        ['KDF string key', (s) => r.kdf(s, 'k'.repeat(32), 'rvkeyst1')],
      ];
      for (const [name, f] of rejected) {
        const { proxy, calls } = recordingProxy(ctx.sodium);
        const out = attempt(() => f(proxy));
        assert(out.threw && /^RuleRejection/.test(out.error), `${name}: not rejected by the rule`);
        assert(calls.length === 0, `${name}: the library was called before the rule rejected it`);
      }
      for (const n of [16, 32]) {
        const key = synthetic(`ok-${n}`, n);
        assert(
          equal(r.mac(ctx.sodium, key, msg, n), ctx.sodium.crypto_generichash(32, msg, key)),
          `valid ${n}-byte MAC changed the result`,
        );
      }
      const k = synthetic('ok-kdf', 32);
      assert(
        equal(
          r.kdf(ctx.sodium, k, 'rvkeyst1'),
          ctx.sodium.crypto_kdf_derive_from_key(32, 1, 'rvkeyst1', k),
        ),
        'valid KDF call changed the result',
      );
      return { rejectedBeforeLibraryCall: rejected.length };
    },
  }),

  defineCheck({
    id: 'PR-KDF-PROFILE-REGISTRY',
    category: C,
    primitive: 'Argon2id parameters (crypto_pwhash)',
    title:
      'Proposed profile rule: parameters come only from the profile registry (profile 1: 64 MiB, t = 3, p = 1, 32 bytes); unknown, reserved, raw and excessive parameters are rejected before any library call',
    subject: ['harness reference predicate'],
    expectedFrom: 'the proposal',
    proposal: 'cryptographic-design.md §3.2; D-03 (profile 1 provisional)',
    status: STATUS,
    enforcement: ENFORCEMENT.harness,
    notes:
      'LB-ARGON2-SILENT-ADJUSTMENTS shows that the library itself accepts excessive memory limits.',
    run: (ctx) => {
      const r = ctx.rules;
      const salt = synthetic('pr-prof-salt', 16);
      const p1 = r.resolveProfile(1);
      assert(
        p1.opslimit === 3 && p1.memlimit === 67108864 && p1.outLength === 32,
        'profile 1 parameters changed',
      );
      const bad = [
        ['profile 2 (reserved, not enabled)', 2, 'profile_not_enabled'],
        ['profile 0', 0, 'profile_unknown'],
        ['profile 3', 3, 'profile_unknown'],
        ['profile -1', -1, 'profile_unknown'],
        ['profile 1.5', 1.5, 'profile_id_not_integer'],
        ['profile "1"', '1', 'profile_id_not_integer'],
        ['profile NaN', NaN, 'profile_id_not_integer'],
        ['profile null', null, 'profile_id_not_integer'],
        [
          'raw weaker parameters',
          { opslimit: 1, memlimit: 8192, outLength: 32 },
          'profile_id_not_integer',
        ],
        [
          'raw excessive parameters (1 GiB)',
          { opslimit: 3, memlimit: 2 ** 30, outLength: 32 },
          'profile_id_not_integer',
        ],
      ];
      for (const [name, id, reason] of bad) {
        const { proxy, calls } = pwhashSpy(ctx.sodium);
        const out = attempt(() => r.pwhash(proxy, id, 'password', salt));
        assert(rejectionReason(out) === reason, `${name}: not rejected as ${reason}`);
        assert(calls.length === 0, `${name}: the library was called`);
      }
      for (const n of [0, 15, 17]) {
        const { proxy, calls } = pwhashSpy(ctx.sodium);
        const out = attempt(() => r.pwhash(proxy, 1, 'password', new Uint8Array(n)));
        assert(
          rejectionReason(out) === 'password_salt_wrong_length' && calls.length === 0,
          `${n}-byte salt not rejected first`,
        );
      }
      const { proxy, calls } = pwhashSpy(ctx.sodium);
      r.pwhash(proxy, 1, 'password', salt);
      const [len, , s, ops, mem, alg] = calls[0]?.args ?? [];
      assert(
        calls.length === 1 &&
          len === 32 &&
          s === salt &&
          ops === 3 &&
          mem === 67108864 &&
          alg === ctx.sodium.crypto_pwhash_ALG_ARGON2ID13,
        'profile 1 call arguments are wrong',
        { args: calls[0]?.args?.map(String) },
      );
      return {
        profile1: { opslimit: 3, memlimit: 67108864, outLength: 32, algorithm: 'ARGON2ID13' },
      };
    },
  }),
];
