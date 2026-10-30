// Checks that run unchanged in Node (Vitest) and in browser pages and dedicated workers
// (scripts/browser-tests.mjs). They exercise the package source with the real pinned libsodium.

import { concat, u32be } from '../../src/bytes.js';
import { CRYPTO_ERROR_CODES, RuveeCryptoError, type CryptoErrorCode } from '../../src/errors.js';
import { PURPOSES, sealEnvelope } from '../../src/envelope.js';
import {
  initRuveeCrypto,
  padPlaintext,
  unpadPlaintext,
  normalizePassword,
} from '../../src/index.js';
import { buildRuveeCrypto, randomNonces } from '../../src/operations.js';
import { guardPrimitives, KDF_CONTEXTS, type RawPrimitives } from '../../src/primitives.js';
import { resolveKdfProfile } from '../../src/profiles.js';
import { cat, hex, pattern, randomBytesFrom, same, seededRandom } from '../support/bytes.js';
import { loadXChaChaVectors, type ReadVectorFile } from '../support/published-vectors.js';
import { recordingPrimitives } from '../support/recording.js';
import { packageOutputs, referenceOutputs, type ProvisionalVectorFile } from './provisional.js';
import { PAIRING_CHECKS, VAULT_CHECKS } from './vault-checks.js';

/** The parts of libsodium.js used directly by checks, never by the package outside src/libsodium.ts. */
export interface LibsodiumForChecks {
  crypto_kdf_derive_from_key(len: number, id: number, ctx: string, key: Uint8Array): Uint8Array;
  pad(buf: Uint8Array, blocksize: number): Uint8Array;
  unpad(buf: Uint8Array, blocksize: number): Uint8Array;
}

export interface PortableEnv {
  raw: RawPrimitives;
  sodium: LibsodiumForChecks;
  readVector: ReadVectorFile;
  committedVectors: ProvisionalVectorFile;
}

export interface PortableCheck {
  readonly id: string;
  readonly category:
    'published-kat' | 'cross-implementation' | 'protocol' | 'boundary' | 'negative';
  run(env: PortableEnv): Promise<void> | void;
}

class CheckError extends Error {}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new CheckError(message);
}

function codeOf(fn: () => unknown): CryptoErrorCode | 'returned' | 'foreign-error' {
  try {
    fn();
    return 'returned';
  } catch (e) {
    return e instanceof RuveeCryptoError ? e.code : 'foreign-error';
  }
}

function expectCode(fn: () => unknown, code: CryptoErrorCode, label: string): void {
  const got = codeOf(fn);
  assert(got === code, `${label}: expected ${code}, got ${got}`);
}

function flip(bytes: Uint8Array, index: number, mask = 0x01): Uint8Array {
  const c = bytes.slice();
  c[index] = (c[index] ?? 0) ^ mask;
  return c;
}

const PUBLIC_METHODS = [
  'accountProofPublicKey',
  'createPairingRequest',
  'createPairingResponse',
  'deriveAccountUnlockKey',
  'deriveLoginStateSealKey',
  'deriveRecoveryKeys',
  'formatPairingCode',
  'formatRecoveryKey',
  'generateDeviceKey',
  'generateKey',
  'generateKeyId',
  'generatePairingSecret',
  'generatePasswordSalt',
  'generateRecoveryKey',
  'generateUuid',
  'itemsDigest',
  'loginBinding',
  'manifestHash',
  'openItemRecord',
  'openKeyset',
  'openLocalRecord',
  'openLoginState',
  'openManifest',
  'openPairingResponse',
  'pairingId',
  'parsePairingCode',
  'parseRecoveryKey',
  'proofPayload',
  'recordHash',
  'recoveryVerifier',
  'sealItemRecord',
  'sealKeyset',
  'sealLocalRecord',
  'sealLoginState',
  'sealManifest',
  'sessionRef',
  'setupBinding',
  'signAccountProof',
  'signDeviceProof',
  'unwrapAccountKey',
  'unwrapAccountKeyForRecovery',
  'verifyAccountProof',
  'verifyDeviceProof',
  'verifyPairingRequest',
  'wrapAccountKey',
  'wrapAccountKeyForRecovery',
];

async function fixtures() {
  const crypto = await initRuveeCrypto();
  const accountId = pattern(21, 16);
  const accountKey = crypto.generateKey();
  const accountKeyId = crypto.generateKeyId();
  const passwordSalt = crypto.generatePasswordSalt();
  const accountUnlockKey = crypto.generateKey();
  const wrapContext = {
    accountUnlockKey,
    accountId,
    accountKeyId,
    accountKeyEpoch: 7,
    profile: 1,
    passwordSalt,
  };
  const keysetContext = { accountKey, accountKeyId, accountId, keysetVersion: 3 };
  const keyset = {
    secretKey: crypto.generateKey(),
    vaults: [
      {
        vaultId: '0b8f3c2e-9a1d-4f6b-8e7c-2d5a4b3c1e0f',
        vkId: crypto.generateKeyId(),
        vk: crypto.generateKey(),
      },
    ],
  } as const;
  return {
    crypto,
    accountId,
    accountKey,
    accountKeyId,
    passwordSalt,
    wrapContext,
    keysetContext,
    keyset,
  };
}

const ENVELOPE_REJECTIONS: readonly CryptoErrorCode[] = [
  'malformed_envelope',
  'unsupported_format',
  'wrong_purpose',
  'wrong_key',
  'integrity_failure',
];

const BASE_CHECKS: readonly PortableCheck[] = [
  {
    id: 'init-and-public-surface',
    category: 'protocol',
    async run() {
      const crypto = await initRuveeCrypto();
      assert(Object.isFrozen(crypto), 'operations object is frozen');
      assert(
        JSON.stringify(Object.keys(crypto).sort()) === JSON.stringify(PUBLIC_METHODS),
        `public methods: ${Object.keys(crypto).sort().join(',')}`,
      );
      assert(crypto.generateKey().length === 32, 'generateKey is 32 bytes');
      assert(crypto.generateKeyId().length === 16, 'generateKeyId is 16 bytes');
      assert(crypto.generatePasswordSalt().length === 16, 'generatePasswordSalt is 16 bytes');
      assert(!same(crypto.generateKey(), crypto.generateKey()), 'two keys differ');
      assert(CRYPTO_ERROR_CODES.includes('integrity_failure'), 'error code list');
    },
  },
  {
    id: 'provisional-protocol-vectors',
    category: 'protocol',
    run(env) {
      const fromPackage = packageOutputs(env.raw);
      const fromReference = referenceOutputs();
      assert(
        JSON.stringify(fromPackage) === JSON.stringify(fromReference),
        'package and noble reference disagree',
      );
      assert(
        JSON.stringify(fromPackage) === JSON.stringify(env.committedVectors.outputs),
        'package output differs from the committed provisional vectors',
      );
      const byLabel = new Map(fromPackage.passwords.map((p) => [p.label, p.result]));
      assert(
        JSON.stringify(byLabel.get('nfc')) === JSON.stringify(byLabel.get('nfd-same-as-nfc')),
        'NFC and NFD inputs derive the same keys',
      );
      assert(byLabel.get('lone-surrogate-rejected') === 'rejected', 'lone surrogate rejected');
      const status: unknown = env.committedVectors.status;
      assert(status === 'provisional', 'vector file is labelled provisional');
    },
  },
  {
    id: 'published-xchacha-draft-a31',
    category: 'published-kat',
    async run(env) {
      const { draft } = await loadXChaChaVectors(env.readVector);
      const p = guardPrimitives(env.raw);
      const sealed = p.aeadEncrypt(draft.plaintext, draft.aad, draft.nonce, draft.key);
      assert(same(sealed, draft.sealed), 'draft §A.3.1 ciphertext and tag');
      const opened = p.aeadDecrypt(draft.sealed, draft.aad, draft.nonce, draft.key);
      assert(opened && same(opened, draft.plaintext), 'draft §A.3.1 decrypts');
    },
  },
  {
    id: 'published-xchacha-wycheproof',
    category: 'published-kat',
    async run(env) {
      const { wycheproof } = await loadXChaChaVectors(env.readVector);
      const p = guardPrimitives(env.raw);
      let valid = 0;
      let invalid = 0;
      let refusedByGuard = 0;
      for (const v of wycheproof) {
        if (v.nonce.length !== 24 || v.key.length !== 32) {
          assert(!v.valid, `${v.id}: off-size parameters only in invalid tests`);
          expectCode(
            () => p.aeadDecrypt(v.sealed, v.aad, v.nonce, v.key),
            'invalid_argument',
            v.id,
          );
          refusedByGuard++;
          continue;
        }
        const opened = p.aeadDecrypt(v.sealed, v.aad, v.nonce, v.key);
        if (v.valid) {
          assert(opened && same(opened, v.plaintext), `${v.id}: decrypts`);
          assert(
            same(p.aeadEncrypt(v.plaintext, v.aad, v.nonce, v.key), v.sealed),
            `${v.id}: encrypts`,
          );
          valid++;
        } else {
          assert(opened === null, `${v.id}: rejected`);
          invalid++;
        }
      }
      assert(wycheproof.length === 315, `315 tests, got ${wycheproof.length}`);
      assert(valid + invalid + refusedByGuard === 315, 'every test classified');
      assert(
        refusedByGuard === 9,
        `9 invalid nonce sizes refused by the guard, got ${refusedByGuard}`,
      );
    },
  },
  {
    id: 'password-input-rule',
    category: 'boundary',
    run() {
      const reason = (input: unknown) => {
        try {
          normalizePassword(input);
          return 'accepted';
        } catch (e) {
          return e instanceof RuveeCryptoError ? `${e.code}:${String(e.reason)}` : 'foreign';
        }
      };
      for (const bad of ['a\ud800', '\udc00a', 'a\udc00\ud800b', '\ud83d', 'x\ud83dy'])
        assert(
          reason(bad) === 'invalid_password:malformed_unicode',
          `lone surrogate ${hex(new TextEncoder().encode(bad))}`,
        );
      assert(reason('\u{1f600}') === 'accepted', 'a valid surrogate pair is accepted');
      for (const bad of [undefined, null, 42, ['a'], {}, new String('pw')])
        assert(reason(bad) === 'invalid_password:not_a_string', `non-string ${typeof bad}`);
      assert(reason('') === 'invalid_password:empty', 'empty');
      assert(normalizePassword('e\u0301') === '\u00e9', 'NFC composes');
      assert(normalizePassword('\u00e9') === normalizePassword('e\u0301'), 'NFC and NFD agree');
      assert(
        normalizePassword('\ufb01') === '\ufb01',
        'compatibility ligature kept (NFC, not NFKC)',
      );
      assert(normalizePassword('\u212b') === '\u00c5', 'singleton decomposition (Angstrom sign)');
      for (const ws of [
        '  lead',
        'trail  ',
        'in ner',
        '\ttab',
        'nb\u00a0sp',
        'ideo\u3000space',
        'line\nbreak',
      ])
        assert(normalizePassword(ws) === ws, `whitespace preserved: ${JSON.stringify(ws)}`);
      assert(normalizePassword('PassWord') === 'PassWord', 'case preserved');
      assert(normalizePassword('\ufeffbom') === '\ufeffbom', 'leading U+FEFF preserved');
      assert(reason('a'.repeat(4096)) === 'accepted', '4,096 ASCII bytes');
      assert(reason('a'.repeat(4097)) === 'invalid_password:too_long', '4,097 ASCII bytes');
      assert(reason('\u{1f511}'.repeat(1024)) === 'accepted', '1,024 four-byte characters');
      assert(
        reason('\u{1f511}'.repeat(1024) + 'a') === 'invalid_password:too_long',
        '4,097 bytes with emoji',
      );
      assert(
        reason('\u20ac'.repeat(1365) + 'a') === 'accepted',
        '3-byte characters to exactly 4,096',
      );
      assert(reason('\u20ac'.repeat(1366)) === 'invalid_password:too_long', '4,098 bytes');
      // The limit is on UTF-8 bytes after NFC: 6,144 bytes as NFD, 4,096 after composition.
      assert(reason('e\u0301'.repeat(2048)) === 'accepted', 'NFD over the limit, NFC within');
      // U+0958 is a composition exclusion: NFC expands it from 3 to 6 bytes.
      assert(
        reason('\u0958'.repeat(1365)) === 'invalid_password:too_long',
        'NFC growth past the limit',
      );
      assert(reason('a'.repeat(65_537)) === 'invalid_password:too_long', 'pre-normalization bound');
    },
  },
  {
    id: 'kdf-profile-floor',
    category: 'boundary',
    run() {
      const { raw, calls } = recordingPrimitives();
      const crypto = createCryptoOver(raw);
      for (const profile of [
        0,
        -1,
        2,
        3,
        255,
        1.5,
        Number.NaN,
        '1',
        null,
        undefined,
        1n,
        { id: 1 },
      ]) {
        expectCode(
          () =>
            crypto.deriveAccountUnlockKey({
              password: 'pw',
              passwordSalt: pattern(1, 16),
              profile: profile as number,
              secretKey: pattern(2, 32),
              accountId: pattern(3, 16),
            }),
          'unsupported_profile',
          `profile ${typeof profile === 'object' && profile !== null ? 'object' : String(profile)}`,
        );
      }
      assert(calls.length === 0, 'no library call for an unsupported profile');
      const profileStatus: string = resolveKdfProfile(1).status;
      assert(profileStatus === 'provisional', 'profile 1 is provisional');
      try {
        resolveKdfProfile(2);
        assert(false, 'profile 2 resolved');
      } catch (e) {
        assert(e instanceof RuveeCryptoError && e.reason === 'reserved', 'profile 2 is reserved');
      }
    },
  },
  {
    id: 'v15-defect-present-in-pinned-library',
    category: 'boundary',
    run(env) {
      // Reproduces V-15 directly against libsodium.js. If this fails, the pinned library no
      // longer behaves as documented: re-read the finding before changing the pin or the guard.
      const a = env.sodium.crypto_kdf_derive_from_key(64, 1, 'rvkeyst1', pattern(30, 32));
      const b = env.sodium.crypto_kdf_derive_from_key(65, 1, 'rvkeyst1', pattern(31, 32));
      assert(b.length === 65, 'library returned 65 bytes without an error');
      assert(same(b.subarray(0, 64), a), "library returned the previous derivation's subkey");
    },
  },
  {
    id: 'v15-contained-by-wrapper',
    category: 'boundary',
    run(env) {
      for (const inner of [undefined, env.raw]) {
        const { raw, calls } = recordingPrimitives(inner);
        const p = guardPrimitives(raw);
        const key = pattern(32, 32);
        const lengths: unknown[] = [
          -1,
          0,
          1,
          15,
          16,
          17,
          31,
          33,
          63,
          64,
          65,
          128,
          2 ** 31,
          2 ** 32 + 32,
          Number.NaN,
          Number.POSITIVE_INFINITY,
          32.5,
          '32',
          32n,
          null,
        ];
        for (const len of lengths)
          expectCode(
            () => p.kdf(len as number, 1, KDF_CONTEXTS.keyset, key),
            'invalid_argument',
            `subkey length ${String(len)}`,
          );
        for (const id of [0, 2, 2 ** 31, -1, 1.5, 1n, '1'])
          expectCode(
            () => p.kdf(32, id as number, KDF_CONTEXTS.keyset, key),
            'invalid_argument',
            `subkey id ${String(id)}`,
          );
        for (const ctx of [
          'rvkeyst',
          'rvkeyst12',
          'rvdevlb1',
          'rvk\u00e9yst',
          'RVKEYST1',
          '        ',
          '\u00e9\u00e9\u00e9\u00e9',
        ])
          expectCode(
            () => p.kdf(32, 1, ctx, key),
            'invalid_argument',
            `context ${JSON.stringify(ctx)}`,
          );
        for (const k of [
          pattern(1, 31),
          pattern(1, 33),
          new Uint8Array(0),
          'k'.repeat(32),
          Array.from(key),
        ])
          expectCode(
            () => p.kdf(32, 1, KDF_CONTEXTS.keyset, k as Uint8Array),
            'invalid_argument',
            'kdf key',
          );
        const rejectedCalls: number = calls.length;
        assert(
          rejectedCalls === 0,
          `rejected KDF calls reached the library ${rejectedCalls} times`,
        );
        const subkey = p.kdf(32, 1, KDF_CONTEXTS.keyset, key);
        assert(subkey.length === 32 && calls.length === 1, 'subkey length 32 is accepted once');
        const [call] = calls;
        assert(
          call?.args[0] === 32 && call.args[1] === 1 && call.args[2] === 'rvkeyst1',
          'fixed arguments',
        );
      }
    },
  },
  {
    id: 'other-library-boundaries-contained',
    category: 'boundary',
    run(env) {
      const { raw, calls } = recordingPrimitives(env.raw);
      const p = guardPrimitives(raw);
      const key = pattern(40, 32);
      const profile = resolveKdfProfile(1);
      // V-12: BLAKE2b accepts 1- to 15-byte keys and outputs.
      for (const len of [0, 1, 15, 16, 31, 33, 64, 65])
        expectCode(() => p.mac(len, pattern(1, 8), key), 'invalid_argument', `mac output ${len}`);
      // Keys of 16 (`RK`) and 32 bytes only.
      for (const len of [0, 1, 15, 17, 31, 33, 64, 65])
        expectCode(
          () => p.mac(32, pattern(1, 8), pattern(2, len)),
          'invalid_argument',
          `mac key ${len}`,
        );
      expectCode(
        () => p.mac(32, pattern(1, 8), 'k'.repeat(32) as unknown as Uint8Array),
        'invalid_argument',
        'string key',
      );
      expectCode(() => p.mac(32, pattern(1, 8193), key), 'invalid_argument', 'mac message bound');
      // Argon2id: memlimit rounding and no ceiling; parameters only from the registry.
      for (const forged of [
        { ...profile },
        { ...profile, memlimit: 1024 },
        { ...profile, memlimit: profile.memlimit + 1 },
        { ...profile, opslimit: 1 },
      ])
        expectCode(
          () => p.argon2id(pattern(1, 8), pattern(2, 16), forged),
          'invalid_argument',
          'forged profile',
        );
      for (const salt of [8, 15, 17])
        expectCode(
          () => p.argon2id(pattern(1, 8), pattern(2, salt), profile),
          'invalid_argument',
          `salt ${salt}`,
        );
      for (const pw of [0, 4097])
        expectCode(
          () => p.argon2id(pattern(1, pw), pattern(2, 16), profile),
          'invalid_argument',
          `password ${pw} bytes`,
        );
      // AEAD sizes, and string inputs that libsodium.js would silently UTF-8 encode.
      const nonce = pattern(3, 24);
      for (const [label, fn] of [
        ['key 31', () => p.aeadEncrypt(pattern(1, 4), new Uint8Array(0), nonce, pattern(1, 31))],
        ['nonce 12', () => p.aeadEncrypt(pattern(1, 4), new Uint8Array(0), pattern(1, 12), key)],
        ['nonce 25', () => p.aeadDecrypt(pattern(1, 20), new Uint8Array(0), pattern(1, 25), key)],
        [
          'plaintext bound',
          () => p.aeadEncrypt(new Uint8Array(1024 * 1024 + 1), new Uint8Array(0), nonce, key),
        ],
        ['aad bound', () => p.aeadEncrypt(pattern(1, 4), new Uint8Array(1025), nonce, key)],
        ['ciphertext 15', () => p.aeadDecrypt(pattern(1, 15), new Uint8Array(0), nonce, key)],
        [
          'string message',
          () => p.aeadEncrypt('hi' as unknown as Uint8Array, new Uint8Array(0), nonce, key),
        ],
        [
          'Uint16Array key',
          () =>
            p.aeadEncrypt(
              pattern(1, 4),
              new Uint8Array(0),
              nonce,
              new Uint16Array(16) as unknown as Uint8Array,
            ),
        ],
      ] as const)
        expectCode(fn, 'invalid_argument', label);
      for (const len of [0, 1, 8, 15, 33, 64])
        expectCode(() => p.randomBytes(len), 'invalid_argument', `random ${len}`);
      assert(calls.length === 0, `rejected calls reached the library ${calls.length} times`);
    },
  },
  {
    id: 'envelope-parsing-and-tampering',
    category: 'negative',
    async run() {
      const f = await fixtures();
      const { crypto, wrapContext, accountKey } = f;
      const envelope = crypto.wrapAccountKey({ ...wrapContext, accountKey });
      assert(envelope.length === 93, 'password wrap is 93 bytes');
      const open = (e: unknown, over: Record<string, unknown> = {}) =>
        crypto.unwrapAccountKey({ ...wrapContext, ...over, envelope: e as Uint8Array });
      assert(same(open(envelope), accountKey), 'round trip');
      for (const len of [0, 1, 44, 60, 61, 92])
        expectCode(() => open(envelope.slice(0, len)), 'malformed_envelope', `length ${len}`);
      expectCode(() => open(cat(envelope, [0])), 'malformed_envelope', 'length 94');
      for (const [i, v] of [
        [0, 0x53],
        [1, 0x57],
        [2, 0x00],
        [2, 0x02],
        [3, 0x00],
        [3, 0x02],
      ] as const) {
        const e = envelope.slice();
        e[i] = v;
        expectCode(() => open(e), 'unsupported_format', `header byte ${i} = ${v}`);
      }
      for (const purpose of [0x00, 0x02, 0x03, 0x04, 0x09, 0xff]) {
        const e = envelope.slice();
        e[4] = purpose;
        expectCode(() => open(e), 'wrong_purpose', `purpose ${purpose}`);
      }
      for (let i = 5; i < 21; i++)
        expectCode(() => open(flip(envelope, i)), 'wrong_key', `key id byte ${i}`);
      for (let i = 21; i < 93; i++)
        expectCode(() => open(flip(envelope, i, 0x80)), 'integrity_failure', `byte ${i}`);
      expectCode(
        () => open(envelope, { accountId: pattern(99, 16) }),
        'integrity_failure',
        'other account',
      );
      expectCode(() => open(envelope, { accountKeyEpoch: 8 }), 'integrity_failure', 'other epoch');
      expectCode(
        () => open(envelope, { passwordSalt: pattern(98, 16) }),
        'integrity_failure',
        'other salt',
      );
      expectCode(
        () => open(envelope, { accountUnlockKey: pattern(97, 32) }),
        'integrity_failure',
        'wrong AUK',
      );
      expectCode(() => open(envelope, { profile: 2 }), 'unsupported_profile', 'reserved profile');
      expectCode(() => open(Array.from(envelope)), 'invalid_argument', 'array envelope');
      expectCode(
        () => open(envelope, { accountKeyEpoch: 2 ** 32 }),
        'invalid_argument',
        'epoch above u32',
      );

      const keysetEnvelope = crypto.sealKeyset({ ...f.keysetContext, keyset: f.keyset });
      const openKeyset = (e: Uint8Array, over: Record<string, unknown> = {}) =>
        crypto.openKeyset({ ...f.keysetContext, ...over, envelope: e });
      const opened = openKeyset(keysetEnvelope);
      assert(same(opened.secretKey, f.keyset.secretKey), 'keyset SK round trip');
      assert(same(opened.vaults[0].vk, f.keyset.vaults[0].vk), 'keyset VK round trip');
      assert(opened.vaults[0].vaultId === f.keyset.vaults[0].vaultId, 'keyset vault id round trip');
      expectCode(() => openKeyset(envelope), 'wrong_purpose', 'password wrap opened as keyset');
      expectCode(
        () => open(keysetEnvelope),
        'malformed_envelope',
        'keyset opened as password wrap',
      );
      expectCode(
        () => openKeyset(keysetEnvelope, { keysetVersion: 2 }),
        'integrity_failure',
        'older keyset version',
      );
      expectCode(
        () => openKeyset(keysetEnvelope, { accountKey: pattern(96, 32) }),
        'integrity_failure',
        'wrong AK',
      );
      expectCode(
        () => openKeyset(keysetEnvelope, { accountKeyId: pattern(95, 16) }),
        'wrong_key',
        'wrong ak_id',
      );
      expectCode(
        () => openKeyset(keysetEnvelope, { accountId: pattern(94, 16) }),
        'integrity_failure',
        'other account',
      );
      expectCode(
        () => openKeyset(new Uint8Array(16_446)),
        'malformed_envelope',
        'keyset above maximum',
      );
    },
  },
  {
    id: 'keyset-plaintext-schema',
    category: 'negative',
    async run(env) {
      const f = await fixtures();
      const p = guardPrimitives(env.raw);
      const k = f.keysetContext;
      const sealPlaintext = (json: string | Uint8Array) =>
        sealEnvelope(p, randomNonces(p), {
          purpose: PURPOSES.KEYSET,
          key: p.kdf(32, 1, KDF_CONTEXTS.keyset, k.accountKey),
          keyId: k.accountKeyId,
          context: concat(k.accountId, u32be(k.keysetVersion)),
          plaintext: typeof json === 'string' ? new TextEncoder().encode(json) : json,
        });
      const open = (json: string | Uint8Array) => () =>
        f.crypto.openKeyset({ ...k, envelope: sealPlaintext(json) });
      const sk = 'A'.repeat(43);
      // Canonical forms: the last character carries zero trailing bits.
      const vkId = `${'B'.repeat(21)}A`;
      const vk = `${'C'.repeat(42)}A`;
      const uuid = '0b8f3c2e-9a1d-4f6b-8e7c-2d5a4b3c1e0f';
      const doc = (over: Record<string, unknown> = {}, vault: Record<string, unknown> = {}) =>
        JSON.stringify({
          v: 1,
          secretKey: sk,
          vaults: [{ vaultId: uuid, vkId, vk, ...vault }],
          ...over,
        });
      assert(codeOf(open(doc())) === 'returned', 'well-formed keyset accepted');
      assert(
        codeOf(
          open(
            `{ "vaults" : [ { "vk":"${vk}", "vkId":"${vkId}", "vaultId":"${uuid}" } ], "secretKey":"${sk}", "v":1 }`,
          ),
        ) === 'returned',
        'whitespace and key order do not matter',
      );
      const malformed: [string, string | Uint8Array][] = [
        ['not JSON', 'keyset'],
        ['invalid UTF-8', Uint8Array.of(0x7b, 0xff, 0x7d)],
        ['leading BOM', `\ufeff${doc()}`],
        ['array', '[]'],
        ['null', 'null'],
        ['v = 2', doc({ v: 2 })],
        ['v as string', doc({ v: '1' })],
        ['missing secretKey', JSON.stringify({ v: 1, vaults: [] })],
        ['extra field', doc({ extra: true })],
        ['no vault', doc({ vaults: [] })],
        [
          'two vaults',
          doc({
            vaults: [
              { vaultId: uuid, vkId, vk },
              { vaultId: uuid, vkId, vk },
            ],
          }),
        ],
        ['extra vault field', doc({}, { name: 'x' })],
        ['secretKey 31 bytes', doc({ secretKey: 'A'.repeat(42) })],
        ['secretKey 33 bytes', doc({ secretKey: 'A'.repeat(44) })],
        ['secretKey padded', doc({ secretKey: `${'A'.repeat(43)}=` })],
        ['standard alphabet', doc({ secretKey: `${'A'.repeat(42)}+` })],
        ['non-canonical trailing bits', doc({ secretKey: `${'A'.repeat(42)}B` })],
        ['secretKey number', doc({ secretKey: 1 })],
        ['vkId 15 bytes', doc({}, { vkId: 'B'.repeat(20) })],
        ['uppercase vault id', doc({}, { vaultId: uuid.toUpperCase() })],
        ['vault id without dashes', doc({}, { vaultId: uuid.replace(/-/g, '') })],
      ];
      for (const [label, json] of malformed) expectCode(open(json), 'malformed_plaintext', label);
    },
  },
  {
    id: 'nonce-uniqueness',
    category: 'negative',
    async run() {
      // Detects a fixed or repeating nonce. It says nothing about the quality of the randomness.
      const f = await fixtures();
      const a = f.crypto.wrapAccountKey({ ...f.wrapContext, accountKey: f.accountKey });
      const b = f.crypto.wrapAccountKey({ ...f.wrapContext, accountKey: f.accountKey });
      assert(!same(a.subarray(21, 45), b.subarray(21, 45)), 'same input, different nonces');
      assert(!same(a.subarray(45), b.subarray(45)), 'same input, different ciphertexts');
      const seen = new Set<string>();
      for (let i = 0; i < 1000; i++)
        seen.add(
          hex(
            f.crypto
              .wrapAccountKey({ ...f.wrapContext, accountKey: f.accountKey })
              .subarray(21, 45),
          ),
        );
      assert(seen.size === 1000, '1,000 envelopes, 1,000 distinct nonces');
    },
  },
  {
    id: 'decoder-fuzz',
    category: 'negative',
    async run() {
      const f = await fixtures();
      const next = seededRandom(0x5eed);
      const valid = f.crypto.wrapAccountKey({ ...f.wrapContext, accountKey: f.accountKey });
      const keyset = f.crypto.sealKeyset({ ...f.keysetContext, keyset: f.keyset });
      const attempts: Uint8Array[] = [];
      for (let i = 0; i < 300; i++) attempts.push(randomBytesFrom(next, next(400)));
      for (let i = 0; i < 300; i++) {
        const base = i % 2 ? valid : keyset;
        const e = base.slice();
        for (let n = 1 + next(3); n > 0; n--) e[next(e.length)] = next(256);
        if (!same(e, base)) attempts.push(e);
      }
      for (let i = 0; i < 300; i++) {
        const e = cat(valid.subarray(0, 21), randomBytesFrom(next, 72));
        attempts.push(e);
      }
      for (const e of attempts) {
        for (const open of [
          () => f.crypto.unwrapAccountKey({ ...f.wrapContext, envelope: e }),
          () => f.crypto.openKeyset({ ...f.keysetContext, envelope: e }),
        ]) {
          const code = codeOf(open);
          assert(
            (ENVELOPE_REJECTIONS as readonly string[]).includes(code),
            `fuzzed input of ${e.length} bytes gave ${code}`,
          );
        }
      }
    },
  },
  {
    id: 'inv17-secret-key-alone-decrypts-nothing',
    category: 'protocol',
    async run() {
      const f = await fixtures();
      const base = {
        passwordSalt: f.passwordSalt,
        profile: 1,
        secretKey: f.keyset.secretKey,
        accountId: f.accountId,
      };
      const auk1 = f.crypto.deriveAccountUnlockKey({ ...base, password: 'first password' });
      const auk2 = f.crypto.deriveAccountUnlockKey({ ...base, password: 'second password' });
      assert(!same(auk1, auk2), 'AUK changes with the password for a fixed SK');
      const keySources = Object.values(PURPOSES).map((p) => p.keySource as string);
      assert(!keySources.includes('SK'), 'no purpose is keyed by SK');
      const wrap = f.crypto.wrapAccountKey({
        ...f.wrapContext,
        accountUnlockKey: auk1,
        accountKey: f.accountKey,
      });
      expectCode(
        () =>
          f.crypto.unwrapAccountKey({
            ...f.wrapContext,
            accountUnlockKey: f.keyset.secretKey,
            envelope: wrap,
          }),
        'integrity_failure',
        'SK used as AUK',
      );
    },
  },
  {
    id: 'padding-matches-libsodium',
    category: 'cross-implementation',
    run(env) {
      const lengths = [
        ...Array.from({ length: 600 }, (_, i) => i),
        1000,
        4095,
        4096,
        65_279,
        65_280,
        65_535,
      ];
      for (const len of lengths) {
        const data = pattern(len, len);
        const ours = padPlaintext(data);
        assert(same(ours, env.sodium.pad(data, 256)), `pad ${len}`);
        assert(same(unpadPlaintext(ours), data), `unpad ${len}`);
        assert(same(env.sodium.unpad(ours, 256), data), `libsodium unpads ours ${len}`);
      }
      expectCode(
        () => padPlaintext(new Uint8Array(65_536)),
        'invalid_argument',
        'pad above maximum',
      );
      const bad: [string, Uint8Array][] = [
        ['empty', new Uint8Array(0)],
        ['255 bytes', new Uint8Array(255).fill(0x80)],
        ['above 65,536', cat(new Uint8Array(65_536), [0x80], new Uint8Array(255))],
        ['all zero', new Uint8Array(256)],
        ['wrong marker', cat(pattern(1, 10), [0x81], new Uint8Array(245))],
        ['data after marker', cat(pattern(1, 10), [0x80, 0x01], new Uint8Array(244))],
        ['marker outside last block', cat([0x80], new Uint8Array(511))],
      ];
      for (const [label, padded] of bad)
        expectCode(() => unpadPlaintext(padded), 'malformed_plaintext', label);
    },
  },
];

function createCryptoOver(raw: RawPrimitives) {
  const p = guardPrimitives(raw);
  return buildRuveeCrypto(p, randomNonces(p));
}

export const PORTABLE_CHECKS: readonly PortableCheck[] = [
  ...BASE_CHECKS,
  ...VAULT_CHECKS,
  ...PAIRING_CHECKS,
];
