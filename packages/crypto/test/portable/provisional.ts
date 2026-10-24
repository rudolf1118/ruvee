// Provisional Ruvee protocol vectors (cryptographic-design §8, category 2), computed twice: by the
// package on libsodium and by the independent noble reference. They must agree with each other
// and with the committed file. NOT a compatibility promise: the format has not been reviewed.

import { encodeKeyset } from '../../src/keyset.js';
import { passwordBytes } from '../../src/password.js';
import { guardPrimitives, KDF_CONTEXTS, type RawPrimitives } from '../../src/primitives.js';
import { resolveKdfProfile } from '../../src/profiles.js';
import { createFixedNonceCrypto } from '../../src/testing/fixed-nonce.js';
import {
  refAccountUnlockKey,
  refEnvelope,
  refKdf,
  refKeysetContext,
  refKeysetPlaintext,
  refPasswordBytes,
  refPasswordKey,
  refWrapContext,
} from '../reference/noble-reference.js';
import { hex, pattern } from '../support/bytes.js';

export const INPUTS = {
  accountId: pattern(1, 16),
  passwordSalt: pattern(2, 16),
  secretKey: pattern(3, 32),
  accountKey: pattern(4, 32),
  accountKeyId: pattern(5, 16),
  accountKeyEpoch: 1,
  profile: 1,
  keysetVersion: 1,
  vaultId: '3f1c9a52-7d4e-4b8a-9c21-5e6f7a8b9c0d',
  vaultKeyId: pattern(6, 16),
  vaultKey: pattern(7, 32),
  wrapNonce: pattern(8, 24),
  keysetNonce: pattern(9, 24),
} as const;

export const PASSWORD_CASES: readonly { label: string; password: string }[] = [
  { label: 'ascii', password: 'correct horse battery staple' },
  { label: 'whitespace-preserved', password: '  pass word\t' },
  { label: 'nfc', password: '\u00c5ngstr\u00f6m caf\u00e9' },
  { label: 'nfd-same-as-nfc', password: 'A\u030angstro\u0308m cafe\u0301' },
  {
    label: 'emoji-and-non-latin',
    password: '\u{1f510} \u043f\u0430\u0440\u043e\u043b\u044c \u5bc6\u7801',
  },
  { label: 'maximum-4096-utf8-bytes', password: '\u{1f511}'.repeat(1024) },
  { label: 'lone-surrogate-rejected', password: 'abc\ud800def' },
];

type PasswordResult = 'rejected' | { passwordUtf8: string; pwk: string; auk: string };

export interface ProvisionalOutputs {
  passwords: { label: string; passwordUtf16: string; result: PasswordResult }[];
  keysetKey: string;
  accountKeyWrap: { aukFrom: string; envelope: string };
  keyset: { plaintext: string; envelope: string };
}

function utf16(text: string): string {
  return Array.from({ length: text.length }, (_, i) =>
    text.charCodeAt(i).toString(16).padStart(4, '0'),
  ).join('');
}

const WRAP_AUK_FROM = 'ascii';

function aukFor(outputs: ProvisionalOutputs['passwords']): string {
  const r = outputs.find((p) => p.label === WRAP_AUK_FROM)?.result;
  if (!r || r === 'rejected') throw new Error('ascii case missing');
  return r.auk;
}

function fromHex(text: string): Uint8Array {
  return Uint8Array.from({ length: text.length / 2 }, (_, i) =>
    parseInt(text.slice(i * 2, i * 2 + 2), 16),
  );
}

export function packageOutputs(raw: RawPrimitives): ProvisionalOutputs {
  const p = guardPrimitives(raw);
  const crypto = createFixedNonceCrypto(raw, [INPUTS.wrapNonce, INPUTS.keysetNonce]);
  const profile = resolveKdfProfile(INPUTS.profile);
  const passwords = PASSWORD_CASES.map(({ label, password }) => {
    let bytes: Uint8Array;
    try {
      bytes = passwordBytes(password);
    } catch {
      return { label, passwordUtf16: utf16(password), result: 'rejected' as const };
    }
    const pwk = p.argon2id(bytes, INPUTS.passwordSalt, profile);
    const auk = crypto.deriveAccountUnlockKey({
      password,
      passwordSalt: INPUTS.passwordSalt,
      profile: INPUTS.profile,
      secretKey: INPUTS.secretKey,
      accountId: INPUTS.accountId,
    });
    return {
      label,
      passwordUtf16: utf16(password),
      result: { passwordUtf8: hex(bytes), pwk: hex(pwk), auk: hex(auk) },
    };
  });
  const wrap = crypto.wrapAccountKey({
    accountUnlockKey: fromHex(aukFor(passwords)),
    accountKey: INPUTS.accountKey,
    accountId: INPUTS.accountId,
    accountKeyId: INPUTS.accountKeyId,
    accountKeyEpoch: INPUTS.accountKeyEpoch,
    profile: INPUTS.profile,
    passwordSalt: INPUTS.passwordSalt,
  });
  const keyset = {
    secretKey: INPUTS.secretKey,
    vaults: [{ vaultId: INPUTS.vaultId, vkId: INPUTS.vaultKeyId, vk: INPUTS.vaultKey }],
  } as const;
  const keysetEnvelope = crypto.sealKeyset({
    accountKey: INPUTS.accountKey,
    accountKeyId: INPUTS.accountKeyId,
    accountId: INPUTS.accountId,
    keysetVersion: INPUTS.keysetVersion,
    keyset,
  });
  return {
    passwords,
    keysetKey: hex(p.kdf(32, 1, KDF_CONTEXTS.keyset, INPUTS.accountKey)),
    accountKeyWrap: { aukFrom: WRAP_AUK_FROM, envelope: hex(wrap) },
    keyset: { plaintext: hex(encodeKeyset(keyset)), envelope: hex(keysetEnvelope) },
  };
}

export function referenceOutputs(): ProvisionalOutputs {
  const passwords = PASSWORD_CASES.map(({ label, password }) => {
    const bytes = refPasswordBytes(password);
    if (bytes === 'rejected')
      return { label, passwordUtf16: utf16(password), result: 'rejected' as const };
    const pwk = refPasswordKey(bytes, INPUTS.passwordSalt);
    const auk = refAccountUnlockKey(
      INPUTS.secretKey,
      INPUTS.accountId,
      INPUTS.profile,
      INPUTS.passwordSalt,
      pwk,
    );
    return {
      label,
      passwordUtf16: utf16(password),
      result: { passwordUtf8: hex(bytes), pwk: hex(pwk), auk: hex(auk) },
    };
  });
  const keysetKey = refKdf(INPUTS.accountKey, 'rvkeyst1');
  const plaintext = refKeysetPlaintext(
    INPUTS.secretKey,
    INPUTS.vaultId,
    INPUTS.vaultKeyId,
    INPUTS.vaultKey,
  );
  return {
    passwords,
    keysetKey: hex(keysetKey),
    accountKeyWrap: {
      aukFrom: WRAP_AUK_FROM,
      envelope: hex(
        refEnvelope(
          0x01,
          fromHex(aukFor(passwords)),
          INPUTS.accountKeyId,
          INPUTS.wrapNonce,
          refWrapContext(
            INPUTS.accountId,
            INPUTS.accountKeyEpoch,
            INPUTS.profile,
            INPUTS.passwordSalt,
          ),
          INPUTS.accountKey,
        ),
      ),
    },
    keyset: {
      plaintext: hex(plaintext),
      envelope: hex(
        refEnvelope(
          0x03,
          keysetKey,
          INPUTS.accountKeyId,
          INPUTS.keysetNonce,
          refKeysetContext(INPUTS.accountId, INPUTS.keysetVersion),
          plaintext,
        ),
      ),
    },
  };
}

export interface ProvisionalVectorFile {
  status: 'provisional';
  notice: string;
  specification: string;
  inputs: Record<string, string | number>;
  outputs: ProvisionalOutputs;
}

export function vectorFile(outputs: ProvisionalOutputs): ProvisionalVectorFile {
  return {
    status: 'provisional',
    notice:
      'Generated by packages/crypto and checked against an independent @noble/* reference. ' +
      'The byte format has not been reviewed or frozen; this file is regenerated whenever it ' +
      'changes and is not a compatibility promise. Synthetic inputs only; fixed nonces come from ' +
      'the test-only entry point.',
    specification: 'docs/security/cryptographic-design.md §3.1-§4.4 and §5.1',
    inputs: Object.fromEntries(
      Object.entries(INPUTS).map(([k, v]) => [k, v instanceof Uint8Array ? hex(v) : v]),
    ),
    outputs,
  };
}
