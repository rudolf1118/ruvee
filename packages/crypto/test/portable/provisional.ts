// Provisional Ruvee protocol vectors (cryptographic-design §8, category 2), computed twice: by the
// package on libsodium and by the independent noble reference. They must agree with each other
// and with the committed file. NOT a compatibility promise: the format has not been reviewed.

import { encodeKeyset } from '../../src/keyset.js';
import { passwordBytes } from '../../src/password.js';
import { guardPrimitives, KDF_CONTEXTS, type RawPrimitives } from '../../src/primitives.js';
import { resolveKdfProfile } from '../../src/profiles.js';
import { encodeManifest } from '../../src/vault-format.js';
import { createFixedNonceCrypto } from '../../src/testing/fixed-nonce.js';
import {
  refAccountUnlockKey,
  refEnvelope,
  refItemRecord,
  refItemsDigest,
  refKdf,
  refKeysetContext,
  refKeysetPlaintext,
  refLocalContext,
  refManifestContext,
  refManifestHash,
  refManifestPlaintext,
  refPairing,
  refPairingCode,
  refPasswordBytes,
  refPasswordKey,
  refRecordHash,
  refRecoveryKeys,
  refRecoveryKeyText,
  refRecoveryVerifier,
  refRecoveryWrapContext,
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
  recoveryKey: pattern(10, 16),
  recoveryKeyId: pattern(11, 16),
  recoveryWrapNonce: pattern(12, 24),
  itemId: '7c0e5a3b-2f41-4d6e-8a9b-0c1d2e3f4a5b',
  itemKey: pattern(14, 32),
  itemKeyId: pattern(15, 16),
  itemKeyNonce: pattern(16, 24),
  itemBodyNonce: pattern(17, 24),
  itemRevision: 1,
  itemBody: '{"v":1,"type":"note","title":"Synthetic note","note":{"text":"not a secret"}}',
  deviceId: '0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d',
  commitId: '5d6e7f80-9a1b-4c2d-8e3f-4a5b6c7d8e9f',
  manifestNonce: pattern(20, 24),
  createdAtMs: 1_760_000_000_000,
  localName: 'checkpoint',
  localPlaintext: '{"seq":1}',
  localNonce: pattern(21, 24),
  pairingSecret: pattern(22, 16),
  pairingEphemeralPublicKey: pattern(23, 32),
  pairingEphemeralPrivateKey: pattern(24, 32),
  /** B's device public key, inside `req_mac` since `pair-req-2` (device-proof.md §8). */
  pairingDevicePublicKey: pattern(26, 32),
} as const;

/** Stands in for a sealed box of the right length: the MAC covers whatever bytes the box has. */
const fakeBox = (plaintextLength: number) => pattern(25, plaintextLength + 48);

/** Two more digest entries for the three-item case: an earlier live item and a tombstone. */
const OTHER_ITEMS = [
  { itemId: pattern(30, 16), revision: 4, recordHash: pattern(31, 32) },
  { itemId: pattern(32, 16), revision: 2, recordHash: null },
] as const;

function uuidHex(text: string): Uint8Array {
  return fromHex(text.replace(/-/g, ''));
}

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
  recovery: { text: string; rwk: string; rak: string; verifier: string; wrapEnvelope: string };
  item: { record: string; recordHash: string };
  itemsDigest: { empty: string; one: string; three: string };
  manifest: { manifestKey: string; plaintext: string; envelope: string; hash: string };
  localRecord: { localKey: string; envelope: string };
  pairing: {
    code: string;
    pairingId: string;
    requestMac: string;
    payload: string;
    responseMac: string;
  };
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
  const te = new TextEncoder();
  const vaultId = uuidHex(INPUTS.vaultId);
  const itemId = uuidHex(INPUTS.itemId);
  // IK and ik_id come from the CSPRNG inside sealItemRecord; here they come from a fixed queue.
  const randomQueue = [INPUTS.itemKey, INPUTS.itemKeyId];
  const vaultCrypto = createFixedNonceCrypto(
    {
      ...raw,
      randombytesBuf: (length) => {
        const next = randomQueue.shift();
        if (next?.length !== length) throw new Error('unexpected random request');
        return next.slice();
      },
    },
    [
      INPUTS.recoveryWrapNonce,
      INPUTS.itemKeyNonce,
      INPUTS.itemBodyNonce,
      INPUTS.manifestNonce,
      INPUTS.localNonce,
    ],
  );
  const recoveryKeys = vaultCrypto.deriveRecoveryKeys(INPUTS.recoveryKey);
  const recoveryWrap = vaultCrypto.wrapAccountKeyForRecovery({
    recoveryWrapKey: recoveryKeys.recoveryWrapKey,
    recoveryKeyId: INPUTS.recoveryKeyId,
    accountId: INPUTS.accountId,
    accountKeyId: INPUTS.accountKeyId,
    accountKeyEpoch: INPUTS.accountKeyEpoch,
    accountKey: INPUTS.accountKey,
  });
  const record = vaultCrypto.sealItemRecord({
    vaultKey: INPUTS.vaultKey,
    vaultKeyId: INPUTS.vaultKeyId,
    vaultId,
    itemId,
    revision: INPUTS.itemRevision,
    schemaVersion: 1,
    body: te.encode(INPUTS.itemBody),
  });
  const recordHash = vaultCrypto.recordHash(record);
  const entry = { itemId, revision: INPUTS.itemRevision, recordHash };
  const itemsDigest = vaultCrypto.itemsDigest([entry, ...OTHER_ITEMS]);
  const manifest = {
    vaultId,
    seq: 1,
    prevManifestHash: new Uint8Array(32),
    itemsDigest,
    liveCount: 2,
    tombstoneCount: 1,
    authorDeviceId: uuidHex(INPUTS.deviceId),
    createdAtMs: INPUTS.createdAtMs,
    commitId: uuidHex(INPUTS.commitId),
  };
  const manifestEnvelope = vaultCrypto.sealManifest({
    vaultKey: INPUTS.vaultKey,
    vaultKeyId: INPUTS.vaultKeyId,
    manifest,
  });
  const localEnvelope = vaultCrypto.sealLocalRecord({
    accountKey: INPUTS.accountKey,
    accountKeyId: INPUTS.accountKeyId,
    deviceId: uuidHex(INPUTS.deviceId),
    name: INPUTS.localName,
    plaintext: te.encode(INPUTS.localPlaintext),
  });
  return {
    passwords,
    keysetKey: hex(p.kdf(32, 1, KDF_CONTEXTS.keyset, INPUTS.accountKey)),
    accountKeyWrap: { aukFrom: WRAP_AUK_FROM, envelope: hex(wrap) },
    keyset: { plaintext: hex(encodeKeyset(keyset)), envelope: hex(keysetEnvelope) },
    recovery: {
      text: vaultCrypto.formatRecoveryKey(INPUTS.recoveryKey),
      rwk: hex(recoveryKeys.recoveryWrapKey),
      rak: hex(recoveryKeys.recoveryAuthKey),
      verifier: hex(vaultCrypto.recoveryVerifier(recoveryKeys.recoveryAuthKey)),
      wrapEnvelope: hex(recoveryWrap),
    },
    item: { record: hex(record), recordHash: hex(recordHash) },
    itemsDigest: {
      empty: hex(vaultCrypto.itemsDigest([])),
      one: hex(vaultCrypto.itemsDigest([entry])),
      three: hex(itemsDigest),
    },
    manifest: {
      manifestKey: hex(p.kdf(32, 1, KDF_CONTEXTS.manifest, INPUTS.vaultKey)),
      plaintext: hex(encodeManifest(manifest)),
      envelope: hex(manifestEnvelope),
      hash: hex(vaultCrypto.manifestHash(manifestEnvelope)),
    },
    localRecord: {
      localKey: hex(p.kdf(32, 1, KDF_CONTEXTS.local, INPUTS.accountKey)),
      envelope: hex(localEnvelope),
    },
    pairing: packagePairing(raw),
  };
}

/** The ephemeral key pair and the sealed box come from fixed bytes, so the MACs are reproducible. */
function packagePairing(raw: RawPrimitives): ProvisionalOutputs['pairing'] {
  let sealed = new Uint8Array(0);
  const crypto = createFixedNonceCrypto(
    {
      ...raw,
      boxKeypair: () => ({
        publicKey: INPUTS.pairingEphemeralPublicKey.slice(),
        privateKey: INPUTS.pairingEphemeralPrivateKey.slice(),
      }),
      boxSeal: (message) => {
        sealed = message.slice();
        return fakeBox(message.length);
      },
    },
    [],
  );
  const deviceId = uuidHex(INPUTS.deviceId);
  const request = crypto.createPairingRequest({
    secret: INPUTS.pairingSecret,
    accountId: INPUTS.accountId,
    deviceId,
    platform: 'web',
    devicePublicKey: INPUTS.pairingDevicePublicKey,
  });
  const response = crypto.createPairingResponse({
    secret: INPUTS.pairingSecret,
    accountId: INPUTS.accountId,
    pairingId: request.pairingId,
    deviceId,
    ephemeralPublicKey: request.ephemeralPublicKey,
    payload: {
      accountId: INPUTS.vaultId,
      deviceId: INPUTS.deviceId,
      secretKey: INPUTS.secretKey,
      checkpoint: {
        vaultId: INPUTS.vaultId,
        seq: 0,
        manifestHash: new Uint8Array(32),
        keysetVersion: 1,
      },
    },
  });
  return {
    code: crypto.formatPairingCode(INPUTS.pairingSecret),
    pairingId: hex(request.pairingId),
    requestMac: hex(request.mac),
    payload: hex(sealed),
    responseMac: hex(response.mac),
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
    ...referenceVaultOutputs(),
  };
}

function referenceVaultOutputs(): Pick<
  ProvisionalOutputs,
  'recovery' | 'item' | 'itemsDigest' | 'manifest' | 'localRecord' | 'pairing'
> {
  const te = new TextEncoder();
  const vaultId = uuidHex(INPUTS.vaultId);
  const itemId = uuidHex(INPUTS.itemId);
  const { rwk, rak } = refRecoveryKeys(INPUTS.recoveryKey);
  const record = refItemRecord({
    vk: INPUTS.vaultKey,
    vkId: INPUTS.vaultKeyId,
    vaultId,
    itemId,
    ik: INPUTS.itemKey,
    ikId: INPUTS.itemKeyId,
    revision: INPUTS.itemRevision,
    schemaVersion: 1,
    body: te.encode(INPUTS.itemBody),
    keyNonce: INPUTS.itemKeyNonce,
    bodyNonce: INPUTS.itemBodyNonce,
  });
  const recordHash = refRecordHash(record);
  const entry = { itemId, revision: INPUTS.itemRevision, recordHash };
  const itemsDigest = refItemsDigest([entry, ...OTHER_ITEMS]);
  const manifestPlaintext = refManifestPlaintext({
    vaultId,
    seq: 1,
    prevManifestHash: new Uint8Array(32),
    itemsDigest,
    liveCount: 2,
    tombstoneCount: 1,
    authorDeviceId: uuidHex(INPUTS.deviceId),
    createdAtMs: INPUTS.createdAtMs,
    commitId: uuidHex(INPUTS.commitId),
  });
  const manifestKey = refKdf(INPUTS.vaultKey, 'rvmanif1');
  const manifestEnvelope = refEnvelope(
    0x06,
    manifestKey,
    INPUTS.vaultKeyId,
    INPUTS.manifestNonce,
    refManifestContext(vaultId, 1),
    manifestPlaintext,
  );
  const localKey = refKdf(INPUTS.accountKey, 'rvlocal1');
  return {
    recovery: {
      text: refRecoveryKeyText(INPUTS.recoveryKey),
      rwk: hex(rwk),
      rak: hex(rak),
      verifier: hex(refRecoveryVerifier(rak)),
      wrapEnvelope: hex(
        refEnvelope(
          0x02,
          rwk,
          INPUTS.recoveryKeyId,
          INPUTS.recoveryWrapNonce,
          refRecoveryWrapContext(INPUTS.accountId, INPUTS.accountKeyId, INPUTS.accountKeyEpoch),
          INPUTS.accountKey,
        ),
      ),
    },
    item: { record: hex(record), recordHash: hex(recordHash) },
    itemsDigest: {
      empty: hex(refItemsDigest([])),
      one: hex(refItemsDigest([entry])),
      three: hex(itemsDigest),
    },
    manifest: {
      manifestKey: hex(manifestKey),
      plaintext: hex(manifestPlaintext),
      envelope: hex(manifestEnvelope),
      hash: hex(refManifestHash(manifestEnvelope)),
    },
    localRecord: {
      localKey: hex(localKey),
      envelope: hex(
        refEnvelope(
          0x07,
          localKey,
          INPUTS.accountKeyId,
          INPUTS.localNonce,
          refLocalContext(uuidHex(INPUTS.deviceId), INPUTS.localName),
          te.encode(INPUTS.localPlaintext),
        ),
      ),
    },
    pairing: (() => {
      const ref = refPairing(INPUTS.pairingSecret, INPUTS.accountId);
      const deviceId = uuidHex(INPUTS.deviceId);
      const b64 = (bytes: Uint8Array) =>
        btoa(String.fromCharCode(...bytes))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=+$/, '');
      const payload = te.encode(
        `{"v":1,"accountId":"${INPUTS.vaultId}","deviceId":"${INPUTS.deviceId}","secretKey":"${b64(INPUTS.secretKey)}","checkpoint":{"vaultId":"${INPUTS.vaultId}","seq":0,"manifestHash":"${b64(new Uint8Array(32))}","keysetVersion":1}}`,
      );
      return {
        code: refPairingCode(INPUTS.pairingSecret),
        pairingId: hex(ref.pairingId),
        requestMac: hex(
          ref.requestMac(
            deviceId,
            1,
            INPUTS.pairingEphemeralPublicKey,
            INPUTS.pairingDevicePublicKey,
          ),
        ),
        payload: hex(payload),
        responseMac: hex(
          ref.responseMac(deviceId, INPUTS.pairingEphemeralPublicKey, fakeBox(payload.length)),
        ),
      };
    })(),
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
    specification:
      'docs/security/cryptographic-design.md §3.1-§4.4 and §5.1-§5.4; device-enrollment.md §3.1-§3.2',
    inputs: Object.fromEntries(
      Object.entries(INPUTS).map(([k, v]) => [k, v instanceof Uint8Array ? hex(v) : v]),
    ),
    outputs,
  };
}
