// Portable checks for the recovery, item, manifest and local-record formats. They run in Node and
// in browser pages and workers through PORTABLE_CHECKS.

import { RuveeCryptoError, type CryptoErrorCode } from '../../src/errors.js';
import {
  initRuveeCrypto,
  manifestStructureProblem,
  parseItemRecord,
  uuidFromBytes,
  uuidToBytes,
  type Manifest,
  type RuveeCrypto,
} from '../../src/index.js';
import { cat, hex, pattern, same, seededRandom } from '../support/bytes.js';
import type { PortableCheck } from './checks.js';

class CheckError extends Error {}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new CheckError(message);
}

function expectCode(fn: () => unknown, code: CryptoErrorCode, label: string): void {
  let got: string;
  try {
    fn();
    got = 'returned';
  } catch (e) {
    got = e instanceof RuveeCryptoError ? e.code : 'foreign-error';
  }
  assert(got === code, `${label}: expected ${code}, got ${got}`);
}

function flip(bytes: Uint8Array, index: number, mask = 0x01): Uint8Array {
  const c = bytes.slice();
  c[index] = (c[index] ?? 0) ^ mask;
  return c;
}

const te = new TextEncoder();
const td = new TextDecoder();

async function vaultFixtures() {
  const crypto: RuveeCrypto = await initRuveeCrypto();
  return {
    crypto,
    vaultKey: crypto.generateKey(),
    vaultKeyId: crypto.generateKeyId(),
    vaultId: uuidToBytes(crypto.generateUuid()),
    itemId: uuidToBytes(crypto.generateUuid()),
  };
}

export const VAULT_CHECKS: readonly PortableCheck[] = [
  {
    id: 'recovery-verifier-is-sha256',
    category: 'cross-implementation',
    async run() {
      const crypto = await initRuveeCrypto();
      // SHA-256 of 32 zero bytes, computed with Node's crypto.createHash; the provisional vectors
      // also compare the verifier with noble's sha256.
      assert(
        hex(crypto.recoveryVerifier(new Uint8Array(32))) ===
          '66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925',
        'SHA-256 of 32 zero bytes',
      );
      expectCode(
        () => crypto.recoveryVerifier(te.encode('abc')),
        'invalid_argument',
        'verifier input must be 32 bytes',
      );
    },
  },
  {
    id: 'uuid-generation-and-encoding',
    category: 'protocol',
    async run() {
      const crypto = await initRuveeCrypto();
      const seen = new Set<string>();
      for (let i = 0; i < 200; i++) {
        const id = crypto.generateUuid();
        assert(
          /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id),
          id,
        );
        assert(uuidFromBytes(uuidToBytes(id)) === id, 'round trip');
        seen.add(id);
      }
      assert(seen.size === 200, 'distinct');
      for (const bad of ['', 'not-a-uuid', '3F1C9A52-7D4E-4B8A-9C21-5E6F7A8B9C0D', 1, null])
        expectCode(() => uuidToBytes(bad), 'invalid_argument', `uuid ${String(bad)}`);
    },
  },
  {
    id: 'recovery-key-text-format',
    category: 'protocol',
    async run() {
      const crypto = await initRuveeCrypto();
      const { recoveryKey, recoveryKeyId } = crypto.generateRecoveryKey();
      assert(recoveryKey.length === 16 && recoveryKeyId.length === 16, 'sizes');
      const text = crypto.formatRecoveryKey(recoveryKey);
      assert(/^RK1(-[0-9A-HJKMNP-TV-Z]{5}){5}-[0-9A-HJKMNP-TV-Z]{4}$/.test(text), text);
      assert(same(crypto.parseRecoveryKey(text), recoveryKey), 'round trip');
      // §5.4 leniency: case, separators and the O/I/L substitutions.
      const lenient = text.toLowerCase().replace(/-/g, ' ').replace(/0/g, 'o').replace(/1/g, 'l');
      assert(same(crypto.parseRecoveryKey(lenient), recoveryKey), 'lenient input');
      const body = text.slice(4).replace(/-/g, '');
      assert(same(crypto.parseRecoveryKey(`RK1${body}`), recoveryKey), 'no separators');
      // Every single-symbol substitution is caught by the checksum or the canonical-bit rule.
      const symbols = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
      let caught = 0;
      for (let i = 0; i < body.length; i++) {
        const replacement = symbols[(symbols.indexOf(body[i] ?? '0') + 1) % 32] ?? '0';
        const typo = `RK1${body.slice(0, i)}${replacement}${body.slice(i + 1)}`;
        try {
          crypto.parseRecoveryKey(typo);
        } catch (e) {
          if (e instanceof RuveeCryptoError && e.code === 'invalid_recovery_key') caught++;
        }
      }
      assert(caught === body.length, `typos caught ${caught}/${body.length}`);
      for (const bad of [
        '',
        'RK2-' + body,
        body,
        `RK1${body}0`,
        `RK1${body.slice(1)}`,
        'RK1-UUUUU',
      ])
        expectCode(() => crypto.parseRecoveryKey(bad), 'invalid_recovery_key', `text ${bad}`);
      expectCode(
        () => crypto.parseRecoveryKey(1 as unknown as string),
        'invalid_recovery_key',
        'non-string',
      );
      expectCode(() => crypto.formatRecoveryKey(pattern(1, 32)), 'invalid_argument', '32-byte RK');
    },
  },
  {
    id: 'recovery-wrap-round-trip-and-binding',
    category: 'negative',
    async run() {
      const crypto = await initRuveeCrypto();
      const { recoveryKey, recoveryKeyId } = crypto.generateRecoveryKey();
      const keys = crypto.deriveRecoveryKeys(recoveryKey);
      assert(!same(keys.recoveryWrapKey, keys.recoveryAuthKey), 'RWK and RAK are separated');
      const other = crypto.deriveRecoveryKeys(crypto.generateRecoveryKey().recoveryKey);
      assert(!same(keys.recoveryWrapKey, other.recoveryWrapKey), 'different RK, different RWK');
      const verifier = crypto.recoveryVerifier(keys.recoveryAuthKey);
      assert(verifier.length === 32 && !same(verifier, keys.recoveryAuthKey), 'verifier');
      const accountKey = crypto.generateKey();
      const context = {
        recoveryWrapKey: keys.recoveryWrapKey,
        recoveryKeyId,
        accountId: pattern(1, 16),
        accountKeyId: pattern(2, 16),
        accountKeyEpoch: 1,
      };
      const envelope = crypto.wrapAccountKeyForRecovery({ ...context, accountKey });
      assert(envelope.length === 93 && envelope[4] === 0x02, 'AK_WRAP_RECOVERY, 93 bytes');
      assert(
        same(crypto.unwrapAccountKeyForRecovery({ ...context, envelope }), accountKey),
        'round trip',
      );
      const open = (over: Record<string, unknown>) =>
        crypto.unwrapAccountKeyForRecovery({ ...context, envelope, ...over });
      expectCode(
        () => open({ recoveryWrapKey: other.recoveryWrapKey }),
        'integrity_failure',
        'other RK',
      );
      expectCode(
        () => open({ recoveryWrapKey: keys.recoveryAuthKey }),
        'integrity_failure',
        'RAK as key',
      );
      expectCode(() => open({ recoveryKeyId: pattern(9, 16) }), 'wrong_key', 'other key id');
      expectCode(() => open({ accountId: pattern(9, 16) }), 'integrity_failure', 'other account');
      expectCode(() => open({ accountKeyId: pattern(9, 16) }), 'integrity_failure', 'other ak_id');
      expectCode(() => open({ accountKeyEpoch: 2 }), 'integrity_failure', 'other epoch');
      expectCode(() => crypto.deriveRecoveryKeys(pattern(1, 32)), 'invalid_argument', 'RK length');
    },
  },
  {
    id: 'item-record-round-trip-and-binding',
    category: 'negative',
    async run() {
      const { crypto, vaultKey, vaultKeyId, vaultId, itemId } = await vaultFixtures();
      const body = te.encode('{"v":1,"type":"note","title":"synthetic"}');
      const base = { vaultKey, vaultKeyId, vaultId, itemId, schemaVersion: 1 };
      const r1 = crypto.sealItemRecord({ ...base, revision: 1, body });
      const parsed = parseItemRecord(r1);
      assert(parsed.ok, 'record parses structurally');
      assert(r1.length === 4 + 4 + 93 + 4 + 61 + 256, `record length ${r1.length}`);
      assert(
        td.decode(crypto.openItemRecord({ ...base, revision: 1, record: r1 })) === td.decode(body),
        'round trip',
      );
      // A new revision keeps IK (the same ITEM_KEY envelope) and uses fresh nonces.
      const r2 = crypto.sealItemRecord({ ...base, revision: 2, body, previousRecord: r1 });
      const p2 = parseItemRecord(r2);
      assert(p2.ok && same(p2.parts.itemKeyEnvelope, parsed.parts.itemKeyEnvelope), 'IK reused');
      assert(!same(p2.parts.itemBodyEnvelope, parsed.parts.itemBodyEnvelope), 'fresh body nonce');
      const open = (record: Uint8Array, over: Record<string, unknown> = {}) =>
        crypto.openItemRecord({ ...base, revision: 2, record, ...over });
      assert(same(open(r2), body), 'revision 2 opens');
      // The AAD binds revision, item and vault (sync-protocol §5, check 6).
      expectCode(() => open(r1), 'integrity_failure', 'revision 1 presented as revision 2');
      expectCode(() => open(r2, { revision: 3 }), 'integrity_failure', 'claimed revision 3');
      expectCode(() => open(r2, { itemId: pattern(5, 16) }), 'integrity_failure', 'moved item');
      expectCode(() => open(r2, { vaultId: pattern(5, 16) }), 'integrity_failure', 'moved vault');
      expectCode(
        () => open(r2, { vaultKey: crypto.generateKey() }),
        'integrity_failure',
        'other VK',
      );
      expectCode(() => open(r2, { vaultKeyId: pattern(5, 16) }), 'wrong_key', 'other vk_id');
      expectCode(() => open(r2, { schemaVersion: 2 }), 'invalid_argument', 'unknown schema');
      for (const i of [4 + 4 + 30, r2.length - 1, r2.length - 100])
        expectCode(() => open(flip(r2, i)), 'integrity_failure', `tampered byte ${i}`);
      // A previous record for another item cannot donate its IK.
      expectCode(
        () =>
          crypto.sealItemRecord({
            ...base,
            itemId: pattern(6, 16),
            revision: 2,
            body,
            previousRecord: r1,
          }),
        'integrity_failure',
        'foreign previous record',
      );
      expectCode(
        () => crypto.sealItemRecord({ ...base, revision: 0, body }),
        'invalid_argument',
        'revision 0',
      );
      expectCode(
        () => crypto.sealItemRecord({ ...base, revision: 1, body: new Uint8Array(65_536) }),
        'invalid_argument',
        'body above maximum',
      );
      const largest = crypto.sealItemRecord({ ...base, revision: 1, body: new Uint8Array(65_535) });
      assert(largest.length === 65_702, `largest record ${largest.length}`);
      // Structural parser: framing and headers.
      for (const [label, bytes] of [
        ['empty', new Uint8Array(0)],
        ['magic', flip(r1, 0)],
        ['version', flip(r1, 3)],
        ['framing', r1.slice(0, -1)],
        ['trailing', cat(r1, [0])],
        ['key purpose', flip(r1, 8 + 4)],
        ['body purpose', flip(r1, 8 + 93 + 4 + 4)],
      ] as const)
        assert(!parseItemRecord(bytes).ok, `structure ${label}`);
      expectCode(() => open(flip(r1, 0)), 'malformed_envelope', 'unparseable record');
      expectCode(() => crypto.recordHash(flip(r1, 0)), 'invalid_argument', 'hash of non-record');
    },
  },
  {
    id: 'items-digest-and-manifest',
    category: 'protocol',
    async run() {
      const { crypto, vaultKey, vaultKeyId, vaultId } = await vaultFixtures();
      const ids = [pattern(1, 16), pattern(2, 16), pattern(3, 16)];
      const entries = ids.map((itemId, i) => ({
        itemId,
        revision: i + 1,
        recordHash: i === 1 ? null : pattern(10 + i, 32),
      }));
      const [e0, e1, e2] = entries as [
        (typeof entries)[0],
        (typeof entries)[0],
        (typeof entries)[0],
      ];
      const digest = crypto.itemsDigest(entries);
      const next = seededRandom(7);
      for (let n = 0; n < 10; n++) {
        const shuffled = [...entries].sort(() => next(3) - 1);
        assert(same(crypto.itemsDigest(shuffled), digest), 'order independent');
      }
      assert(!same(crypto.itemsDigest(entries.slice(0, 2)), digest), 'omission changes digest');
      assert(
        !same(crypto.itemsDigest([{ ...e0, revision: 9 }, e1, e2]), digest),
        'revision changes digest',
      );
      assert(
        !same(crypto.itemsDigest([e0, { ...e1, recordHash: new Uint8Array(32) }, e2]), digest),
        'tombstone differs from a zero hash',
      );
      expectCode(() => crypto.itemsDigest([e0, e0]), 'invalid_argument', 'duplicate item');
      assert(crypto.itemsDigest([]).length === 32, 'empty vault digest');

      const manifest: Manifest = {
        vaultId,
        seq: 1,
        prevManifestHash: new Uint8Array(32),
        itemsDigest: digest,
        liveCount: 2,
        tombstoneCount: 1,
        authorDeviceId: pattern(20, 16),
        createdAtMs: 1_760_000_000_000,
        commitId: pattern(21, 16),
      };
      const envelope = crypto.sealManifest({ vaultKey, vaultKeyId, manifest });
      assert(envelope.length === 198, 'manifest envelope 198 bytes');
      assert(manifestStructureProblem(envelope) === undefined, 'structure ok');
      const opened = crypto.openManifest({ vaultKey, vaultKeyId, vaultId, seq: 1, envelope });
      assert(
        hex(opened.itemsDigest) === hex(digest) &&
          opened.liveCount === 2 &&
          opened.tombstoneCount === 1 &&
          opened.createdAtMs === manifest.createdAtMs &&
          same(opened.commitId, manifest.commitId) &&
          same(opened.authorDeviceId, manifest.authorDeviceId),
        'fields round trip',
      );
      const open = (over: Record<string, unknown>) =>
        crypto.openManifest({ vaultKey, vaultKeyId, vaultId, seq: 1, envelope, ...over });
      expectCode(() => open({ seq: 2 }), 'integrity_failure', 'presented at another seq');
      expectCode(() => open({ vaultId: pattern(9, 16) }), 'integrity_failure', 'other vault');
      expectCode(() => open({ vaultKey: crypto.generateKey() }), 'integrity_failure', 'other VK');
      expectCode(() => open({ envelope: flip(envelope, 100) }), 'integrity_failure', 'tampered');
      assert(manifestStructureProblem(envelope.slice(0, 197)) === 'length', 'short manifest');
      assert(manifestStructureProblem(flip(envelope, 4, 0x03)) === 'purpose', 'purpose byte');
      const h = crypto.manifestHash(envelope);
      assert(h.length === 32 && !same(h, crypto.manifestHash(flip(envelope, 50))), 'manifest hash');
      expectCode(
        () => crypto.sealManifest({ vaultKey, vaultKeyId, manifest: { ...manifest, seq: 0 } }),
        'invalid_argument',
        'seq 0',
      );
      expectCode(
        () =>
          crypto.sealManifest({
            vaultKey,
            vaultKeyId,
            manifest: { ...manifest, liveCount: 2 ** 32 },
          }),
        'invalid_argument',
        'count above u32',
      );
    },
  },
  {
    id: 'local-record-round-trip-and-binding',
    category: 'negative',
    async run() {
      const crypto = await initRuveeCrypto();
      const context = {
        accountKey: crypto.generateKey(),
        accountKeyId: crypto.generateKeyId(),
        deviceId: pattern(3, 16),
        name: 'checkpoint',
      };
      const plaintext = te.encode('{"seq":1}');
      const envelope = crypto.sealLocalRecord({ ...context, plaintext });
      assert(envelope[4] === 0x07, 'LOCAL_RECORD purpose');
      assert(same(crypto.openLocalRecord({ ...context, envelope }), plaintext), 'round trip');
      const open = (over: Record<string, unknown>) =>
        crypto.openLocalRecord({ ...context, envelope, ...over });
      expectCode(() => open({ name: 'pending-queue' }), 'integrity_failure', 'other name');
      expectCode(() => open({ deviceId: pattern(4, 16) }), 'integrity_failure', 'other device');
      expectCode(() => open({ accountKey: crypto.generateKey() }), 'integrity_failure', 'other AK');
      for (const name of ['', 'Upper', 'with space', 'x'.repeat(65), 'café', 1])
        expectCode(() => open({ name }), 'invalid_argument', `name ${String(name)}`);
      const large = crypto.sealLocalRecord({ ...context, plaintext: new Uint8Array(1_048_576) });
      assert(large.length === 1_048_637, 'largest local record');
      expectCode(
        () => crypto.sealLocalRecord({ ...context, plaintext: new Uint8Array(1_048_577) }),
        'invalid_argument',
        'above maximum',
      );
    },
  },
];

export const PAIRING_CHECKS: readonly PortableCheck[] = [
  {
    id: 'pairing-code-format',
    category: 'protocol',
    async run() {
      const crypto = await initRuveeCrypto();
      const secret = crypto.generatePairingSecret();
      assert(secret.length === 16, 'S is 16 bytes');
      const code = crypto.formatPairingCode(secret);
      assert(/^PC1(-[0-9A-HJKMNP-TV-Z]{5}){5}-[0-9A-HJKMNP-TV-Z]{4}$/.test(code), code);
      assert(same(crypto.parsePairingCode(code.toLowerCase()), secret), 'round trip');
      const body = code.slice(4).replace(/-/g, '');
      const symbols = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
      for (let i = 0; i < body.length; i++) {
        const typo = `PC1${body.slice(0, i)}${symbols[(symbols.indexOf(body[i] ?? '0') + 7) % 32] ?? '0'}${body.slice(i + 1)}`;
        expectCode(() => crypto.parsePairingCode(typo), 'invalid_pairing_code', `typo at ${i}`);
      }
      expectCode(
        () => crypto.parsePairingCode(`RK1${body}`),
        'invalid_pairing_code',
        'Recovery Key prefix',
      );
      assert(crypto.pairingId(secret).length === 16, 'pairing id is 16 bytes');
      assert(!same(crypto.pairingId(secret), secret), 'pairing id is not S');
    },
  },
  {
    id: 'pairing-round-trip-and-binding',
    category: 'negative',
    async run() {
      const crypto = await initRuveeCrypto();
      const secret = crypto.generatePairingSecret();
      const accountId = pattern(1, 16);
      const deviceId = pattern(2, 16);
      const req = crypto.createPairingRequest({ secret, accountId, deviceId, platform: 'web' });
      assert(same(req.pairingId, crypto.pairingId(secret)), 'request names the pairing');
      const transcript = {
        secret,
        accountId,
        pairingId: req.pairingId,
        deviceId,
        ephemeralPublicKey: req.ephemeralPublicKey,
      };
      assert(
        crypto.verifyPairingRequest({ ...transcript, platform: 'web', mac: req.mac }),
        'A verifies B',
      );
      // A server that swaps the key, the device, the platform or the account is caught (§3.3).
      for (const [label, over] of [
        ['substituted ephemeral key', { ephemeralPublicKey: crypto.generateKey() }],
        ['other device', { deviceId: pattern(3, 16) }],
        ['other account', { accountId: pattern(4, 16) }],
        ['other pairing id', { pairingId: pattern(5, 16) }],
        ['wrong secret', { secret: crypto.generatePairingSecret() }],
      ] as const)
        assert(
          !crypto.verifyPairingRequest({ ...transcript, ...over, platform: 'web', mac: req.mac }),
          label,
        );
      assert(
        !crypto.verifyPairingRequest({ ...transcript, platform: 'ios', mac: req.mac }),
        'other platform',
      );

      const payload = {
        accountId: '01010101-0101-4101-8101-010101010101',
        deviceId: '02020202-0202-4202-8202-020202020202',
        secretKey: crypto.generateKey(),
        checkpoint: {
          vaultId: crypto.generateUuid(),
          seq: 7,
          manifestHash: pattern(9, 32),
          keysetVersion: 1,
        },
      };
      // Ids in the payload are compared with the transcript, so build matching byte ids.
      const ids = {
        accountId: uuidToBytes(payload.accountId),
        deviceId: uuidToBytes(payload.deviceId),
      };
      const req2 = crypto.createPairingRequest({ secret, ...ids, platform: 'web' });
      const t2 = {
        secret,
        ...ids,
        pairingId: req2.pairingId,
        ephemeralPublicKey: req2.ephemeralPublicKey,
      };
      const res = crypto.createPairingResponse({ ...t2, payload });
      const opened = crypto.openPairingResponse({
        ...t2,
        ephemeralPrivateKey: req2.ephemeralPrivateKey,
        ciphertext: res.ciphertext,
        mac: res.mac,
      });
      assert(
        same(opened.secretKey, payload.secretKey) && opened.checkpoint.seq === 7,
        'B opens the reply',
      );
      const open = (over: Record<string, unknown>) =>
        crypto.openPairingResponse({
          ...t2,
          ephemeralPrivateKey: req2.ephemeralPrivateKey,
          ciphertext: res.ciphertext,
          mac: res.mac,
          ...over,
        });
      expectCode(
        () => open({ ciphertext: flip(res.ciphertext, 60) }),
        'integrity_failure',
        'tampered box',
      );
      expectCode(() => open({ mac: flip(res.mac, 0) }), 'integrity_failure', 'tampered MAC');
      // A reply the server made itself, sealed to B's key, has no valid MAC.
      const forged = crypto.createPairingResponse({
        ...t2,
        secret: crypto.generatePairingSecret(),
        payload,
      });
      expectCode(
        () => open({ ciphertext: forged.ciphertext, mac: forged.mac }),
        'integrity_failure',
        'forged reply',
      );
      // The request MAC is never accepted as a response MAC (reflection).
      expectCode(() => open({ mac: req2.mac }), 'integrity_failure', 'reflected MAC');
      // A payload for another device is refused even with a valid MAC.
      const other = crypto.createPairingResponse({
        ...t2,
        payload: { ...payload, deviceId: crypto.generateUuid() },
      });
      expectCode(
        () => open({ ciphertext: other.ciphertext, mac: other.mac }),
        'integrity_failure',
        'other device',
      );
      expectCode(
        () => crypto.createPairingRequest({ secret, accountId, deviceId, platform: 'tv' as 'web' }),
        'invalid_argument',
        'unknown platform',
      );
    },
  },
];
