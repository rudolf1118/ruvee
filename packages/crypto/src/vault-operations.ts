import {
  ascii,
  concat,
  lengthPrefixed,
  requireBytes,
  requireBytesWithin,
  requireU32,
  requireU64,
  u16be,
  u32be,
  u64be,
} from './bytes.js';
import { crockfordDecodeExact, crockfordEncode, crockfordNormalize } from './crockford.js';
import {
  KEY_ID_BYTES,
  openEnvelope,
  PURPOSES,
  sealEnvelope,
  type NonceSource,
} from './envelope.js';
import { RuveeCryptoError } from './errors.js';
import { asUuidV4, UUID_BYTES, uuidFromBytes } from './ids.js';
import { padPlaintext, PADDED_MAX_BYTES, unpadPlaintext } from './padding.js';
import {
  KDF_CONTEXTS,
  KDF_SUBKEY_BYTES,
  KDF_SUBKEY_ID,
  KEY_BYTES,
  MAC_BYTES,
  type Primitives,
} from './primitives.js';
import {
  decodeManifest,
  encodeItemRecord,
  encodeManifest,
  HASH_DOMAINS,
  itemsDigestInput,
  parseItemRecord,
  type DigestEntry,
  type Manifest,
} from './vault-format.js';

export const RECOVERY_KEY_BYTES = 16;
const RECOVERY_KEY_CHECK_BYTES = 2;
const RECOVERY_KEY_PREFIX = 'RK1';
/** 18 bytes in Crockford base32. */
const RECOVERY_KEY_SYMBOLS = 29;
const RECOVERY_WRAP_DOMAIN = ascii('ruvee/v1/recovery-wrap');
const RECOVERY_AUTH_DOMAIN = ascii('ruvee/v1/recovery-auth');

/** Item body schema versions this client can open; part of the `ITEM_BODY` AAD (§4.3). */
export const ITEM_SCHEMA_VERSIONS: ReadonlySet<number> = new Set([1]);
/** Largest unpadded item body: one byte is always taken by the padding. */
export const ITEM_BODY_MAX_BYTES = PADDED_MAX_BYTES - 1;

const LOCAL_RECORD_NAME = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export interface RecoveryKeyMaterial {
  /** `RK`, 16 bytes. Shown once in the Recovery Kit and never stored. */
  readonly recoveryKey: Uint8Array;
  /** `recovery_key_id`, 16 bytes. */
  readonly recoveryKeyId: Uint8Array;
}

export interface RecoveryKeys {
  /** `RWK = MAC(RK, "ruvee/v1/recovery-wrap")`. */
  readonly recoveryWrapKey: Uint8Array;
  /** `RAK = MAC(RK, "ruvee/v1/recovery-auth")`, sent to the server for recovery only. */
  readonly recoveryAuthKey: Uint8Array;
}

/** The `AK_WRAP_RECOVERY` context (§4.3). */
export interface RecoveryWrapContext {
  readonly recoveryWrapKey: Uint8Array;
  readonly recoveryKeyId: Uint8Array;
  readonly accountId: Uint8Array;
  readonly accountKeyId: Uint8Array;
  readonly accountKeyEpoch: number;
}

export interface SealItemRecordInput {
  /** `VK`, 32 bytes, and `vk_id`. */
  readonly vaultKey: Uint8Array;
  readonly vaultKeyId: Uint8Array;
  readonly vaultId: Uint8Array;
  readonly itemId: Uint8Array;
  readonly revision: number;
  readonly schemaVersion: number;
  /** Unpadded UTF-8 JSON of the item body; padded here. */
  readonly body: Uint8Array;
  /**
   * The item's current record. Its `ITEM_KEY` envelope is reused, so `IK` stays the same across
   * revisions (§5.2) and never leaves the package. Omit for a new item, which gets a fresh `IK`.
   */
  readonly previousRecord?: Uint8Array;
}

export interface OpenItemRecordInput {
  readonly vaultKey: Uint8Array;
  readonly vaultKeyId: Uint8Array;
  readonly vaultId: Uint8Array;
  readonly itemId: Uint8Array;
  /** The revision the record is claimed to be; the AAD makes any other value fail. */
  readonly revision: number;
  readonly schemaVersion: number;
  readonly record: Uint8Array;
}

export interface SealManifestInput {
  readonly vaultKey: Uint8Array;
  readonly vaultKeyId: Uint8Array;
  readonly manifest: Manifest;
}

export interface OpenManifestInput {
  readonly vaultKey: Uint8Array;
  readonly vaultKeyId: Uint8Array;
  /** Where the caller expects this manifest: its vault and `seq`. */
  readonly vaultId: Uint8Array;
  readonly seq: number;
  readonly envelope: Uint8Array;
}

export interface LocalRecordContext {
  /** `AK` and `ak_id`; `K_local` is derived inside the call. */
  readonly accountKey: Uint8Array;
  readonly accountKeyId: Uint8Array;
  readonly deviceId: Uint8Array;
  /** Lowercase ASCII name such as `checkpoint` or `pending-queue`; part of the AAD. */
  readonly name: string;
}

export interface VaultOperations {
  /** A random version 4 UUID in canonical text form. */
  generateUuid(): string;
  generateRecoveryKey(): RecoveryKeyMaterial;
  /** `RK1-` and 29 Crockford symbols in groups of five (§5.4). */
  formatRecoveryKey(recoveryKey: Uint8Array): string;
  /** Lenient input per §5.4; a bad checksum is refused before any network request. */
  parseRecoveryKey(text: string): Uint8Array;
  deriveRecoveryKeys(recoveryKey: Uint8Array): RecoveryKeys;
  /** `SHA-256(RAK)`, the value the server stores and compares. */
  recoveryVerifier(recoveryAuthKey: Uint8Array): Uint8Array;
  wrapAccountKeyForRecovery(
    input: RecoveryWrapContext & { readonly accountKey: Uint8Array },
  ): Uint8Array;
  unwrapAccountKeyForRecovery(
    input: RecoveryWrapContext & { readonly envelope: Uint8Array },
  ): Uint8Array;
  sealItemRecord(input: SealItemRecordInput): Uint8Array;
  /** Returns the unpadded body bytes; the caller validates the JSON schema. */
  openItemRecord(input: OpenItemRecordInput): Uint8Array;
  /** `record_hash = H("ruvee/v1/record-hash" ‖ record)`. */
  recordHash(record: Uint8Array): Uint8Array;
  /** `items_digest` over the vault state (§5.3); order of `entries` does not matter. */
  itemsDigest(entries: readonly DigestEntry[]): Uint8Array;
  sealManifest(input: SealManifestInput): Uint8Array;
  /** Decrypts and checks that the plaintext's vault and `seq` are the expected ones. */
  openManifest(input: OpenManifestInput): Manifest;
  /** `manifest_hash = H("ruvee/v1/manifest-hash" ‖ manifest_envelope)`. */
  manifestHash(envelope: Uint8Array): Uint8Array;
  sealLocalRecord(input: LocalRecordContext & { readonly plaintext: Uint8Array }): Uint8Array;
  openLocalRecord(input: LocalRecordContext & { readonly envelope: Uint8Array }): Uint8Array;
}

function input(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null)
    throw new RuveeCryptoError('invalid_argument', { field: 'input' });
  return value as Record<string, unknown>;
}

function schemaVersion(value: unknown): number {
  if (typeof value !== 'number' || !ITEM_SCHEMA_VERSIONS.has(value))
    throw new RuveeCryptoError('invalid_argument', { field: 'schemaVersion' });
  return value;
}

export function buildVaultOperations(p: Primitives, nextNonce: NonceSource): VaultOperations {
  const subkey = (context: string, key: Uint8Array) =>
    p.kdf(KDF_SUBKEY_BYTES, KDF_SUBKEY_ID, context, key);
  const domainHash = (domain: Uint8Array, bytes: Uint8Array) => p.hash(concat(domain, bytes));

  const recoveryCheck = (recoveryKey: Uint8Array) =>
    domainHash(HASH_DOMAINS.recoveryKeyCheck, recoveryKey).slice(0, RECOVERY_KEY_CHECK_BYTES);

  const recoveryWrapContext = (i: Record<string, unknown>) => ({
    key: requireBytes(i.recoveryWrapKey, 'recoveryWrapKey', KEY_BYTES),
    keyId: requireBytes(i.recoveryKeyId, 'recoveryKeyId', KEY_ID_BYTES),
    context: concat(
      requireBytes(i.accountId, 'accountId', UUID_BYTES),
      requireBytes(i.accountKeyId, 'accountKeyId', KEY_ID_BYTES),
      u32be(requireU32(i.accountKeyEpoch, 'accountKeyEpoch')),
    ),
  });

  const itemContext = (i: Record<string, unknown>) => ({
    vaultKey: requireBytes(i.vaultKey, 'vaultKey', KEY_BYTES),
    vaultKeyId: requireBytes(i.vaultKeyId, 'vaultKeyId', KEY_ID_BYTES),
    vaultId: requireBytes(i.vaultId, 'vaultId', UUID_BYTES),
    itemId: requireBytes(i.itemId, 'itemId', UUID_BYTES),
    revision: requireU64(i.revision, 'revision', 1),
    schemaVersion: schemaVersion(i.schemaVersion),
  });
  const itemKeyContext = (vaultId: Uint8Array, itemId: Uint8Array, itemKeyId: Uint8Array) =>
    concat(vaultId, itemId, itemKeyId);
  const itemBodyContext = (c: ReturnType<typeof itemContext>) =>
    concat(c.vaultId, c.itemId, u64be(c.revision), u16be(c.schemaVersion));

  const openItemKey = (c: ReturnType<typeof itemContext>, record: unknown) => {
    const parsed = parseItemRecord(record);
    if (!parsed.ok) throw new RuveeCryptoError('malformed_envelope');
    const { itemKeyEnvelope, itemBodyEnvelope, itemKeyId } = parsed.parts;
    const itemKey = openEnvelope(p, {
      purpose: PURPOSES.ITEM_KEY,
      key: c.vaultKey,
      expectedKeyId: c.vaultKeyId,
      context: itemKeyContext(c.vaultId, c.itemId, itemKeyId),
      envelope: itemKeyEnvelope,
    });
    return { itemKey, itemKeyId, itemKeyEnvelope, itemBodyEnvelope };
  };

  const localContext = (i: Record<string, unknown>) => {
    if (typeof i.name !== 'string' || !LOCAL_RECORD_NAME.test(i.name))
      throw new RuveeCryptoError('invalid_argument', { field: 'name' });
    return {
      accountKey: requireBytes(i.accountKey, 'accountKey', KEY_BYTES),
      keyId: requireBytes(i.accountKeyId, 'accountKeyId', KEY_ID_BYTES),
      context: concat(
        requireBytes(i.deviceId, 'deviceId', UUID_BYTES),
        lengthPrefixed(ascii(i.name)),
      ),
    };
  };

  return Object.freeze({
    generateUuid: () => uuidFromBytes(asUuidV4(p.randomBytes(UUID_BYTES))),

    generateRecoveryKey: () => ({
      recoveryKey: p.randomBytes(RECOVERY_KEY_BYTES),
      recoveryKeyId: p.randomBytes(KEY_ID_BYTES),
    }),

    formatRecoveryKey(recoveryKey: Uint8Array): string {
      const rk = requireBytes(recoveryKey, 'recoveryKey', RECOVERY_KEY_BYTES);
      const payload = concat(rk, recoveryCheck(rk));
      const symbols = crockfordEncode(payload);
      payload.fill(0);
      const groups = symbols.match(/.{1,5}/g) ?? [];
      return [RECOVERY_KEY_PREFIX, ...groups].join('-');
    },

    parseRecoveryKey(text: string): Uint8Array {
      if (typeof text !== 'string' || text.length > 128)
        throw new RuveeCryptoError('invalid_recovery_key', { reason: 'malformed' });
      const normalized = crockfordNormalize(text);
      if (!normalized.startsWith(RECOVERY_KEY_PREFIX))
        throw new RuveeCryptoError('invalid_recovery_key', { reason: 'malformed' });
      const payload = crockfordDecodeExact(
        normalized.slice(RECOVERY_KEY_PREFIX.length),
        RECOVERY_KEY_BYTES + RECOVERY_KEY_CHECK_BYTES,
      );
      if (normalized.length !== RECOVERY_KEY_PREFIX.length + RECOVERY_KEY_SYMBOLS || !payload)
        throw new RuveeCryptoError('invalid_recovery_key', { reason: 'malformed' });
      const rk = payload.slice(0, RECOVERY_KEY_BYTES);
      const check = recoveryCheck(rk);
      const matches =
        check[0] === payload[RECOVERY_KEY_BYTES] && check[1] === payload[RECOVERY_KEY_BYTES + 1];
      payload.fill(0);
      if (!matches) {
        rk.fill(0);
        throw new RuveeCryptoError('invalid_recovery_key', { reason: 'checksum' });
      }
      return rk;
    },

    deriveRecoveryKeys(recoveryKey: Uint8Array): RecoveryKeys {
      const rk = requireBytes(recoveryKey, 'recoveryKey', RECOVERY_KEY_BYTES);
      return {
        recoveryWrapKey: p.mac(MAC_BYTES, RECOVERY_WRAP_DOMAIN, rk),
        recoveryAuthKey: p.mac(MAC_BYTES, RECOVERY_AUTH_DOMAIN, rk),
      };
    },

    recoveryVerifier: (recoveryAuthKey: Uint8Array) =>
      p.sha256(requireBytes(recoveryAuthKey, 'recoveryAuthKey', KEY_BYTES)),

    wrapAccountKeyForRecovery(value) {
      const i = input(value);
      const { key, keyId, context } = recoveryWrapContext(i);
      return sealEnvelope(p, nextNonce, {
        purpose: PURPOSES.AK_WRAP_RECOVERY,
        key,
        keyId,
        context,
        plaintext: requireBytes(i.accountKey, 'accountKey', KEY_BYTES),
      });
    },

    unwrapAccountKeyForRecovery(value) {
      const i = input(value);
      const { key, keyId, context } = recoveryWrapContext(i);
      return openEnvelope(p, {
        purpose: PURPOSES.AK_WRAP_RECOVERY,
        key,
        expectedKeyId: keyId,
        context,
        envelope: i.envelope,
      });
    },

    sealItemRecord(value: SealItemRecordInput): Uint8Array {
      const i = input(value);
      const c = itemContext(i);
      const body = requireBytesWithin(i.body, 'body', 0, ITEM_BODY_MAX_BYTES);
      let itemKey: Uint8Array | undefined;
      let padded: Uint8Array | undefined;
      try {
        let itemKeyId: Uint8Array;
        let itemKeyEnvelope: Uint8Array;
        if (i.previousRecord === undefined) {
          itemKey = p.randomBytes(KEY_BYTES);
          itemKeyId = p.randomBytes(KEY_ID_BYTES);
          itemKeyEnvelope = sealEnvelope(p, nextNonce, {
            purpose: PURPOSES.ITEM_KEY,
            key: c.vaultKey,
            keyId: c.vaultKeyId,
            context: itemKeyContext(c.vaultId, c.itemId, itemKeyId),
            plaintext: itemKey,
          });
        } else {
          const previous = openItemKey(c, i.previousRecord);
          itemKey = previous.itemKey;
          itemKeyId = previous.itemKeyId;
          itemKeyEnvelope = previous.itemKeyEnvelope.slice();
        }
        padded = padPlaintext(body);
        const bodyEnvelope = sealEnvelope(p, nextNonce, {
          purpose: PURPOSES.ITEM_BODY,
          key: itemKey,
          keyId: itemKeyId,
          context: itemBodyContext(c),
          plaintext: padded,
        });
        return encodeItemRecord(itemKeyEnvelope, bodyEnvelope);
      } finally {
        itemKey?.fill(0);
        padded?.fill(0);
      }
    },

    openItemRecord(value: OpenItemRecordInput): Uint8Array {
      const i = input(value);
      const c = itemContext(i);
      const { itemKey, itemKeyId, itemBodyEnvelope } = openItemKey(c, i.record);
      let padded: Uint8Array | undefined;
      try {
        padded = openEnvelope(p, {
          purpose: PURPOSES.ITEM_BODY,
          key: itemKey,
          expectedKeyId: itemKeyId,
          context: itemBodyContext(c),
          envelope: itemBodyEnvelope,
        });
        return unpadPlaintext(padded);
      } finally {
        itemKey.fill(0);
        padded?.fill(0);
      }
    },

    recordHash: (record: Uint8Array) => {
      const parsed = parseItemRecord(record);
      if (!parsed.ok) throw new RuveeCryptoError('invalid_argument', { field: 'record' });
      return domainHash(HASH_DOMAINS.record, record);
    },

    itemsDigest: (entries: readonly DigestEntry[]) =>
      domainHash(HASH_DOMAINS.itemsDigest, itemsDigestInput(entries)),

    sealManifest(value: SealManifestInput): Uint8Array {
      const i = input(value);
      const vaultKey = requireBytes(i.vaultKey, 'vaultKey', KEY_BYTES);
      const vaultKeyId = requireBytes(i.vaultKeyId, 'vaultKeyId', KEY_ID_BYTES);
      const plaintext = encodeManifest(i.manifest);
      const m = i.manifest as Manifest;
      let key: Uint8Array | undefined;
      try {
        key = subkey(KDF_CONTEXTS.manifest, vaultKey);
        return sealEnvelope(p, nextNonce, {
          purpose: PURPOSES.MANIFEST,
          key,
          keyId: vaultKeyId,
          context: concat(m.vaultId, u64be(m.seq)),
          plaintext,
        });
      } finally {
        key?.fill(0);
      }
    },

    openManifest(value: OpenManifestInput): Manifest {
      const i = input(value);
      const vaultKey = requireBytes(i.vaultKey, 'vaultKey', KEY_BYTES);
      const vaultKeyId = requireBytes(i.vaultKeyId, 'vaultKeyId', KEY_ID_BYTES);
      const vaultId = requireBytes(i.vaultId, 'vaultId', UUID_BYTES);
      const seq = requireU64(i.seq, 'seq', 1);
      let key: Uint8Array | undefined;
      try {
        key = subkey(KDF_CONTEXTS.manifest, vaultKey);
        const plaintext = openEnvelope(p, {
          purpose: PURPOSES.MANIFEST,
          key,
          expectedKeyId: vaultKeyId,
          context: concat(vaultId, u64be(seq)),
          envelope: i.envelope,
        });
        const manifest = decodeManifest(plaintext);
        if (manifest.seq !== seq || !manifest.vaultId.every((b, n) => b === vaultId[n]))
          throw new RuveeCryptoError('malformed_plaintext');
        return manifest;
      } finally {
        key?.fill(0);
      }
    },

    manifestHash: (envelope: Uint8Array) =>
      domainHash(HASH_DOMAINS.manifest, requireBytesWithin(envelope, 'envelope', 198, 198)),

    sealLocalRecord(value) {
      const i = input(value);
      const c = localContext(i);
      const plaintext = requireBytesWithin(
        i.plaintext,
        'plaintext',
        0,
        PURPOSES.LOCAL_RECORD.plaintextMaxBytes,
      );
      let key: Uint8Array | undefined;
      try {
        key = subkey(KDF_CONTEXTS.local, c.accountKey);
        return sealEnvelope(p, nextNonce, {
          purpose: PURPOSES.LOCAL_RECORD,
          key,
          keyId: c.keyId,
          context: c.context,
          plaintext,
        });
      } finally {
        key?.fill(0);
      }
    },

    openLocalRecord(value) {
      const i = input(value);
      const c = localContext(i);
      let key: Uint8Array | undefined;
      try {
        key = subkey(KDF_CONTEXTS.local, c.accountKey);
        return openEnvelope(p, {
          purpose: PURPOSES.LOCAL_RECORD,
          key,
          expectedKeyId: c.keyId,
          context: c.context,
          envelope: i.envelope,
        });
      } finally {
        key?.fill(0);
      }
    },
  } satisfies VaultOperations);
}
