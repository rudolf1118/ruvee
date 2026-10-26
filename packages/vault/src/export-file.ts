import { base64urlBytes, manifestSchema, recordSchema, uuidSchema } from '@ruvee/contracts';
import { uuidFromBytes, uuidToBytes, type RuveeCrypto } from '@ruvee/crypto';
import { z } from 'zod';
import { fromB64, toB64 } from './bytes.js';
import { decodeItemBody, ITEM_SCHEMA_VERSION, type ItemBody } from './item-schema.js';
import { VaultError } from './vault-error.js';

/**
 * The portable encrypted export (backup-restore.md §4, D-13 option A, approved for development
 * 2026-10-26). A container of envelopes Ruvee already defines: the keyset, the newest verified
 * manifest and the item records, plus an `AK_WRAP_RECOVERY` made at export time from the Recovery
 * Key the user typed. No new cipher, KDF, MAC or envelope purpose. Every field outside an envelope
 * is checked against a value an envelope authenticates; any difference fails the whole file.
 */

export const EXPORT_FORMAT = 'ruvee-export';
export const EXPORT_VERSION = 1;
export const EXPORT_MAX_ITEMS = 100_000;
/** The whole file, in UTF-16 code units as JavaScript reads it (base64url and JSON are ASCII). */
export const EXPORT_MAX_CHARS = 512 * 1024 * 1024;

const counter = z.int().min(1).max(Number.MAX_SAFE_INTEGER);
const u32 = z.int().min(0).max(0xffff_ffff);

export const exportFileSchema = z.strictObject({
  format: z.literal(EXPORT_FORMAT),
  version: z.literal(EXPORT_VERSION),
  accountId: uuidSchema,
  vaultId: uuidSchema,
  akId: base64urlBytes({ length: 16 }),
  akEpoch: u32,
  recoveryKeyId: base64urlBytes({ length: 16 }),
  recoveryWrap: base64urlBytes({ length: 93 }),
  keyset: z.strictObject({ version: u32, envelope: base64urlBytes({ min: 61, max: 16_445 }) }),
  manifest: z.strictObject({ seq: counter, envelope: manifestSchema }),
  items: z
    .array(
      z.strictObject({ itemId: uuidSchema, revision: counter, record: recordSchema.nullable() }),
    )
    .max(EXPORT_MAX_ITEMS),
});
export type ExportFile = z.infer<typeof exportFileSchema>;

export interface ExportInput {
  readonly crypto: RuveeCrypto;
  readonly accountId: string;
  readonly vaultId: string;
  readonly accountKey: Uint8Array;
  readonly accountKeyId: Uint8Array;
  readonly accountKeyEpoch: number;
  /** As the user typed it; it must parse (checksum) or nothing is built. */
  readonly recoveryKeyText: string;
  readonly keyset: { readonly version: number; readonly envelope: Uint8Array };
  /** The newest manifest this device verified, matching `items` exactly. */
  readonly manifest: { readonly seq: number; readonly envelope: Uint8Array };
  readonly items: ReadonlyMap<
    string,
    { readonly revision: number; readonly record: Uint8Array | null }
  >;
}

/** Serializes an export. The caller has verified `manifest` against `items` (a synced state). */
export function buildExport(input: ExportInput): string {
  const { crypto } = input;
  let recoveryKey: Uint8Array;
  try {
    recoveryKey = crypto.parseRecoveryKey(input.recoveryKeyText);
  } catch {
    throw new VaultError('invalid_recovery_key');
  }
  const keys = crypto.deriveRecoveryKeys(recoveryKey);
  recoveryKey.fill(0);
  // An identifier for this wrap only: devices do not learn the server kit's id.
  const recoveryKeyId = crypto.generateKey().slice(0, 16);
  let recoveryWrap: Uint8Array;
  try {
    recoveryWrap = crypto.wrapAccountKeyForRecovery({
      recoveryWrapKey: keys.recoveryWrapKey,
      recoveryKeyId,
      accountId: uuidToBytes(input.accountId),
      accountKeyId: input.accountKeyId,
      accountKeyEpoch: input.accountKeyEpoch,
      accountKey: input.accountKey,
    });
  } finally {
    keys.recoveryWrapKey.fill(0);
    keys.recoveryAuthKey.fill(0);
  }
  const file: ExportFile = {
    format: EXPORT_FORMAT,
    version: EXPORT_VERSION,
    accountId: input.accountId,
    vaultId: input.vaultId,
    akId: toB64(input.accountKeyId),
    akEpoch: input.accountKeyEpoch,
    recoveryKeyId: toB64(recoveryKeyId),
    recoveryWrap: toB64(recoveryWrap),
    keyset: { version: input.keyset.version, envelope: toB64(input.keyset.envelope) },
    manifest: { seq: input.manifest.seq, envelope: toB64(input.manifest.envelope) },
    // Canonical lowercase UUID text sorts in the same order as the bytes.
    items: [...input.items]
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([itemId, item]) => ({
        itemId,
        revision: item.revision,
        record: item.record === null ? null : toB64(item.record),
      })),
  };
  return JSON.stringify(file);
}

export interface OpenedExport {
  readonly accountId: string;
  readonly vaultId: string;
  readonly seq: number;
  /** Authenticated by the manifest: when, and by which device, the vault last changed. */
  readonly asOfMs: number;
  readonly authorDeviceId: string;
  readonly items: ReadonlyMap<string, { readonly revision: number; readonly body: ItemBody }>;
  readonly tombstones: number;
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * backup-restore.md §4.3, steps 1 to 5. Nothing is returned unless every check passed: a bad file
 * is `invalid_export`, a key that does not open it `kit_mismatch`, and anything that opens but
 * does not agree with its manifest `integrity`. Keys are wiped before returning.
 */
export function openExport(
  crypto: RuveeCrypto,
  text: string,
  recoveryKeyText: string,
): OpenedExport {
  // Step 1: the schema, strictly.
  if (text.length > EXPORT_MAX_CHARS) throw new VaultError('invalid_export');
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new VaultError('invalid_export');
  }
  const parsed = exportFileSchema.safeParse(raw);
  if (!parsed.success) throw new VaultError('invalid_export');
  const file = parsed.data;
  const ids = file.items.map((i) => i.itemId);
  for (let i = 1; i < ids.length; i++)
    if (!((ids[i - 1] ?? '') < (ids[i] ?? ''))) throw new VaultError('invalid_export');

  // Step 2: the Recovery Key opens the AK wrap, with every expectation taken from the file.
  let recoveryKey: Uint8Array;
  try {
    recoveryKey = crypto.parseRecoveryKey(recoveryKeyText);
  } catch {
    throw new VaultError('invalid_recovery_key');
  }
  const keys = crypto.deriveRecoveryKeys(recoveryKey);
  recoveryKey.fill(0);
  const accountId = uuidToBytes(file.accountId);
  const akId = fromB64(file.akId);
  let accountKey: Uint8Array;
  try {
    accountKey = crypto.unwrapAccountKeyForRecovery({
      recoveryWrapKey: keys.recoveryWrapKey,
      recoveryKeyId: fromB64(file.recoveryKeyId),
      accountId,
      accountKeyId: akId,
      accountKeyEpoch: file.akEpoch,
      envelope: fromB64(file.recoveryWrap),
    });
  } catch {
    throw new VaultError('kit_mismatch');
  } finally {
    keys.recoveryWrapKey.fill(0);
    keys.recoveryAuthKey.fill(0);
  }

  let vaultKey: Uint8Array | undefined;
  try {
    // Step 3: the keyset, and its one vault must be the file's.
    const keyset = crypto.openKeyset({
      accountKey,
      accountKeyId: akId,
      accountId,
      keysetVersion: file.keyset.version,
      envelope: fromB64(file.keyset.envelope),
    });
    keyset.secretKey.fill(0);
    const vault = keyset.vaults[0];
    vaultKey = vault.vk;
    if (vault.vaultId !== file.vaultId) throw new VaultError('integrity');
    const vaultId = uuidToBytes(file.vaultId);

    // Step 4: the manifest, and the items must be exactly what it describes.
    const manifest = crypto.openManifest({
      vaultKey,
      vaultKeyId: vault.vkId,
      vaultId,
      seq: file.manifest.seq,
      envelope: fromB64(file.manifest.envelope),
    });
    const records = file.items.map((i) => ({
      itemId: i.itemId,
      revision: i.revision,
      record: i.record === null ? null : fromB64(i.record),
    }));
    const digest = crypto.itemsDigest(
      records.map((r) => ({
        itemId: uuidToBytes(r.itemId),
        revision: r.revision,
        recordHash: r.record === null ? null : crypto.recordHash(r.record),
      })),
    );
    const live = records.filter((r) => r.record !== null).length;
    if (
      !same(digest, manifest.itemsDigest) ||
      manifest.liveCount !== live ||
      manifest.tombstoneCount !== records.length - live
    )
      throw new VaultError('integrity');

    // Step 5: every record opens at its revision and holds a valid body.
    const items = new Map<string, { revision: number; body: ItemBody }>();
    for (const r of records) {
      if (r.record === null) continue;
      const bytes = crypto.openItemRecord({
        vaultKey,
        vaultKeyId: vault.vkId,
        vaultId,
        itemId: uuidToBytes(r.itemId),
        revision: r.revision,
        schemaVersion: ITEM_SCHEMA_VERSION,
        record: r.record,
      });
      const body = decodeItemBody(bytes);
      bytes.fill(0);
      if (!body) throw new VaultError('integrity');
      items.set(r.itemId, { revision: r.revision, body });
    }
    return {
      accountId: file.accountId,
      vaultId: file.vaultId,
      seq: file.manifest.seq,
      asOfMs: manifest.createdAtMs,
      authorDeviceId: uuidFromBytes(manifest.authorDeviceId),
      items,
      tombstones: records.length - live,
    };
  } catch (error) {
    // The key opened the wrap, so anything else that fails is the file's, not the key's.
    if (error instanceof VaultError) throw error;
    throw new VaultError('integrity');
  } finally {
    accountKey.fill(0);
    vaultKey?.fill(0);
  }
}
