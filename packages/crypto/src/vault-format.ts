import {
  ascii,
  compareBytes,
  concat,
  isBytes,
  lengthPrefixed,
  readU32,
  readU64,
  requireBytes,
  requireU32,
  requireU64,
  u32be,
  u64be,
  u8,
} from './bytes.js';
import {
  envelopeKeyId,
  envelopeStructureProblem,
  ITEM_BODY_ENVELOPE_MAX_BYTES,
  ITEM_KEY_ENVELOPE_BYTES,
  MANIFEST_ENVELOPE_BYTES,
  PURPOSES,
} from './envelope.js';
import { RuveeCryptoError } from './errors.js';
import { UUID_BYTES } from './ids.js';
import { HASH_BYTES } from './primitives.js';

/**
 * Byte formats of the vault (cryptographic-design §5.2 and §5.3) that need no key: the item
 * record container, the manifest plaintext and the hash inputs. The server uses the structural
 * checks; it can never check what is inside the envelopes.
 */

const RECORD_MAGIC = ascii('RVI');
const RECORD_VERSION = 1;
const RECORD_HEADER_BYTES = 4;
/** `"RVI" ‖ u8(1) ‖ LP(93) ‖ LP(≤ 65,597)`: 65,702 bytes. */
export const ITEM_RECORD_MAX_BYTES =
  RECORD_HEADER_BYTES + 4 + ITEM_KEY_ENVELOPE_BYTES + 4 + ITEM_BODY_ENVELOPE_MAX_BYTES;

export interface ItemRecordParts {
  readonly itemKeyEnvelope: Uint8Array;
  readonly itemBodyEnvelope: Uint8Array;
  /** `ik_id`, read from the body envelope header; the item-key envelope authenticates it. */
  readonly itemKeyId: Uint8Array;
}

export function encodeItemRecord(itemKeyEnvelope: Uint8Array, itemBodyEnvelope: Uint8Array) {
  return concat(
    RECORD_MAGIC,
    u8(RECORD_VERSION),
    lengthPrefixed(itemKeyEnvelope),
    lengthPrefixed(itemBodyEnvelope),
  );
}

export type RecordStructureProblem =
  | 'not_bytes'
  | 'length'
  | 'magic'
  | 'version'
  | 'framing'
  | 'item_key_envelope'
  | 'item_body_envelope';

/** Splits a record and checks its framing and both envelope headers. */
export function parseItemRecord(
  record: unknown,
): { ok: true; parts: ItemRecordParts } | { ok: false; problem: RecordStructureProblem } {
  if (!isBytes(record)) return { ok: false, problem: 'not_bytes' };
  if (record.length < RECORD_HEADER_BYTES + 8 || record.length > ITEM_RECORD_MAX_BYTES)
    return { ok: false, problem: 'length' };
  if (
    record[0] !== RECORD_MAGIC[0] ||
    record[1] !== RECORD_MAGIC[1] ||
    record[2] !== RECORD_MAGIC[2]
  )
    return { ok: false, problem: 'magic' };
  if (record[3] !== RECORD_VERSION) return { ok: false, problem: 'version' };
  const keyLength = readU32(record, RECORD_HEADER_BYTES);
  const keyStart = RECORD_HEADER_BYTES + 4;
  const bodyLengthAt = keyStart + keyLength;
  if (bodyLengthAt + 4 > record.length) return { ok: false, problem: 'framing' };
  const bodyLength = readU32(record, bodyLengthAt);
  const bodyStart = bodyLengthAt + 4;
  if (bodyStart + bodyLength !== record.length) return { ok: false, problem: 'framing' };
  const itemKeyEnvelope = record.subarray(keyStart, bodyLengthAt);
  const itemBodyEnvelope = record.subarray(bodyStart);
  if (envelopeStructureProblem(itemKeyEnvelope, PURPOSES.ITEM_KEY) !== undefined)
    return { ok: false, problem: 'item_key_envelope' };
  if (envelopeStructureProblem(itemBodyEnvelope, PURPOSES.ITEM_BODY) !== undefined)
    return { ok: false, problem: 'item_body_envelope' };
  return {
    ok: true,
    parts: { itemKeyEnvelope, itemBodyEnvelope, itemKeyId: envelopeKeyId(itemBodyEnvelope) },
  };
}

/** Header checks for a manifest envelope (exactly 198 bytes, purpose `MANIFEST`). */
export function manifestStructureProblem(envelope: unknown): string | undefined {
  if (!isBytes(envelope)) return 'not_bytes';
  if (envelope.length !== MANIFEST_ENVELOPE_BYTES) return 'length';
  return envelopeStructureProblem(envelope, PURPOSES.MANIFEST);
}

/** Vault manifest plaintext (§5.3). Identifiers are 16 raw bytes. */
export interface Manifest {
  readonly vaultId: Uint8Array;
  readonly seq: number;
  readonly prevManifestHash: Uint8Array;
  readonly itemsDigest: Uint8Array;
  readonly liveCount: number;
  readonly tombstoneCount: number;
  readonly authorDeviceId: Uint8Array;
  readonly createdAtMs: number;
  readonly commitId: Uint8Array;
}

const MANIFEST_VERSION = 1;
export const MANIFEST_PLAINTEXT_BYTES = 137;

export function encodeManifest(value: unknown): Uint8Array {
  if (typeof value !== 'object' || value === null)
    throw new RuveeCryptoError('invalid_argument', { field: 'manifest' });
  const m = value as Record<string, unknown>;
  const out = concat(
    u8(MANIFEST_VERSION),
    requireBytes(m.vaultId, 'manifest.vaultId', UUID_BYTES),
    u64be(requireU64(m.seq, 'manifest.seq', 1)),
    requireBytes(m.prevManifestHash, 'manifest.prevManifestHash', HASH_BYTES),
    requireBytes(m.itemsDigest, 'manifest.itemsDigest', HASH_BYTES),
    u32be(requireU32(m.liveCount, 'manifest.liveCount')),
    u32be(requireU32(m.tombstoneCount, 'manifest.tombstoneCount')),
    requireBytes(m.authorDeviceId, 'manifest.authorDeviceId', UUID_BYTES),
    u64be(requireU64(m.createdAtMs, 'manifest.createdAtMs')),
    requireBytes(m.commitId, 'manifest.commitId', UUID_BYTES),
  );
  if (out.length !== MANIFEST_PLAINTEXT_BYTES)
    throw new RuveeCryptoError('invalid_argument', { field: 'manifest' });
  return out;
}

/** Strict decoding; the caller compares `vaultId` and `seq` with the ones it expected. */
export function decodeManifest(plaintext: Uint8Array): Manifest {
  if (plaintext.length !== MANIFEST_PLAINTEXT_BYTES || plaintext[0] !== MANIFEST_VERSION)
    throw new RuveeCryptoError('malformed_plaintext');
  const seq = readU64(plaintext, 17);
  const createdAtMs = readU64(plaintext, 113);
  if (seq === undefined || seq < 1 || createdAtMs === undefined)
    throw new RuveeCryptoError('malformed_plaintext');
  return {
    vaultId: plaintext.slice(1, 17),
    seq,
    prevManifestHash: plaintext.slice(25, 57),
    itemsDigest: plaintext.slice(57, 89),
    liveCount: readU32(plaintext, 89),
    tombstoneCount: readU32(plaintext, 93),
    authorDeviceId: plaintext.slice(97, 113),
    createdAtMs,
    commitId: plaintext.slice(121, 137),
  };
}

/** One entry of `items_digest`: a live record's hash, or a tombstone. */
export interface DigestEntry {
  readonly itemId: Uint8Array;
  readonly revision: number;
  /** `record_hash` for a live item; null for a tombstone. */
  readonly recordHash: Uint8Array | null;
}

const ENTRY_BYTES = UUID_BYTES + 8 + 1 + HASH_BYTES;
const STATE_LIVE = 1;
const STATE_TOMBSTONE = 2;

/** `u32(n) ‖ entry_1 ‖ … ‖ entry_n`, sorted by `item_id` bytewise; duplicates are refused. */
export function itemsDigestInput(entries: unknown): Uint8Array {
  if (!Array.isArray(entries) || entries.length > 0xffff_ffff)
    throw new RuveeCryptoError('invalid_argument', { field: 'entries' });
  const checked = (entries as unknown[]).map((value) => {
    if (typeof value !== 'object' || value === null)
      throw new RuveeCryptoError('invalid_argument', { field: 'entries' });
    const e = value as Record<string, unknown>;
    const itemId = requireBytes(e.itemId, 'entry.itemId', UUID_BYTES);
    const revision = requireU64(e.revision, 'entry.revision', 1);
    const recordHash =
      e.recordHash === null ? null : requireBytes(e.recordHash, 'entry.recordHash', HASH_BYTES);
    return { itemId, revision, recordHash };
  });
  checked.sort((a, b) => compareBytes(a.itemId, b.itemId));
  const out = new Uint8Array(4 + checked.length * ENTRY_BYTES);
  out.set(u32be(checked.length), 0);
  checked.forEach((e, i) => {
    const prev = checked[i - 1];
    if (prev && compareBytes(prev.itemId, e.itemId) === 0)
      throw new RuveeCryptoError('invalid_argument', { field: 'entries' });
    const at = 4 + i * ENTRY_BYTES;
    out.set(e.itemId, at);
    out.set(u64be(e.revision), at + UUID_BYTES);
    out[at + UUID_BYTES + 8] = e.recordHash === null ? STATE_TOMBSTONE : STATE_LIVE;
    if (e.recordHash) out.set(e.recordHash, at + UUID_BYTES + 9);
  });
  return out;
}

export const HASH_DOMAINS = {
  manifest: ascii('ruvee/v1/manifest-hash'),
  record: ascii('ruvee/v1/record-hash'),
  itemsDigest: ascii('ruvee/v1/items-digest'),
  recoveryKeyCheck: ascii('ruvee/v1/rk-check'),
} as const;
