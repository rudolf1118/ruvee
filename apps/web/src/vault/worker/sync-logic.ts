import { uuidToBytes, type Manifest, type RuveeCrypto } from '@ruvee/crypto';
import type { CommitRequest, SyncChangesResponse } from '@ruvee/contracts';
import { fromB64, toB64 } from './bytes';

/** What a device has verified (sync-protocol §5 "Checkpoints"). */
export interface Checkpoint {
  readonly vaultId: string;
  readonly seq: number;
  readonly manifestHash: Uint8Array;
  readonly keysetVersion: number;
}

export interface SyncedItem {
  readonly revision: number;
  readonly record: Uint8Array | null;
}

export type SyncedState = ReadonlyMap<string, SyncedItem>;

export interface VaultKeys {
  readonly vaultId: string;
  readonly vaultKey: Uint8Array;
  readonly vaultKeyId: Uint8Array;
}

export interface PendingMutation {
  readonly itemId: string;
  /** The synced revision this change is based on; 0 for a new item. */
  readonly baseRevision: number;
  /** Sealed at `baseRevision + 1`; null for a permanent deletion. */
  readonly record: Uint8Array | null;
}

export const ZERO_HASH = new Uint8Array(32);

export type VerifyFailure =
  | 'server_behind'
  | 'history_rewritten'
  | 'manifest_invalid'
  | 'sequence_gap'
  | 'digest_mismatch'
  | 'record_invalid'
  | 'wrong_vault';

export type VerifyResult =
  | {
      readonly ok: true;
      readonly state: Map<string, SyncedItem>;
      readonly checkpoint: Checkpoint;
      /** The newest verified manifest, or undefined when nothing changed. */
      readonly newest?: {
        readonly seq: number;
        readonly envelope: Uint8Array;
        readonly manifest: Manifest;
      };
      readonly changed: readonly string[];
    }
  | { readonly ok: false; readonly reason: VerifyFailure };

export function digestEntries(crypto: RuveeCrypto, state: SyncedState) {
  return [...state].map(([itemId, item]) => ({
    itemId: uuidToBytes(itemId),
    revision: item.revision,
    recordHash: item.record === null ? null : crypto.recordHash(item.record),
  }));
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/**
 * Verifies staged pages against the checkpoint before anything is applied (sync-protocol §5,
 * checks 1 to 6, INV-07). Any failure means nothing is applied and the vault goes read-only.
 * `openRecord` decrypts a record at its claimed revision and returns false if it cannot.
 */
/**
 * A checkpoint received by pairing (device-enrollment §3.2 step 10) before the device has any
 * records. The device pulls from genesis, and the verified chain must pass through this hash at
 * this `seq` and must not end before it, which keeps the rollback protection of the checkpoint.
 */
export interface Anchor {
  readonly seq: number;
  readonly manifestHash: Uint8Array;
}

export function verifyPages(
  crypto: RuveeCrypto,
  keys: VaultKeys,
  checkpoint: Checkpoint,
  synced: SyncedState,
  pages: readonly SyncChangesResponse[],
  openRecord: (itemId: string, revision: number, record: Uint8Array) => boolean,
  anchor?: Anchor,
): VerifyResult {
  const last = pages.at(-1);
  if (!last || pages.some((p) => p.vaultId !== keys.vaultId))
    return { ok: false, reason: 'wrong_vault' };
  const currentSeq = last.currentSeq;
  // Check 4: the server must not be behind what this device has already verified.
  if (currentSeq < checkpoint.seq || (anchor !== undefined && currentSeq < anchor.seq))
    return { ok: false, reason: 'server_behind' };
  const manifests = pages.flatMap((p) => p.manifests);
  if (currentSeq === checkpoint.seq) {
    if (manifests.length > 0 || pages.some((p) => p.items.length > 0))
      return { ok: false, reason: 'history_rewritten' };
    return { ok: true, state: new Map(synced), checkpoint, changed: [] };
  }

  // Checks 1 to 3: consecutive seqs from the checkpoint, each decrypting at its position and
  // chaining to the one before it.
  let previous = checkpoint.manifestHash;
  let newest: { seq: number; envelope: Uint8Array; manifest: Manifest } | undefined;
  const vaultIdBytes = uuidToBytes(keys.vaultId);
  for (const [i, entry] of manifests.entries()) {
    if (entry.seq !== checkpoint.seq + i + 1) return { ok: false, reason: 'sequence_gap' };
    const envelope = fromB64(entry.manifest);
    let manifest: Manifest;
    try {
      manifest = crypto.openManifest({
        vaultKey: keys.vaultKey,
        vaultKeyId: keys.vaultKeyId,
        vaultId: vaultIdBytes,
        seq: entry.seq,
        envelope,
      });
    } catch {
      return { ok: false, reason: 'manifest_invalid' };
    }
    if (!sameBytes(manifest.prevManifestHash, previous))
      return { ok: false, reason: 'history_rewritten' };
    previous = crypto.manifestHash(envelope);
    if (anchor?.seq === entry.seq && !sameBytes(previous, anchor.manifestHash))
      return { ok: false, reason: 'history_rewritten' };
    newest = { seq: entry.seq, envelope, manifest };
  }
  if (newest?.seq !== currentSeq) return { ok: false, reason: 'sequence_gap' };

  // Check 6, then check 5 on the merged state.
  const state = new Map(synced);
  const changed: string[] = [];
  for (const item of pages.flatMap((p) => p.items)) {
    const record = item.record === null ? null : fromB64(item.record);
    if (record !== null && !openRecord(item.itemId, item.revision, record))
      return { ok: false, reason: 'record_invalid' };
    state.set(item.itemId, { revision: item.revision, record });
    changed.push(item.itemId);
  }
  const entries = digestEntries(crypto, state);
  const live = entries.filter((e) => e.recordHash !== null).length;
  if (
    !sameBytes(crypto.itemsDigest(entries), newest.manifest.itemsDigest) ||
    newest.manifest.liveCount !== live ||
    newest.manifest.tombstoneCount !== entries.length - live
  )
    return { ok: false, reason: 'digest_mismatch' };

  return {
    ok: true,
    state,
    checkpoint: {
      vaultId: keys.vaultId,
      seq: newest.seq,
      manifestHash: previous,
      keysetVersion: checkpoint.keysetVersion,
    },
    newest,
    changed,
  };
}

/** Builds a commit at `checkpoint.seq + 1` over the synced state (sync-protocol §4.1). */
export function buildCommit(
  crypto: RuveeCrypto,
  keys: VaultKeys,
  deviceId: string,
  checkpoint: Checkpoint,
  synced: SyncedState,
  mutations: readonly PendingMutation[],
  nowMs: number,
): {
  body: CommitRequest;
  envelope: Uint8Array;
  manifestHash: Uint8Array;
  state: Map<string, SyncedItem>;
} {
  const state = new Map(synced);
  for (const m of mutations)
    state.set(m.itemId, { revision: m.baseRevision + 1, record: m.record });
  const entries = digestEntries(crypto, state);
  const live = entries.filter((e) => e.recordHash !== null).length;
  const commitId = crypto.generateUuid();
  const seq = checkpoint.seq + 1;
  const envelope = crypto.sealManifest({
    vaultKey: keys.vaultKey,
    vaultKeyId: keys.vaultKeyId,
    manifest: {
      vaultId: uuidToBytes(keys.vaultId),
      seq,
      prevManifestHash: checkpoint.manifestHash,
      itemsDigest: crypto.itemsDigest(entries),
      liveCount: live,
      tombstoneCount: entries.length - live,
      authorDeviceId: uuidToBytes(deviceId),
      createdAtMs: nowMs,
      commitId: uuidToBytes(commitId),
    },
  });
  return {
    body: {
      vaultId: keys.vaultId,
      commitId,
      baseSeq: checkpoint.seq,
      mutations: mutations.map((m) => ({
        itemId: m.itemId,
        baseRevision: m.baseRevision,
        newRevision: m.baseRevision + 1,
        record: m.record === null ? null : toB64(m.record),
      })),
      manifest: toB64(envelope),
    },
    envelope,
    manifestHash: crypto.manifestHash(envelope),
    state,
  };
}

export type ConflictKind = 'edited_on_both' | 'deleted_elsewhere' | 'edited_after_delete';

export interface Conflict {
  readonly itemId: string;
  readonly kind: ConflictKind;
  /** This device's version, sealed at `localRevision`; null when this device deleted the item. */
  readonly localRecord: Uint8Array | null;
  readonly localRevision: number;
  /** The server revision the conflict was detected against. */
  readonly remoteRevision: number;
  readonly detectedAtMs: number;
}

/**
 * Rebases pending mutations on a newly verified state (sync-protocol §6). Timestamps never
 * decide: a mutation whose base is no longer current becomes an explicit conflict for the user.
 */
export function rebase(
  pending: readonly PendingMutation[],
  remote: SyncedState,
  nowMs: number,
): { keep: PendingMutation[]; conflicts: Conflict[] } {
  const keep: PendingMutation[] = [];
  const conflicts: Conflict[] = [];
  for (const m of pending) {
    const current = remote.get(m.itemId);
    const currentRevision = current?.revision ?? 0;
    if (currentRevision === m.baseRevision) {
      keep.push(m);
      continue;
    }
    const remoteDeleted = current?.record === null;
    if (m.record === null && remoteDeleted) continue; // Deleted on both: nothing to do.
    conflicts.push({
      itemId: m.itemId,
      kind:
        m.record === null
          ? 'edited_after_delete'
          : remoteDeleted
            ? 'deleted_elsewhere'
            : 'edited_on_both',
      localRecord: m.record,
      localRevision: m.baseRevision + 1,
      remoteRevision: currentRevision,
      detectedAtMs: nowMs,
    });
  }
  return { keep, conflicts };
}
