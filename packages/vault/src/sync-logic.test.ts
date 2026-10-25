// @vitest-environment node
import { initRuveeCrypto, uuidToBytes, type RuveeCrypto } from '@ruvee/crypto';
import type { SyncChangesResponse } from '@ruvee/contracts';
import { toB64 } from './bytes.js';
import {
  buildCommit,
  rebase,
  verifyPages,
  ZERO_HASH,
  type Checkpoint,
  type VaultKeys,
} from './sync-logic.js';

let crypto: RuveeCrypto;
let keys: VaultKeys;
const deviceId = '0a1b2c3d-4e5f-4a6b-9c7d-8e9f0a1b2c3d';

beforeAll(async () => {
  crypto = await initRuveeCrypto();
  keys = {
    vaultId: crypto.generateUuid(),
    vaultKey: crypto.generateKey(),
    vaultKeyId: crypto.generateKeyId(),
  };
});

function record(itemId: string, revision: number) {
  return crypto.sealItemRecord({
    vaultKey: keys.vaultKey,
    vaultKeyId: keys.vaultKeyId,
    vaultId: uuidToBytes(keys.vaultId),
    itemId: uuidToBytes(itemId),
    revision,
    schemaVersion: 1,
    body: new TextEncoder().encode('{"synthetic":true}'),
  });
}

/** A two-commit history from genesis, as the server would serve it from seq 0. */
function history() {
  const genesisCheckpoint: Checkpoint = {
    vaultId: keys.vaultId,
    seq: 0,
    manifestHash: ZERO_HASH,
    keysetVersion: 1,
  };
  const genesis = buildCommit(crypto, keys, deviceId, genesisCheckpoint, new Map(), [], 1);
  const itemId = crypto.generateUuid();
  const r1 = record(itemId, 1);
  const second = buildCommit(
    crypto,
    keys,
    deviceId,
    { ...genesisCheckpoint, seq: 1, manifestHash: genesis.manifestHash },
    new Map(),
    [{ itemId, baseRevision: 0, record: r1 }],
    2,
  );
  const page: SyncChangesResponse = {
    vaultId: keys.vaultId,
    currentSeq: 2,
    pageEndSeq: 2,
    items: [{ itemId, revision: 1, updatedSeq: 2, record: toB64(r1) }],
    manifests: [
      { seq: 1, manifest: genesis.body.manifest },
      { seq: 2, manifest: second.body.manifest },
    ],
  };
  return { genesisCheckpoint, page, itemId, r1, second };
}

const accept = () => true;

describe('verifyPages (sync-protocol §5)', () => {
  it('accepts a consistent chain from genesis and returns the new checkpoint', () => {
    const { genesisCheckpoint, page, itemId, second } = history();
    const result = verifyPages(crypto, keys, genesisCheckpoint, new Map(), [page], accept);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.checkpoint.seq).toBe(2);
    expect(toB64(result.checkpoint.manifestHash)).toBe(toB64(second.manifestHash));
    expect(result.state.get(itemId)?.revision).toBe(1);
  });

  it.each([
    ['omits an item', (p: SyncChangesResponse) => ({ ...p, items: [] }), 'digest_mismatch'],
    [
      'claims another revision',
      (p: SyncChangesResponse) => ({ ...p, items: p.items.map((i) => ({ ...i, revision: 2 })) }),
      'digest_mismatch',
    ],
    [
      'drops a manifest',
      (p: SyncChangesResponse) => ({ ...p, manifests: p.manifests.slice(1) }),
      'sequence_gap',
    ],
    [
      'reorders manifests',
      (p: SyncChangesResponse) => ({ ...p, manifests: [...p.manifests].reverse() }),
      'sequence_gap',
    ],
    [
      'stops short of currentSeq',
      (p: SyncChangesResponse) => ({ ...p, currentSeq: 3 }),
      'sequence_gap',
    ],
    [
      'serves another vault',
      (p: SyncChangesResponse) => ({ ...p, vaultId: '7c0e5a3b-2f41-4d6e-8a9b-0c1d2e3f4a5b' }),
      'wrong_vault',
    ],
    [
      'swaps a manifest for one at another position',
      (p: SyncChangesResponse) => ({
        ...p,
        manifests: p.manifests.map((m) => ({ ...m, manifest: p.manifests[1]?.manifest ?? '' })),
      }),
      'manifest_invalid',
    ],
  ])('detects a server that %s', (_label, tamper, reason) => {
    const { genesisCheckpoint, page } = history();
    const result = verifyPages(crypto, keys, genesisCheckpoint, new Map(), [tamper(page)], accept);
    expect(result).toEqual({ ok: false, reason });
  });

  it('detects a rewritten history after the checkpoint, and a server that went backwards', () => {
    const { genesisCheckpoint, page } = history();
    const forged = { ...genesisCheckpoint, seq: 1, manifestHash: new Uint8Array(32).fill(7) };
    expect(
      verifyPages(
        crypto,
        keys,
        forged,
        new Map(),
        [{ ...page, manifests: page.manifests.slice(1) }],
        accept,
      ),
    ).toEqual({
      ok: false,
      reason: 'history_rewritten',
    });
    const ahead = { ...genesisCheckpoint, seq: 5 };
    expect(verifyPages(crypto, keys, ahead, new Map(), [page], accept)).toEqual({
      ok: false,
      reason: 'server_behind',
    });
  });

  it("requires a paired device's chain to pass through the checkpoint it received", () => {
    const { genesisCheckpoint, page, second } = history();
    const anchor = { seq: 2, manifestHash: second.manifestHash };
    expect(verifyPages(crypto, keys, genesisCheckpoint, new Map(), [page], accept, anchor).ok).toBe(
      true,
    );
    const forged = { seq: 2, manifestHash: new Uint8Array(32).fill(3) };
    expect(verifyPages(crypto, keys, genesisCheckpoint, new Map(), [page], accept, forged)).toEqual(
      {
        ok: false,
        reason: 'history_rewritten',
      },
    );
    // A server that hides commits the approving device had already seen.
    const later = { seq: 5, manifestHash: second.manifestHash };
    expect(verifyPages(crypto, keys, genesisCheckpoint, new Map(), [page], accept, later)).toEqual({
      ok: false,
      reason: 'server_behind',
    });
  });

  it('rejects a record that does not decrypt at its claimed revision (check 6)', () => {
    const { genesisCheckpoint, page } = history();
    expect(verifyPages(crypto, keys, genesisCheckpoint, new Map(), [page], () => false)).toEqual({
      ok: false,
      reason: 'record_invalid',
    });
  });
});

describe('rebase (sync-protocol §6)', () => {
  const id = '7c0e5a3b-2f41-4d6e-8a9b-0c1d2e3f4a5b';
  const r = new Uint8Array([1]);
  it.each([
    ['unchanged remote', { revision: 3, record: r }, { baseRevision: 3, record: r }, 'keep'],
    ['edit vs edit', { revision: 4, record: r }, { baseRevision: 3, record: r }, 'edited_on_both'],
    [
      'edit vs delete',
      { revision: 4, record: null },
      { baseRevision: 3, record: r },
      'deleted_elsewhere',
    ],
    [
      'delete vs edit',
      { revision: 4, record: r },
      { baseRevision: 3, record: null },
      'edited_after_delete',
    ],
    [
      'delete vs delete',
      { revision: 4, record: null },
      { baseRevision: 3, record: null },
      'dropped',
    ],
  ] as const)('%s', (_label, remote, mutation, outcome) => {
    const result = rebase([{ itemId: id, ...mutation }], new Map([[id, remote]]), 1);
    if (outcome === 'keep')
      expect(result).toEqual({ keep: [{ itemId: id, ...mutation }], conflicts: [] });
    else if (outcome === 'dropped') expect(result).toEqual({ keep: [], conflicts: [] });
    else expect(result.conflicts.map((c) => c.kind)).toEqual([outcome]);
  });
});
