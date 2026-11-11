import { uuidToBytes } from '@ruvee/crypto';
import {
  API_ERRORS,
  commitResponseSchema,
  errorResponseSchema,
  syncChangesResponseSchema,
} from '@ruvee/contracts';
import type request from 'supertest';
import { registerAccount, startHarness, type Harness } from './support/api-harness.js';
import {
  buildCommit,
  sealItem,
  syntheticAccount,
  type SyntheticAccount,
} from './support/synthetic-client.js';

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  return errorResponseSchema.parse(res.body);
}

interface ItemState {
  revision: number;
  record: Uint8Array | null;
}

describe('sync commits and changes (real database, real envelopes)', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let cookie: string;
  /** What the test client believes the vault holds, as a client would track it. */
  const items = new Map<string, ItemState>();
  let seq = 0;
  let prevHash: Uint8Array = new Uint8Array(32);

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-sync-owner');
    cookie = await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  function stateAfter(
    mutations: { itemId: string; revision: number; record: Uint8Array | null }[],
  ) {
    const next = new Map(items);
    for (const m of mutations) next.set(m.itemId, { revision: m.revision, record: m.record });
    return [...next].map(([itemId, s]) => ({ itemId, ...s }));
  }

  /** Builds and sends a commit at the current seq; on success, advances the local state. */
  async function commit(
    mutations: { itemId: string; baseRevision: number; record: Uint8Array | null }[],
    options: { commitId?: string; baseSeq?: number } = {},
  ) {
    const full = mutations.map((m) => ({ ...m, revision: m.baseRevision + 1 }));
    const built = buildCommit(account, {
      seq: (options.baseSeq ?? seq) + 1,
      prevManifestHash: prevHash,
      items: stateAfter(full),
      ...(options.commitId ? { commitId: options.commitId } : {}),
    });
    const body = {
      vaultId: account.vaultId,
      commitId: built.commitId,
      baseSeq: options.baseSeq ?? seq,
      mutations: full.map((m) => ({
        itemId: m.itemId,
        baseRevision: m.baseRevision,
        newRevision: m.revision,
        record: m.record === null ? null : b64(m.record),
      })),
      manifest: b64(built.manifest),
    };
    const res = await h.post('/api/v1/sync/commits', body, cookie);
    if (res.status === 200) {
      for (const m of full) items.set(m.itemId, { revision: m.revision, record: m.record });
      seq = commitResponseSchema.parse(res.body).seq;
      prevHash = built.manifestHash;
    }
    return { res, body };
  }

  /** Pulls every page and verifies the chain and digest the way sync-protocol §5 requires. */
  async function pullAndVerify(since: number, limit?: number) {
    const pages = [];
    let cursor = since;
    for (;;) {
      const res = await h
        .get(`/api/v1/sync/changes?since=${cursor}${limit ? `&limit=${limit}` : ''}`, cookie)
        .expect(200);
      const page = syncChangesResponseSchema.parse(res.body);
      pages.push(page);
      if (page.nextCursor === undefined) break;
      cursor = page.nextCursor;
    }
    const manifests = pages.flatMap((p) => p.manifests);
    let previous: Uint8Array | undefined = since === 0 ? new Uint8Array(32) : undefined;
    let last;
    for (const [i, m] of manifests.entries()) {
      expect(m.seq).toBe(since + i + 1);
      const envelope = unb64(m.manifest);
      const opened = account.crypto.openManifest({
        vaultKey: account.vaultKey,
        vaultKeyId: account.vaultKeyId,
        vaultId: uuidToBytes(account.vaultId),
        seq: m.seq,
        envelope,
      });
      if (previous) expect(b64(opened.prevManifestHash)).toBe(b64(previous));
      previous = account.crypto.manifestHash(envelope);
      last = opened;
    }
    const latest = new Map<string, { revision: number; record: string | null }>();
    for (const item of pages.flatMap((p) => p.items)) latest.set(item.itemId, item);
    return { pages, manifests, latest, last };
  }

  it('accepts the genesis commit of an empty vault', async () => {
    const { res } = await commit([]);
    expect(res.status, res.text).toBe(200);
    expect(res.body).toEqual({ seq: 1 });
  });

  it('stores an item and serves records and a manifest chain the client can verify', async () => {
    const itemId = account.crypto.generateUuid();
    const record = sealItem(account, itemId, 1, { v: 1, type: 'note', title: 'Synthetic' });
    expect((await commit([{ itemId, baseRevision: 0, record }])).res.status).toBe(200);
    const pulled = await pullAndVerify(0);
    expect(pulled.manifests).toHaveLength(2);
    expect(pulled.latest.get(itemId)?.record).toBe(b64(record));
    // Check 5: the digest over the received state equals the newest manifest's.
    const digest = account.crypto.itemsDigest(
      [...pulled.latest].map(([id, i]) => ({
        itemId: uuidToBytes(id),
        revision: i.revision,
        recordHash: i.record === null ? null : account.crypto.recordHash(unb64(i.record)),
      })),
    );
    expect(b64(digest)).toBe(b64(pulled.last?.itemsDigest ?? new Uint8Array()));
  });

  it('refuses a commit on a stale baseSeq with the current seq (409 seq_conflict)', async () => {
    const itemId = account.crypto.generateUuid();
    const record = sealItem(account, itemId, 1, { v: 1, type: 'note', title: 'Late' });
    const { res } = await commit([{ itemId, baseRevision: 0, record }], { baseSeq: seq - 1 });
    expect(expectError(res, 'seq_conflict')).toMatchObject({ details: { currentSeq: seq } });
  });

  it('refuses a stale item revision and lists every conflicting item (409 revision_conflict)', async () => {
    const [existing] = [...items.keys()];
    const record = sealItem(account, existing ?? '', 2, { v: 1, type: 'note', title: 'Edited' });
    const fresh = account.crypto.generateUuid();
    const { res } = await commit([
      { itemId: existing ?? '', baseRevision: 0, record },
      { itemId: fresh, baseRevision: 3, record: sealItem(account, fresh, 4, { v: 1 }) },
    ]);
    const error = expectError(res, 'revision_conflict');
    expect(error).toMatchObject({
      details: {
        conflicts: [
          { itemId: existing, currentRevision: 1, tombstone: false },
          { itemId: fresh, currentRevision: null, tombstone: false },
        ],
      },
    });
  });

  it('replays a retried commit id, and refuses the same id with a different body', async () => {
    const itemId = account.crypto.generateUuid();
    const record = sealItem(account, itemId, 1, { v: 1, type: 'note', title: 'Retry' });
    const first = await commit([{ itemId, baseRevision: 0, record }]);
    expect(first.res.status).toBe(200);
    const retry = await h.post('/api/v1/sync/commits', first.body, cookie);
    expect(retry.status).toBe(200);
    expect(retry.body).toEqual(first.res.body);
    const changed = { ...first.body, mutations: [] };
    expectError(await h.post('/api/v1/sync/commits', changed, cookie), 'idempotency_mismatch');
  });

  it('turns a permanent deletion into a tombstone that can no longer be edited', async () => {
    const [itemId, state] = [...items].find(([, s]) => s.record !== null) ?? [];
    if (!itemId || !state) throw new Error('fixture item missing');
    expect(
      (await commit([{ itemId, baseRevision: state.revision, record: null }])).res.status,
    ).toBe(200);
    const pulled = await pullAndVerify(seq - 1);
    expect(pulled.latest.get(itemId)).toMatchObject({ record: null, revision: state.revision + 1 });
    expect(pulled.last?.tombstoneCount).toBe(1);
    const edit = sealItem(account, itemId, state.revision + 2, { v: 1 });
    const { res } = await commit([{ itemId, baseRevision: state.revision + 1, record: edit }]);
    expect(expectError(res, 'revision_conflict')).toMatchObject({
      details: { conflicts: [{ itemId, tombstone: true }] },
    });
  });

  it('checks framing, headers and revision arithmetic, but nothing inside the ciphertext', async () => {
    const itemId = account.crypto.generateUuid();
    const good = sealItem(account, itemId, 1, { v: 1 });
    const built = buildCommit(account, { seq: seq + 1, prevManifestHash: prevHash, items: [] });
    const base = {
      vaultId: account.vaultId,
      commitId: built.commitId,
      baseSeq: seq,
      manifest: b64(built.manifest),
    };
    const send = (mutations: unknown[], over: object = {}) =>
      h.post('/api/v1/sync/commits', { ...base, mutations, ...over }, cookie);
    const garbage = new Uint8Array(good);
    garbage[0] = 0x00;
    expectError(
      await send([{ itemId, baseRevision: 0, newRevision: 1, record: b64(garbage) }]),
      'invalid_request',
    );
    expectError(
      await send([{ itemId, baseRevision: 0, newRevision: 2, record: b64(good) }]),
      'invalid_request',
    );
    expectError(
      await send([{ itemId, baseRevision: 0, newRevision: 1, record: null }]),
      'invalid_request',
    );
    expectError(
      await send([
        { itemId, baseRevision: 0, newRevision: 1, record: b64(good) },
        { itemId, baseRevision: 0, newRevision: 1, record: b64(good) },
      ]),
      'invalid_request',
    );
    // A record whose item key was wrapped under another vault key id.
    const otherVault = { ...account, vaultKeyId: account.crypto.generateKeyId() };
    const foreign = sealItem(otherVault, itemId, 1, { v: 1 });
    expectError(
      await send([{ itemId, baseRevision: 0, newRevision: 1, record: b64(foreign) }]),
      'invalid_request',
    );
    const badManifest = unb64(base.manifest);
    badManifest[4] = 0x05;
    expectError(await send([], { manifest: b64(badManifest) }), 'invalid_request');
    expectError(await send([], { vaultId: account.crypto.generateUuid() }), 'not_found');
  });

  it('accepts commit bodies above 64 KiB on the commit route only', async () => {
    const mutations = [];
    for (let i = 0; i < 4; i++) {
      const itemId = account.crypto.generateUuid();
      // About 60 KB of synthetic filler per item, well below the 64 KiB body limit each.
      mutations.push({
        itemId,
        baseRevision: 0,
        record: sealItem(account, itemId, 1, { v: 1, filler: 'x'.repeat(60_000) }),
      });
    }
    const { res } = await commit(mutations);
    expect(res.status, res.text).toBe(200);
    const big = { username: 'x'.repeat(70_000) };
    expectError(await h.post('/api/v1/auth/login/start', big), 'payload_too_large');
  });

  it('pages on commit boundaries and the client can still verify the whole range', async () => {
    const before = seq;
    for (let c = 0; c < 2; c++) {
      const mutations = Array.from({ length: 75 }, () => {
        const itemId = account.crypto.generateUuid();
        return { itemId, baseRevision: 0, record: sealItem(account, itemId, 1, { v: 1, n: c }) };
      });
      expect((await commit(mutations)).res.status).toBe(200);
    }
    const pulled = await pullAndVerify(before, 100);
    expect(pulled.pages.length).toBe(2);
    expect(pulled.pages[0]?.items).toHaveLength(75);
    expect(pulled.pages[0]?.pageEndSeq).toBe(before + 1);
    expect(pulled.latest.size).toBe(150);
    expect(pulled.manifests.map((m) => m.seq)).toEqual([before + 1, before + 2]);
  });

  it('reports the server behind the client without inventing data', async () => {
    const res = await h.get(`/api/v1/sync/changes?since=${seq + 10}`, cookie).expect(200);
    expect(res.body).toMatchObject({ currentSeq: seq, items: [], manifests: [] });
    expectError(await h.get('/api/v1/sync/changes?since=-1', cookie), 'invalid_request');
    expectError(await h.get('/api/v1/sync/changes?since=0&limit=50', cookie), 'invalid_request');
  });
});
