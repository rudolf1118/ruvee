// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { ItemDraft } from '../protocol.js';
import { DeviceStore } from '../store.js';
import { FakeServer, fakeOpaque } from '../test-support.js';
import { VaultEngine } from '../vault-engine.js';

/**
 * Pre-deployment review, findings R5 and R6 (docs/security/predeployment-review.md), as
 * regressions: the reproductions now assert the secure outcome. Synthetic data only.
 */

const PASSWORD = 'synthetic engine passphrase 4c1e';
let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

async function device(
  server: FakeServer,
  factory = new IDBFactory(),
  onEvent: (engine: VaultEngine) => void = () => undefined,
) {
  const store = await DeviceStore.open(factory);
  const engine: VaultEngine = new VaultEngine({
    crypto,
    api: server.api(),
    store,
    opaque: fakeOpaque,
    origin: 'http://127.0.0.1:3101',
    platform: 'web',
    now: () => Date.now(),
    emit: () => {
      onEvent(engine);
    },
  });
  return { engine, store, factory };
}

const login = (title: string): ItemDraft => ({
  type: 'login',
  title,
  username: 'u@mail.example',
  password: 'synthetic-pw',
  urls: [],
  notes: '',
  noteText: '',
  tags: [],
  favorite: false,
});

async function account() {
  const server = new FakeServer();
  const a = await device(server);
  const kit = await a.engine.setupBegin({
    bootstrapToken: 'T'.repeat(43),
    username: 'Synthetic-User',
    password: PASSWORD,
  });
  await a.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
  await a.engine.setupFinish();
  return { server, a, kit: kit.recoveryKey };
}

async function paired(server: FakeServer, from: Awaited<ReturnType<typeof device>>) {
  const b = await device(server);
  await b.engine.login({ username: 'synthetic-user', password: PASSWORD });
  const started = await from.engine.pairingStart();
  await b.engine.pairingJoin({ code: started.code });
  await from.engine.pairingStatus({ pairingId: started.pairingId });
  await b.engine.pairingWait();
  await from.engine.pairingApprove({ pairingId: started.pairingId });
  await b.engine.pairingWait();
  return b;
}

const checkpointSeq = (e: VaultEngine) =>
  (e as unknown as { session: { checkpoint: { seq: number } } }).session.checkpoint.seq;

describe('REVIEW R5 (regression): no commit reply lowers the checkpoint', () => {
  /** A has one commit applied whose reply was lost; B committed on top of it. */
  async function lostReplyThenB() {
    const { server, a } = await account();
    const b = await paired(server, a);
    const item = await a.engine.save({ draft: login('v1') });
    await a.engine.sync();
    await b.engine.sync();
    server.loseNextCommitResponse = true;
    await a.engine.save({ draft: { ...login('A edit'), id: item.id } });
    await a.engine.idle();
    const seqOfA = server.currentSeq;
    const itemsAtA = structuredClone(server.items);
    const manifestsAtA = structuredClone(server.manifests);
    await b.engine.sync();
    await b.engine.save({ draft: { ...login('B edit (e.g. a rotated password)'), id: item.id } });
    await b.engine.sync();
    const seqOfB = server.currentSeq;
    expect(seqOfB).toBe(seqOfA + 1);
    const hideB = () => {
      server.manifests = manifestsAtA;
      server.items = itemsAtA;
    };
    return { server, a, b, seqOfA, seqOfB, hideB };
  }

  it('keeps the checkpoint at what the pull verified, and refuses a later rollback', async () => {
    const { server, a, seqOfB, hideB } = await lostReplyThenB();
    const status = await a.engine.sync();
    expect(status.state).toBe('synced');
    expect(checkpointSeq(a.engine)).toBe(seqOfB);
    expect(a.engine.items().map((i) => i.title)).toEqual(['B edit (e.g. a rotated password)']);
    // The commit was recognised as landed, not sent again.
    expect(server.currentSeq).toBe(seqOfB);
    // The server now hides B's commit: A notices.
    hideB();
    const after = await a.engine.sync();
    expect(after.state).toBe('integrity_error');
    expect(after.integrity).toBe('server_behind');
    expect(checkpointSeq(a.engine)).toBe(seqOfB);
  });

  it('holds across a restart with the lost commit still persisted as in flight', async () => {
    const { server, a, seqOfB, hideB } = await lostReplyThenB();
    // A is locked (the worker ends) and unlocked again: the in-flight commit comes from storage.
    a.engine.wipeMemory();
    const again = await device(server, a.factory);
    await again.engine.unlock({ password: PASSWORD });
    await again.engine.sync();
    expect(checkpointSeq(again.engine)).toBe(seqOfB);
    expect(server.currentSeq).toBe(seqOfB);
    hideB();
    expect((await again.engine.sync()).state).toBe('integrity_error');
  });

  it('refuses a reply for an older seq (replayed or reordered) and keeps its checkpoint', async () => {
    const { server, a } = await account();
    await a.engine.save({ draft: login('one') });
    await a.engine.sync();
    await a.engine.save({ draft: login('two') });
    await a.engine.sync();
    const verified = checkpointSeq(a.engine);
    // A server that applies the next commit but answers with an earlier commit's reply.
    const apply = server.applyCommit.bind(server);
    server.applyCommit = (body) => {
      apply(body);
      return { seq: verified - 1 };
    };
    await a.engine.save({ draft: login('three') });
    const status = await a.engine.sync();
    expect(status.state).toBe('integrity_error');
    expect(status.integrity).toBe('stale_commit_reply');
    expect(checkpointSeq(a.engine)).toBe(verified);
  });

  it('never lets the checkpoint decrease while syncs, saves and a lost reply interleave', async () => {
    const { server, a: first, b } = await lostReplyThenB();
    // The same device again, observed on every event it emits, inside each sync too.
    first.engine.wipeMemory();
    const seen: number[] = [];
    const watch = (engine: VaultEngine = a.engine) => {
      const s = (engine as unknown as { session?: { checkpoint: { seq: number } } }).session;
      if (s) seen.push(s.checkpoint.seq);
    };
    const a = await device(server, first.factory, watch);
    await a.engine.unlock({ password: PASSWORD });
    // Concurrent calls on A while B keeps committing; the engine serializes A's own.
    await Promise.all([
      a.engine.sync().then(() => {
        watch();
      }),
      a.engine.save({ draft: login('A new item') }).then(() => {
        watch();
      }),
      b.engine.save({ draft: login('B new item') }).then(() => b.engine.sync()),
      a.engine.sync().then(() => {
        watch();
      }),
    ]);
    await b.engine.sync();
    await a.engine.sync();
    watch();
    for (let i = 1; i < seen.length; i++)
      expect(seen[i] ?? 0).toBeGreaterThanOrEqual(seen[i - 1] ?? 0);
    expect(checkpointSeq(a.engine)).toBe(server.currentSeq);
    expect(
      a.engine
        .items()
        .map((i) => i.title)
        .sort(),
    ).toEqual(['A new item', 'B edit (e.g. a rotated password)', 'B new item'].sort());
  });
});

describe('REVIEW R6: recovery on an enrolled device erases its unsynced edits', () => {
  it('drops a pending edit without a warning (R6, vulnerable)', async () => {
    const { server, a, kit } = await account();
    await a.engine.save({ draft: login('Synced') });
    await a.engine.sync();
    server.offline = true;
    await a.engine.save({ draft: login('Pending, never uploaded') });
    await a.engine.idle();
    // Locked (the worker is terminated): the pending edit exists only in this browser's store.
    a.engine.wipeMemory();
    expect([...server.items.values()].filter((i) => i.record !== null)).toHaveLength(1);
    // Still offline: an offline unlock shows the pending edit is stored on this device.
    const before = await device(server, a.factory);
    expect((await before.engine.unlock({ password: PASSWORD })).sync.pendingCount).toBe(1);
    before.engine.wipeMemory();

    // Forgotten-password recovery on the same browser (lock screen → "Use your Recovery Kit").
    server.offline = false;
    const same = await device(server, a.factory);
    await same.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit });
    const newKit = await same.engine.recoverySetPassword({ password: 'synthetic recovered pw 77' });
    await same.engine.recoveryVerifyKit({ recoveryKey: newKit.recoveryKey });
    const done = await same.engine.recoveryFinish();
    expect(done.items.map((i) => i.title)).toEqual(['Synced']);
    expect(done.sync.pendingCount).toBe(0);
  });
});
