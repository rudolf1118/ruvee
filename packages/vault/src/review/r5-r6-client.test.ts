// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { ItemDraft } from '../protocol.js';
import { DeviceStore } from '../store.js';
import { FakeServer, fakeOpaque } from '../test-support.js';
import { VaultEngine } from '../vault-engine.js';

/**
 * Pre-deployment review, findings R5 and R6 (docs/security/predeployment-review.md). These tests
 * describe the CURRENT behaviour and are expected to fail once the findings are fixed.
 */

const PASSWORD = 'synthetic engine passphrase 4c1e';
let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

async function device(server: FakeServer, factory = new IDBFactory()) {
  const store = await DeviceStore.open(factory);
  const engine = new VaultEngine({
    crypto,
    api: server.api(),
    store,
    opaque: fakeOpaque,
    origin: 'http://127.0.0.1:3101',
    platform: 'web',
    now: () => Date.now(),
    emit: () => undefined,
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

describe('REVIEW R5: a replayed commit reply lowers the checkpoint', () => {
  it('lets a server roll a device back below a seq it already verified (R5, vulnerable)', async () => {
    const { server, a } = await account();
    const b = await paired(server, a);
    const item = await a.engine.save({ draft: login('v1') });
    await a.engine.sync();
    await b.engine.sync();

    // The server applies A's next commit but drops the reply (a reset connection).
    const apply = server.applyCommit.bind(server);
    let drop = true;
    server.applyCommit = (body) => {
      const result = apply(body);
      if (drop) {
        drop = false;
        throw new Error('connection reset');
      }
      return result;
    };
    await a.engine.save({ draft: { ...login('A edit'), id: item.id } });
    await a.engine.idle();
    const seqOfA = server.currentSeq;
    const itemsAtA = structuredClone(server.items);
    const manifestsAtA = structuredClone(server.manifests);

    // B commits on top of A's commit.
    await b.engine.sync();
    await b.engine.save({ draft: { ...login('B edit (e.g. a rotated password)'), id: item.id } });
    await b.engine.sync();
    const seqOfB = server.currentSeq;
    expect(seqOfB).toBe(seqOfA + 1);

    // A syncs: its pull verifies B's commit, then the retried commit's replayed reply
    // (`{ seq: seqOfA }`) is taken as the new checkpoint.
    await a.engine.sync();
    expect(checkpointSeq(a.engine)).toBe(seqOfA);
    expect(a.engine.items().map((i) => i.title)).toEqual(['A edit']);

    // The server now hides B's commit. A accepts it: no integrity error.
    server.manifests = manifestsAtA;
    server.items = itemsAtA;
    const status = await a.engine.sync();
    expect(status.state).toBe('synced');
    expect(status.integrity).toBeUndefined();
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
