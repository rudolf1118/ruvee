// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { ConflictView, ItemDraft } from '../protocol.js';
import { DeviceStore } from '../store.js';
import { FakeServer, fakeOpaque } from '../test-support.js';
import { CONFLICT_LIMITS } from '../sync-logic.js';
import { VaultEngine, VaultError } from '../vault-engine.js';

/**
 * Follow-up review F-16 (owner-approved behaviour, 2026-10-28): repeated conflicts on one item
 * keep every local version; a resolution names the draft and the server revision it was decided
 * against, and is refused if either moved; storage is bounded, and reaching the bound pauses
 * sync without deleting anything. Synthetic data only.
 */

const PASSWORD = 'synthetic engine passphrase 4c1e';
let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

async function device(server: FakeServer, factory = new IDBFactory(), api = server.api()) {
  const store = await DeviceStore.open(factory);
  const engine = new VaultEngine({
    crypto,
    api,
    store,
    opaque: fakeOpaque,
    origin: 'http://127.0.0.1:3101',
    platform: 'web',
    now: () => Date.now(),
    emit: () => undefined,
  });
  return { engine, store, factory, api };
}
type Device = Awaited<ReturnType<typeof device>>;

const note = (title: string): ItemDraft => ({
  type: 'note',
  title,
  username: '',
  password: '',
  urls: [],
  notes: '',
  noteText: 'synthetic',
  tags: [],
  favorite: false,
});

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (error) {
    return error instanceof VaultError ? error.code : String(error);
  }
};

/** Device A with an account and one synced note X, and device B paired and synced. */
async function shared() {
  const server = new FakeServer();
  const a = await device(server);
  const kit = await a.engine.setupBegin({
    bootstrapToken: 'T'.repeat(43),
    username: 'Synthetic-User',
    password: PASSWORD,
  });
  await a.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
  await a.engine.setupFinish();
  const x = await a.engine.save({ draft: note('X') });
  await a.engine.sync();
  const b = await device(server);
  await b.engine.login({ username: 'synthetic-user', password: PASSWORD });
  const started = await a.engine.pairingStart();
  await b.engine.pairingJoin({ code: started.code });
  await a.engine.pairingStatus({ pairingId: started.pairingId });
  await b.engine.pairingWait();
  await a.engine.pairingApprove({ pairingId: started.pairingId });
  await b.engine.pairingWait();
  await b.engine.sync();
  return { server, a, b, id: x.id };
}

/** B edits X offline while A edits it and syncs first; B's sync then finds a conflict. */
async function conflictRound(
  server: FakeServer,
  a: Device,
  b: Device,
  id: string,
  mine: string,
  theirs: string,
) {
  server.offline = true;
  await b.engine.save({ draft: { ...note(mine), id } });
  await b.engine.idle();
  server.offline = false;
  await a.engine.sync();
  await a.engine.save({ draft: { ...note(theirs), id } });
  await a.engine.sync();
  return b.engine.sync();
}

/** Every draft of an item, oldest first, by resolving nothing: the views as the UI pages them. */
function draftsOf(b: Device, id: string): ConflictView {
  return b.engine.conflict({ id });
}

describe('F-16: repeated conflicts and their resolution', () => {
  it('a second conflict on the same item keeps the first draft', async () => {
    const { server, a, b, id } = await shared();
    await conflictRound(server, a, b, id, 'B first', 'A first');
    expect(draftsOf(b, id)).toMatchObject({ local: { title: 'B first' }, drafts: 1 });
    // While that conflict is open, B edits the item again and A changes it again.
    await conflictRound(server, a, b, id, 'B second', 'A second');
    const first = draftsOf(b, id);
    expect(first).toMatchObject({ local: { title: 'B first' }, drafts: 2 });
    expect(first.remote?.title).toBe('A second');
    // Resolving the first shows the second; neither was lost.
    await b.engine.resolveConflict({
      id,
      draftId: first.draftId,
      remoteRevision: first.remoteRevision,
      choice: 'theirs',
    });
    expect(draftsOf(b, id)).toMatchObject({ local: { title: 'B second' }, drafts: 1 });
  });

  it('drafts survive a lock and unlock', async () => {
    const { server, a, b, id } = await shared();
    await conflictRound(server, a, b, id, 'B first', 'A first');
    await conflictRound(server, a, b, id, 'B second', 'A second');
    b.engine.wipeMemory();
    const again = await device(server, b.factory, b.api);
    await again.engine.unlock({ password: PASSWORD });
    expect(draftsOf(again, id)).toMatchObject({ local: { title: 'B first' }, drafts: 2 });
    expect((await again.engine.localState()).conflicts).toBe(2);
  });

  it('a resolution decided against an older server version is refused, and nothing changes', async () => {
    const { server, a, b, id } = await shared();
    await conflictRound(server, a, b, id, 'B mine', 'A theirs');
    const shown = draftsOf(b, id);
    // The server changes again, and B pulls it before the user's click arrives.
    await a.engine.save({ draft: { ...note('A newer'), id } });
    await a.engine.sync();
    await b.engine.sync();
    const seq = server.currentSeq;
    expect(
      await code(
        b.engine.resolveConflict({
          id,
          draftId: shown.draftId,
          remoteRevision: shown.remoteRevision,
          choice: 'mine',
        }),
      ),
    ).toBe('conflict_changed');
    await b.engine.sync();
    expect(server.currentSeq).toBe(seq);
    // The draft is kept and the view now shows the newer version; deciding against it works.
    const now = draftsOf(b, id);
    expect(now).toMatchObject({ draftId: shown.draftId, local: { title: 'B mine' } });
    expect(now.remote?.title).toBe('A newer');
    expect(now.remoteRevision).toBe(shown.remoteRevision + 1);
    await b.engine.resolveConflict({
      id,
      draftId: now.draftId,
      remoteRevision: now.remoteRevision,
      choice: 'mine',
    });
    await b.engine.sync();
    await a.engine.sync();
    expect(a.engine.items().find((i) => i.id === id)?.title).toBe('B mine');
  });

  it('a server change after the resolution was queued returns to a conflict that keeps it', async () => {
    const { server, a, b, id } = await shared();
    await conflictRound(server, a, b, id, 'B mine', 'A theirs');
    const shown = draftsOf(b, id);
    server.offline = true;
    await b.engine.resolveConflict({
      id,
      draftId: shown.draftId,
      remoteRevision: shown.remoteRevision,
      choice: 'mine',
    });
    await b.engine.idle();
    server.offline = false;
    await a.engine.save({ draft: { ...note('A after the choice'), id } });
    await a.engine.sync();
    await b.engine.sync();
    // Not last-write-wins: the server keeps A's newer version, and B's choice is a draft again.
    const back = draftsOf(b, id);
    expect(back.local?.title).toBe('B mine');
    expect(back.remote?.title).toBe('A after the choice');
    await a.engine.sync();
    expect(a.engine.items().find((i) => i.id === id)?.title).toBe('A after the choice');
  });

  it('"keep this device\'s version" never replaces a newer unsynced edit of the item', async () => {
    const { server, a, b, id } = await shared();
    await conflictRound(server, a, b, id, 'B draft', 'A theirs');
    const shown = draftsOf(b, id);
    server.offline = true;
    await b.engine.save({ draft: { ...note('B later edit'), id } });
    expect(
      await code(
        b.engine.resolveConflict({
          id,
          draftId: shown.draftId,
          remoteRevision: shown.remoteRevision,
          choice: 'mine',
        }),
      ),
    ).toBe('conflict_pending_edit');
    await b.engine.idle();
    server.offline = false;
    await b.engine.sync();
    await a.engine.sync();
    // The later edit reached the server; the older draft is still there to decide on.
    expect(a.engine.items().find((i) => i.id === id)?.title).toBe('B later edit');
    expect(draftsOf(b, id)).toMatchObject({ draftId: shown.draftId, local: { title: 'B draft' } });
  });

  it('at the per-item bound, sync pauses and keeps the edit; resolving makes room', async () => {
    const { server, a, b, id } = await shared();
    for (let i = 0; i < CONFLICT_LIMITS.perItem; i++)
      await conflictRound(server, a, b, id, `B ${String(i)}`, `A ${String(i)}`);
    expect(draftsOf(b, id).drafts).toBe(CONFLICT_LIMITS.perItem);
    const full = await conflictRound(server, a, b, id, 'B over the bound', 'A over the bound');
    expect(full.state).toBe('conflicts_full');
    expect(full.pendingCount).toBe(1);
    expect(draftsOf(b, id).drafts).toBe(CONFLICT_LIMITS.perItem);
    // Nothing of B's reached the server, and nothing was dropped.
    await a.engine.sync();
    expect(a.engine.items().find((i) => i.id === id)?.title).toBe('A over the bound');
    // One resolution frees a slot: the held edit becomes a draft and sync resumes.
    const oldest = draftsOf(b, id);
    await b.engine.resolveConflict({
      id,
      draftId: oldest.draftId,
      remoteRevision: oldest.remoteRevision,
      choice: 'theirs',
    });
    const resumed = await b.engine.sync();
    expect(resumed.state).toBe('synced');
    expect(draftsOf(b, id).drafts).toBe(CONFLICT_LIMITS.perItem);
    let last = draftsOf(b, id);
    for (let i = 1; i < CONFLICT_LIMITS.perItem; i++) {
      await b.engine.resolveConflict({
        id,
        draftId: last.draftId,
        remoteRevision: last.remoteRevision,
        choice: 'theirs',
      });
      last = draftsOf(b, id);
    }
    expect(last.local?.title).toBe('B over the bound');
  });
});
