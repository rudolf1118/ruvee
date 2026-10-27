// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { ItemDraft } from '../protocol.js';
import { DeviceStore } from '../store.js';
import { FakeServer, fakeOpaque } from '../test-support.js';
import { VaultEngine, VaultError } from '../vault-engine.js';

/**
 * Accounts from before D-31 (docs/security/device-proof.md §9, owner decision of 2026-10-27):
 * nothing establishes their `AVPK`, neither recovery nor reopening, and their data moves to a
 * fresh account by local export and import. The fake server applies the API's rule. Synthetic
 * data only.
 */

const PASSWORD = 'synthetic engine passphrase 4c1e';
const CODE = `RC1-${'C'.repeat(43)}`;
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

async function setUp(server: FakeServer, username: string) {
  const d = await device(server);
  const kit = await d.engine.setupBegin({
    bootstrapToken: 'T'.repeat(43),
    username,
    password: PASSWORD,
  });
  await d.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
  await d.engine.setupFinish();
  return { d, kit: kit.recoveryKey };
}

/**
 * A pre-D-31 account as the development migration left it: no `AVPK`, no device key on either
 * side. Device A holds two verified items, an unresolved conflict and two edits never uploaded.
 */
async function legacyAccount() {
  const server = new FakeServer();
  const { d: a, kit } = await setUp(server, 'Synthetic-User');
  const shared = await a.engine.save({ draft: note('Shared') });
  const kept = await a.engine.save({ draft: note('Kept') });
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
  // A conflict on A: B's edit reaches the server first.
  server.offline = true;
  await a.engine.save({ draft: { ...note('Shared (A draft)'), id: shared.id } });
  await a.engine.idle();
  server.offline = false;
  await b.engine.save({ draft: { ...note('Shared (B)'), id: shared.id } });
  await b.engine.sync();
  await a.engine.sync();
  // Two edits the server never sees.
  server.offline = true;
  await a.engine.save({ draft: note('New on A') });
  await a.engine.save({ draft: { ...note('Kept (edited)'), id: kept.id } });
  await a.engine.idle();
  a.engine.wipeMemory();
  b.engine.wipeMemory();
  server.offline = false;
  server.devicePublicKeys.clear();
  server.akVerifyKey = undefined;
  await a.store.apply({ local: { 'device-key': null } });
  await b.store.apply({ local: { 'device-key': null } });
  server.sessionValid = false;
  return { server, a, kit };
}

/** What a legacy device must still hold after anything this file tries. */
async function localCopy(server: FakeServer, factory: IDBFactory) {
  const d = await device(server, factory);
  const view = await d.engine.unlock({ password: PASSWORD });
  const state = await d.engine.localState();
  d.engine.wipeMemory();
  return {
    problem: view.sessionProblem,
    titles: view.items.map((i) => i.title).sort(),
    pending: state.pending,
    conflicts: state.conflicts,
    seq: state.snapshot.seq,
  };
}

const EXPECTED_LOCAL = {
  problem: 'migration_required',
  titles: ['Kept (edited)', 'New on A', 'Shared (B)'],
  pending: 2,
  conflicts: 1,
};

describe('pre-D-31 accounts never establish a trust anchor (device-proof.md §9)', () => {
  it('unlocks offline with every local change and reports migration, not re-enrollment', async () => {
    const { server, a } = await legacyAccount();
    expect(await localCopy(server, a.factory)).toMatchObject(EXPECTED_LOCAL);
    // Still usable offline: an edit is kept locally.
    const d = await device(server, a.factory);
    await d.engine.unlock({ password: PASSWORD });
    await d.engine.save({ draft: note('Offline after migration notice') });
    expect((await d.engine.localState()).pending).toBe(3);
  });

  it('recovery on this browser is refused and changes nothing, on the server or here', async () => {
    const { server, a, kit } = await legacyAccount();
    const before = server.snapshot();
    const d = await device(server, a.factory);
    expect(
      await code(d.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit })),
    ).toBe('migration_required');
    expect(server.akVerifyKey).toBeUndefined();
    expect(server.devicePublicKeys.size).toBe(0);
    expect(server.snapshot()).toEqual(before);
    // The kit was not rotated: the same kit gives the same answer, not recovery_failed.
    const again = await device(server, a.factory);
    expect(
      await code(again.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit })),
    ).toBe('migration_required');
    expect(await localCopy(server, a.factory)).toMatchObject(EXPECTED_LOCAL);
  });

  it('recovery on a fresh browser is refused before a device or session exists', async () => {
    const { server, kit } = await legacyAccount();
    const devices = [...server.devices.keys()].sort();
    const fresh = await device(server);
    expect(
      await code(fresh.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit })),
    ).toBe('migration_required');
    expect([...server.devices.keys()].sort()).toEqual(devices);
    expect(server.akVerifyKey).toBeUndefined();
  });

  it('a restored legacy snapshot cannot be reopened by either path', async () => {
    const { server, a, kit } = await legacyAccount();
    server.restoreReopening(server.snapshot(), '11111111-1111-4111-8111-111111111111', CODE);
    const fresh = await device(server);
    expect(
      await code(
        fresh.engine.recoveryBegin({
          username: 'synthetic-user',
          recoveryKey: kit,
          reopenCode: CODE,
        }),
      ),
    ).toBe('migration_required');
    // The code was not spent on a reopening that cannot finish.
    expect(server.reopenCode).toBe(CODE);
    const old = await device(server, a.factory);
    await old.engine.unlock({ password: PASSWORD });
    expect(await code(old.engine.reopenBegin({ reopenCode: CODE, password: PASSWORD }))).not.toBe(
      'ok',
    );
    expect(await code(old.engine.recoveryFinish())).not.toBe('ok');
    expect(server.akVerifyKey).toBeUndefined();
    expect(server.devicePublicKeys.size).toBe(0);
  });
});

describe('moving a legacy vault to a fresh D-31 account', () => {
  it("keeping this device's conflict draft works offline and stays listed for the move", async () => {
    const { server, a } = await legacyAccount();
    const d = await device(server, a.factory);
    await d.engine.unlock({ password: PASSWORD });
    const [conflict] = (await d.engine.migrationReport()).conflicts;
    await d.engine.resolveConflict({ id: conflict?.id ?? '', choice: 'mine' });
    const report = await d.engine.migrationReport();
    expect(report.conflicts).toEqual([]);
    expect(report.changes.map((c) => [c.title, c.change]).sort()).toEqual([
      ['Kept (edited)', 'edited'],
      ['New on A', 'created'],
      ['Shared (A draft)', 'edited'],
    ]);
    expect(d.engine.items().map((i) => i.title)).toContain('Shared (A draft)');
    expect(server.akVerifyKey).toBeUndefined();
  });

  it('names every change no export holds, exports offline, and imports under new keys', async () => {
    const { server, a, kit } = await legacyAccount();
    const sourceServer = server.snapshot();
    const old = await device(server, a.factory);
    await old.engine.unlock({ password: PASSWORD });

    const report = await old.engine.migrationReport();
    expect(report.snapshot.items).toBe(2);
    expect(report.changes.map((c) => [c.title, c.change]).sort()).toEqual([
      ['Kept (edited)', 'edited'],
      ['New on A', 'created'],
    ]);
    expect(report.conflicts.map((c) => [c.title, c.kind, c.localDeleted])).toEqual([
      ['Shared (A draft)', expect.any(String), false],
    ]);
    expect(report.exported).toBe(false);
    // No secret field travels with the report.
    expect(JSON.stringify(report)).not.toContain('synthetic');

    // The verified copy, made with no server, only after the omissions are acknowledged.
    expect(await code(old.engine.exportLocal({ password: PASSWORD, recoveryKey: kit }))).toBe(
      'unsynced_changes',
    );
    const file = await old.engine.exportLocal({
      password: PASSWORD,
      recoveryKey: kit,
      acknowledgeNotIncluded: true,
    });
    expect(file.notIncluded).toEqual({ pending: 2, conflicts: 1 });
    expect((await old.engine.migrationReport()).exported).toBe(true);
    old.engine.wipeMemory();

    // A separate installation: its own server, a clean browser, a D-31 bootstrap.
    const target = new FakeServer();
    const { d: fresh, kit: newKit } = await setUp(target, 'Synthetic-New-User');
    const avpk = target.akVerifyKey;
    expect(avpk).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect([...target.devicePublicKeys.keys()]).toHaveLength(1);
    const opened = fresh.engine.exportOpen({ text: file.text, recoveryKey: kit });
    expect(opened.items.map((i) => i.title).sort()).toEqual(['Kept', 'Shared (B)']);
    const status = await fresh.engine.importIntoEmptyVault();
    expect(status.import?.state).toBe('complete');
    expect(
      fresh.engine
        .items()
        .map((i) => i.title)
        .sort(),
    ).toEqual(['Kept', 'Shared (B)']);
    // Re-encrypted: nothing of the old account's records or ids reached the new server.
    const oldIds = new Set(sourceServer.items.keys());
    expect([...target.items.keys()].some((id) => oldIds.has(id))).toBe(false);

    // The new account's kit works and keeps the AVPK its bootstrap registered.
    fresh.engine.wipeMemory();
    const check = await device(target);
    await check.engine.recoveryBegin({ username: 'synthetic-new-user', recoveryKey: newKit });
    const rotated = await check.engine.recoverySetPassword({ password: PASSWORD });
    await check.engine.recoveryVerifyKit({ recoveryKey: rotated.recoveryKey });
    const recovered = await check.engine.recoveryFinish();
    expect(recovered.items.map((i) => i.title).sort()).toEqual(['Kept', 'Shared (B)']);
    expect(target.akVerifyKey).toBe(avpk);

    // The source is untouched: its server state, and every local change on the old browser.
    expect(server.snapshot()).toEqual(sourceServer);
    expect(await localCopy(server, a.factory)).toMatchObject(EXPECTED_LOCAL);
  });
});
