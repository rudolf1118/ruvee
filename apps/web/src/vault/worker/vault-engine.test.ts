// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { ItemDraft, VaultEvent } from '../protocol';
import { DeviceStore, STORES } from './store';
import { FakeServer, fakeOpaque } from './test-support';
import { VaultEngine, VaultError } from './vault-engine';

const PASSWORD = 'synthetic engine passphrase 4c1e';
const TOKEN = 'T'.repeat(43);

let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

interface Device {
  engine: VaultEngine;
  store: DeviceStore;
  factory: IDBFactory;
  events: VaultEvent[];
}

async function device(server: FakeServer, factory = new IDBFactory()): Promise<Device> {
  const store = await DeviceStore.open(factory);
  const events: VaultEvent[] = [];
  const engine = new VaultEngine({
    crypto,
    api: server.api(),
    store,
    opaque: fakeOpaque,
    origin: 'http://127.0.0.1:3101',
    now: () => Date.now(),
    emit: (e) => events.push(e),
  });
  return { engine, store, factory, events };
}

const login = (title: string, password = 'synthetic-item-secret'): ItemDraft => ({
  type: 'login',
  title,
  username: 'someone@mail.example',
  password,
  urls: ['https://mail.example'],
  notes: '',
  noteText: '',
  tags: ['work'],
  favorite: false,
});

async function code(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return 'resolved';
  } catch (e) {
    return e instanceof VaultError ? e.code : String(e);
  }
}

async function createAccount(server: FakeServer): Promise<{ a: Device; kit: string }> {
  const a = await device(server);
  const kit = await a.engine.setupBegin({
    bootstrapToken: TOKEN,
    username: 'Synthetic-User',
    password: PASSWORD,
  });
  await a.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
  await a.engine.setupFinish();
  await a.engine.phase();
  return { a, kit: kit.recoveryKey };
}

/** A second browser: logs in (pending), then is paired from `from` (device-enrollment §3). */
async function secondDevice(server: FakeServer, from: Device): Promise<Device> {
  const b = await device(server);
  expect(await b.engine.login({ username: 'synthetic-user', password: PASSWORD })).toMatchObject({
    phase: 'pending',
  });
  const started = await from.engine.pairingStart();
  await b.engine.pairingJoin({ code: started.code });
  expect(await from.engine.pairingStatus({ pairingId: started.pairingId })).toMatchObject({
    state: 'request',
    platform: 'web',
  });
  expect(await b.engine.pairingWait()).toEqual({ state: 'waiting' });
  await from.engine.pairingApprove({ pairingId: started.pairingId });
  const joined = await b.engine.pairingWait();
  expect(joined.state).toBe('enrolled');
  return b;
}

describe('vault engine', () => {
  it('requires the Recovery Kit to be typed back before the account is created', async () => {
    const server = new FakeServer();
    const a = await device(server);
    expect(
      await code(a.engine.setupBegin({ bootstrapToken: TOKEN, username: 'u', password: 'short' })),
    ).toBe('invalid_password');
    const kit = await a.engine.setupBegin({
      bootstrapToken: TOKEN,
      username: 'Synthetic-User',
      password: PASSWORD,
    });
    expect(kit.recoveryKey).toMatch(/^RK1-/);
    expect(kit.username).toBe('synthetic-user');
    expect(await code(a.engine.setupFinish())).toBe('kit_mismatch');
    expect(await code(a.engine.setupVerifyKit({ recoveryKey: 'RK1-00000-00000' }))).toBe(
      'invalid_recovery_key',
    );
    const other = crypto.formatRecoveryKey(crypto.generateRecoveryKey().recoveryKey);
    expect(await code(a.engine.setupVerifyKit({ recoveryKey: other }))).toBe('kit_mismatch');
    expect(server.account).toBeUndefined();
    await a.engine.setupVerifyKit({
      recoveryKey: kit.recoveryKey.toLowerCase().replace(/-/g, ' '),
    });
    const vault = await a.engine.setupFinish();
    expect(vault.sync.state).toBe('synced');
    // The genesis manifest is committed straight away.
    expect(server.currentSeq).toBe(1);
    expect(await a.engine.phase()).toMatchObject({ phase: 'enrolled', username: 'synthetic-user' });
  });

  it('stores items as ciphertext only, and keeps the password in the worker until asked', async () => {
    const server = new FakeServer();
    const { a, kit } = await createAccount(server);
    const saved = await a.engine.save({ draft: login('Synthetic Mail', 'synthetic-pw-marker-91') });
    await a.engine.sync();
    expect(server.currentSeq).toBe(2);
    const detail = a.engine.detail({ id: saved.id });
    expect(detail).toMatchObject({
      title: 'Synthetic Mail',
      username: 'someone@mail.example',
      hasPassword: true,
    });
    expect(JSON.stringify(detail)).not.toContain('synthetic-pw-marker-91');
    expect(a.engine.secret({ id: saved.id })).toBe('synthetic-pw-marker-91');

    // INV-01: nothing the server received contains the password, the item or the kit.
    const sent = server.received.join('\n');
    for (const secret of [
      PASSWORD,
      'synthetic-pw-marker-91',
      'Synthetic Mail',
      kit,
      kit.replace(/-/g, ''),
    ])
      expect(sent).not.toContain(secret);

    // INV-16: the device store holds no plaintext.
    const dump: string[] = [];
    for (const name of STORES) {
      const db = await new Promise<IDBDatabase>((resolve) => {
        const req = a.factory.open('ruvee');
        req.onsuccess = () => {
          resolve(req.result);
        };
      });
      const all = await new Promise<unknown[]>((resolve) => {
        const req = db.transaction(name).objectStore(name).getAll();
        req.onsuccess = () => {
          resolve(req.result);
        };
      });
      db.close();
      dump.push(
        JSON.stringify(all, (_k, v: unknown) =>
          v instanceof Uint8Array ? new TextDecoder('latin1').decode(v) : v,
        ),
      );
    }
    for (const plaintext of [
      'synthetic-pw-marker-91',
      'Synthetic Mail',
      'someone@mail.example',
      PASSWORD,
    ])
      expect(dump.join('\n')).not.toContain(plaintext);
  });

  it('unlocks offline with the password, and refuses a wrong one', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    await a.engine.save({ draft: login('Offline item') });
    await a.engine.sync();
    const again = await device(server, a.factory);
    await again.engine.phase();
    expect(await code(again.engine.unlock({ password: 'synthetic wrong passphrase' }))).toBe(
      'wrong_password',
    );
    server.offline = true;
    const unlocked = await again.engine.unlock({ password: PASSWORD });
    expect(unlocked.sessionProblem).toBe('offline');
    expect(unlocked.items.map((i) => i.title)).toEqual(['Offline item']);
    // Edits made offline wait in the encrypted queue and upload on reconnect.
    await again.engine.save({ draft: login('Written offline') });
    await again.engine.idle();
    expect((await again.engine.sync()).state).toBe('offline');
    server.offline = false;
    const status = await again.engine.sync();
    expect(status).toMatchObject({ state: 'synced', pendingCount: 0 });
    expect(server.currentSeq).toBe(3);
  });

  it('syncs between two devices and turns concurrent edits into an explicit conflict', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const item = await a.engine.save({ draft: login('Shared') });
    await a.engine.sync();
    const b = await secondDevice(server, a);
    const unlockedB = await b.engine.unlock({ password: PASSWORD });
    expect(unlockedB.items.map((i) => i.title)).toEqual(['Shared']);

    // Both edit the same item while offline; A reconnects first.
    server.offline = true;
    await a.engine.save({ draft: { ...login('Shared (A)'), id: item.id } });
    await b.engine.save({ draft: { ...login('Shared (B)'), id: item.id } });
    await Promise.all([a.engine.idle(), b.engine.idle()]);
    server.offline = false;
    await a.engine.sync();
    const statusB = await b.engine.sync();
    expect(statusB.state).toBe('synced');
    const conflicted = b.engine.items().find((i) => i.id === item.id);
    expect(conflicted).toMatchObject({ title: 'Shared (A)', conflict: 'edited_on_both' });
    const view = b.engine.conflict({ id: item.id });
    expect(view.local?.title).toBe('Shared (B)');
    expect(view.remote?.title).toBe('Shared (A)');

    await b.engine.resolveConflict({ id: item.id, choice: 'both' });
    await b.engine.sync();
    await a.engine.sync();
    expect(
      a.engine
        .items()
        .map((i) => i.title)
        .sort(),
    ).toEqual(['Shared (A)', 'Shared (B) (this device)']);
    expect(b.engine.items().every((i) => i.conflict === null)).toBe(true);
  });

  it('reports an edit of an item that was deleted on another device', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const item = await a.engine.save({ draft: login('Doomed') });
    await a.engine.sync();
    const b = await secondDevice(server, a);
    await b.engine.unlock({ password: PASSWORD });
    await a.engine.trash({ id: item.id });
    await a.engine.purge({ id: item.id });
    await a.engine.sync();
    server.offline = true;
    await b.engine.save({ draft: { ...login('Doomed, edited'), id: item.id } });
    await b.engine.idle();
    server.offline = false;
    await b.engine.sync();
    expect(b.engine.conflict({ id: item.id }).kind).toBe('deleted_elsewhere');
    await b.engine.resolveConflict({ id: item.id, choice: 'mine' });
    await b.engine.sync();
    await a.engine.sync();
    // Restored as a new item: tombstoned ids are never reused.
    const titles = a.engine.items().map((i) => [i.id === item.id, i.title]);
    expect(titles).toEqual([[false, 'Doomed, edited']]);
  });

  it('recognises its own commit after a lost response, without a conflict', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const item = await a.engine.save({ draft: login('Lost reply') });
    await a.engine.sync();
    let dropped = false;
    // The server applies the commit, but the response never arrives.
    const original = server.applyCommit.bind(server);
    server.applyCommit = (body) => {
      const result = original(body);
      if (!dropped) {
        dropped = true;
        throw new Error('connection reset after the commit was applied');
      }
      return result;
    };
    await a.engine.save({ draft: { ...login('Lost reply, v2'), id: item.id } });
    await a.engine.sync();
    await a.engine.save({ draft: { ...login('Lost reply, v3'), id: item.id } });
    const status = await a.engine.sync();
    expect(status.state).toBe('synced');
    expect(a.engine.items()).toMatchObject([{ title: 'Lost reply, v3', conflict: null }]);
  });

  it('stops and goes read-only when the server rolls back a record', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const item = await a.engine.save({ draft: login('Version 1') });
    await a.engine.sync();
    const b = await secondDevice(server, a);
    await b.engine.unlock({ password: PASSWORD });
    const v1 = server.items.get(item.id)?.record ?? null;
    await a.engine.save({ draft: { ...login('Version 2'), id: item.id } });
    await a.engine.sync();
    // The server serves the old record under the new revision number.
    server.replaceRecord(item.id, v1, 2);
    const status = await b.engine.sync();
    expect(status.state).toBe('integrity_error');
    expect(b.engine.items().map((i) => i.title)).toEqual(['Version 1']);
    expect(await code(b.engine.save({ draft: login('Blocked') }))).toBe('read_only');
  });

  it('moves items to Trash and back, and deletes permanently only from Trash', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const item = await a.engine.save({ draft: login('Binned') });
    expect(await code(a.engine.purge({ id: item.id }))).toBe('invalid_item');
    expect((await a.engine.trash({ id: item.id })).trashed).toBe(true);
    expect((await a.engine.restore({ id: item.id })).trashed).toBe(false);
    await a.engine.trash({ id: item.id });
    await a.engine.sync();
    await a.engine.purge({ id: item.id });
    await a.engine.sync();
    expect(a.engine.items()).toEqual([]);
    // Each change was committed by the background sync: create, trash, restore, trash, delete.
    expect(server.items.get(item.id)).toMatchObject({ record: null, revision: 5 });
  });

  it('pairs a second device that then unlocks offline with the same password', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    await a.engine.save({ draft: login('Before pairing') });
    await a.engine.sync();
    const b = await secondDevice(server, a);
    expect(b.engine.items().map((i) => i.title)).toEqual(['Before pairing']);
    expect(await b.engine.phase()).toMatchObject({ phase: 'enrolled' });
    // The pairing is complete on the server and nothing about it remains.
    expect(server.pairings.size).toBe(0);
    // The new device has its own SK copy and checkpoint: it unlocks without the server.
    const again = await device(server, b.factory);
    server.offline = true;
    expect((await again.engine.unlock({ password: PASSWORD })).items.map((i) => i.title)).toEqual([
      'Before pairing',
    ]);
  });

  it('burns a pairing whose request MAC does not verify, and refuses a reused or mistyped code', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const b = await device(server);
    await b.engine.login({ username: 'synthetic-user', password: PASSWORD });
    const started = await a.engine.pairingStart();
    expect(await code(b.engine.pairingJoin({ code: `${started.code.slice(0, -1)}0` }))).toMatch(
      /invalid_pairing_code|pairing_expired/,
    );
    await b.engine.pairingJoin({ code: started.code });
    // A malicious server swaps B's ephemeral key for its own (device-enrollment §3.3).
    const relayed = server.pairings.get(started.pairingId);
    if (!relayed) throw new Error('no pairing');
    relayed.epk = 'B'.repeat(43);
    expect(await a.engine.pairingStatus({ pairingId: started.pairingId })).toEqual({
      state: 'failed',
    });
    expect(server.pairings.has(started.pairingId)).toBe(false);
    expect(await code(a.engine.pairingApprove({ pairingId: started.pairingId }))).toBe(
      'pairing_expired',
    );

    // One request per pairing: a second device with the same code is refused.
    const second = await a.engine.pairingStart();
    await b.engine.pairingJoin({ code: second.code });
    const c = await device(server);
    await c.engine.login({ username: 'synthetic-user', password: PASSWORD });
    expect(await code(c.engine.pairingJoin({ code: second.code }))).toBe('pairing_used');
  });

  it('discards a forged reply and stores nothing', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const b = await device(server);
    await b.engine.login({ username: 'synthetic-user', password: PASSWORD });
    const started = await a.engine.pairingStart();
    await b.engine.pairingJoin({ code: started.code });
    await a.engine.pairingStatus({ pairingId: started.pairingId });
    await a.engine.pairingApprove({ pairingId: started.pairingId });
    const relayed = server.pairings.get(started.pairingId);
    if (!relayed?.responseMac) throw new Error('no reply');
    relayed.responseMac = `A${relayed.responseMac.slice(1)}`;
    expect(await code(b.engine.pairingWait())).toBe('pairing_failed');
    expect(await b.engine.phase()).toMatchObject({ phase: 'pending' });
    expect((await b.store.device())?.enrolled).toBeUndefined();
  });

  it('ends the unlocked session when the server session expires', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    server.sessionValid = false;
    const status = await a.engine.sync();
    expect(status.state).toBe('session_expired');
    expect(a.events).toContainEqual({ event: 'ended', reason: 'session_expired' });
  });
});
