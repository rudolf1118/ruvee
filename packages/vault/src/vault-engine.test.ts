// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { ItemDraft, VaultEvent } from './protocol.js';
import type { Api } from './api.js';
import { DeviceStore, STORES } from './store.js';
import { FakeServer, fakeOpaque } from './test-support.js';
import { VaultEngine, VaultError } from './vault-engine.js';

const PASSWORD = 'synthetic engine passphrase 4c1e';
const TOKEN = 'T'.repeat(43);

let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

interface Device {
  engine: VaultEngine;
  /** The device's cookie jar: reuse it to model the same browser after a restart. */
  api: Api;
  store: DeviceStore;
  factory: IDBFactory;
  events: VaultEvent[];
}

async function device(
  server: FakeServer,
  factory = new IDBFactory(),
  api = server.api(),
): Promise<Device> {
  const store = await DeviceStore.open(factory);
  const events: VaultEvent[] = [];
  const engine = new VaultEngine({
    crypto,
    api,
    store,
    opaque: fakeOpaque,
    origin: 'http://127.0.0.1:3101',
    platform: 'web',
    now: () => Date.now(),
    emit: (e) => events.push(e),
  });
  return { engine, api, store, factory, events };
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
    // The same browser after a restart: same IndexedDB, same session cookie.
    const again = await device(server, a.factory, a.api);
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
    // A mistyped last character, always different from the real one.
    const typo = `${started.code.slice(0, -1)}${started.code.endsWith('0') ? '1' : '0'}`;
    expect(await code(b.engine.pairingJoin({ code: typo }))).toMatch(
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
    // Always a different first character (a fixed 'A' would leave 1 in 64 MACs unchanged).
    relayed.responseMac = `${relayed.responseMac.startsWith('A') ? 'B' : 'A'}${relayed.responseMac.slice(1)}`;
    expect(await code(b.engine.pairingWait())).toBe('pairing_failed');
    expect(await b.engine.phase()).toMatchObject({ phase: 'pending' });
    expect((await b.store.device())?.enrolled).toBeUndefined();
  });

  it('recovers on a new device with the Recovery Kit, rotating the kit and moving other devices over', async () => {
    const server = new FakeServer();
    const { a, kit } = await createAccount(server);
    await a.engine.save({ draft: login('Before recovery') });
    await a.engine.sync();

    const c = await device(server);
    expect(
      await code(c.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: 'RK1-00000' })),
    ).toBe('invalid_recovery_key');
    const other = crypto.formatRecoveryKey(crypto.generateRecoveryKey().recoveryKey);
    expect(
      await code(c.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: other })),
    ).toBe('recovery_failed');
    await c.engine.recoveryBegin({ username: 'Synthetic-User', recoveryKey: kit });
    const NEW = 'synthetic recovered passphrase 61aa';
    const rotated = await c.engine.recoverySetPassword({ password: NEW });
    expect(rotated.recoveryKey).not.toBe(kit);
    expect(await code(c.engine.recoveryFinish())).toBe('kit_mismatch');
    expect(await code(c.engine.recoveryVerifyKit({ recoveryKey: kit }))).toBe('kit_mismatch');
    await c.engine.recoveryVerifyKit({ recoveryKey: rotated.recoveryKey });
    const recovered = await c.engine.recoveryFinish();
    expect(recovered.items.map((i) => i.title)).toEqual(['Before recovery']);
    expect(recovered.recovered).toBeDefined();
    // This device ran the recovery, so it shows no notice about it.
    expect(recovered.sync.recoveryUsedAtMs).toBeUndefined();

    // The old kit no longer works; the new one would.
    const d = await device(server);
    expect(
      await code(d.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit })),
    ).toBe('recovery_failed');

    // Device A: its session ended. The old password still opens its local copy offline, and the
    // new password moves it to the new wrap once it reaches the server (authentication §9).
    expect((await a.engine.sync()).state).toBe('session_expired');
    const again = await device(server, a.factory);
    const offline = await again.engine.unlock({ password: PASSWORD });
    expect(offline.sessionProblem).toBeDefined();
    const updated = await (await device(server, a.factory)).engine.unlock({ password: NEW });
    expect(updated.passwordUpdated).toBe(true);
    expect(updated.items.map((i) => i.title)).toEqual(['Before recovery']);
    expect(updated.sync.recoveryUsedAtMs).toEqual(expect.any(Number));
    const afterUpdate = await device(server, a.factory);
    expect((await afterUpdate.engine.unlock({ password: NEW })).passwordUpdated).toBeUndefined();
    expect(
      await code(
        (await device(server, a.factory)).engine.unlock({ password: 'synthetic wrong passphrase' }),
      ),
    ).toBe('wrong_password');
    await afterUpdate.engine.acknowledgeRecoveryNotice();
    expect((await afterUpdate.engine.sync()).recoveryUsedAtMs).toBeUndefined();
  });

  it('revokes another device after step-up; the revoked device wipes itself', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const b = await secondDevice(server, a);
    const bId = (await b.engine.phase()) as { deviceId: string };
    const listed = await a.engine.devices();
    expect(listed.map((d) => d.current)).toEqual([true, false]);
    const self = listed[0]?.id ?? '';
    expect(
      await code(a.engine.revokeDevice({ deviceId: self, reason: 'retired', password: PASSWORD })),
    ).toBe('cannot_revoke_current');
    expect(
      await code(
        a.engine.revokeDevice({
          deviceId: bId.deviceId,
          reason: 'lost',
          password: 'synthetic wrong',
        }),
      ),
    ).toBe('wrong_password');
    expect(server.devices.get(bId.deviceId)).toBe('active');
    expect(
      await a.engine.revokeDevice({ deviceId: bId.deviceId, reason: 'lost', password: PASSWORD }),
    ).toEqual({ secretKeyRotated: true });
    expect(server.revokeReasons).toEqual(['lost']);
    // Revoking as lost rotates SK in the same step-up (D-24).
    expect(server.account?.keys.keysetVersion).toBe(2);
    expect(await code(b.engine.sync())).toBe('device_revoked');
    expect(b.events).toContainEqual({ event: 'ended', reason: 'device_revoked' });
    expect(await b.store.device()).toBeUndefined();
  });

  it('changes the password: the same AK under a new wrap, here and on the other device', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const b = await secondDevice(server, a);
    await a.engine.save({ draft: login('Kept across the change') });
    await a.engine.sync();
    const NEW = 'synthetic changed passphrase 77b2';
    expect(
      await code(a.engine.changePassword({ currentPassword: PASSWORD, newPassword: 'short' })),
    ).toBe('invalid_password');
    expect(
      await code(
        a.engine.changePassword({ currentPassword: 'synthetic wrong guess', newPassword: NEW }),
      ),
    ).toBe('wrong_password');
    await a.engine.changePassword({ currentPassword: PASSWORD, newPassword: NEW });
    // This session continues; the local wrap now opens with the new password only.
    expect((await a.engine.sync()).state).toBe('synced');
    expect(
      await code((await device(server, a.factory)).engine.unlock({ password: PASSWORD })),
    ).toBe('wrong_password');
    const reopened = await (await device(server, a.factory)).engine.unlock({ password: NEW });
    expect(reopened.passwordUpdated).toBeUndefined();
    expect(reopened.items.map((i) => i.title)).toEqual(['Kept across the change']);
    // Device B's session ended; online with the new password it moves to the new wrap.
    expect((await b.engine.sync()).state).toBe('session_expired');
    const bAgain = await (await device(server, b.factory, b.api)).engine.unlock({ password: NEW });
    expect(bAgain.passwordUpdated).toBe(true);
    expect(bAgain.items.map((i) => i.title)).toEqual(['Kept across the change']);
  });

  it('rotates SK; another device adopts it at its next online unlock (D-24)', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const b = await secondDevice(server, a);
    await a.engine.save({ draft: login('Survives the rotation') });
    await a.engine.sync();
    const skOf = async (d: Device) => (await d.store.device())?.enrolled?.secretKey.slice();
    const oldSk = await skOf(a);
    expect(await code(a.engine.rotateSecretKey({ password: 'synthetic wrong guess' }))).toBe(
      'wrong_password',
    );
    await a.engine.rotateSecretKey({ password: PASSWORD });
    const newSk = await skOf(a);
    expect(newSk).toBeDefined();
    expect(Buffer.from(newSk ?? []).equals(Buffer.from(oldSk ?? []))).toBe(false);
    expect(server.account?.keys.keysetVersion).toBe(2);
    // A unlocks with the same password under the new SK.
    const aAgain = await (
      await device(server, a.factory, a.api)
    ).engine.unlock({
      password: PASSWORD,
    });
    expect(aAgain.secretKeyUpdated).toBeUndefined();

    // B still holds the old SK; its online unlock reads the new keyset and re-wraps locally.
    expect(Buffer.from((await skOf(b)) ?? []).equals(Buffer.from(oldSk ?? []))).toBe(true);
    const bAgain = await (
      await device(server, b.factory, b.api)
    ).engine.unlock({
      password: PASSWORD,
    });
    expect(bAgain.secretKeyUpdated).toBe(true);
    expect(bAgain.items.map((i) => i.title)).toEqual(['Survives the rotation']);
    expect(Buffer.from((await skOf(b)) ?? []).equals(Buffer.from(newSk ?? []))).toBe(true);
    // Offline now, B opens with the local wrap it just made.
    server.offline = true;
    const bOffline = await (
      await device(server, b.factory, b.api)
    ).engine.unlock({
      password: PASSWORD,
    });
    expect(bOffline.sessionProblem).toBe('offline');
  });

  it('asks for the previous password when SK and the password both changed elsewhere', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const b = await secondDevice(server, a);
    const NEW = 'synthetic rotated passphrase 0d4f';
    await a.engine.rotateSecretKey({ password: PASSWORD });
    await a.engine.changePassword({ currentPassword: PASSWORD, newPassword: NEW });
    const fresh = () => device(server, b.factory, b.api);
    expect(await code((await fresh()).engine.unlock({ password: NEW }))).toBe(
      'previous_password_required',
    );
    expect(
      await code(
        (await fresh()).engine.unlock({ password: NEW, previousPassword: 'synthetic wrong one' }),
      ),
    ).toBe('wrong_password');
    const moved = await (
      await fresh()
    ).engine.unlock({ password: NEW, previousPassword: PASSWORD });
    expect(moved.passwordUpdated).toBe(true);
    const later = await (await fresh()).engine.unlock({ password: NEW });
    expect(later.passwordUpdated).toBeUndefined();
    expect(later.sync.state).toBe('synced');
  });

  it('rotates the Recovery Kit from Security: verified first, then only the new kit works', async () => {
    const server = new FakeServer();
    const { a, kit } = await createAccount(server);
    expect(await code(a.engine.kitRotateFinish({ password: PASSWORD }))).toBe('kit_mismatch');
    const fresh = a.engine.kitRotateBegin();
    expect(fresh.recoveryKey).not.toBe(kit);
    expect(
      await code(Promise.resolve().then(() => a.engine.kitRotateVerify({ recoveryKey: kit }))),
    ).toBe('kit_mismatch');
    expect(await code(a.engine.kitRotateFinish({ password: PASSWORD }))).toBe('kit_mismatch');
    a.engine.kitRotateVerify({ recoveryKey: fresh.recoveryKey });
    expect(await code(a.engine.kitRotateFinish({ password: 'synthetic wrong guess' }))).toBe(
      'wrong_password',
    );
    await a.engine.kitRotateFinish({ password: PASSWORD });
    const c = await device(server);
    expect(
      await code(c.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit })),
    ).toBe('recovery_failed');
    await c.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: fresh.recoveryKey });
  });

  it('labels activity from this device', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const page = await a.engine.activity({});
    expect(page.events).toEqual([
      expect.objectContaining({ type: 'device_revoked', device: 'this_device', atMs: 0 }),
    ]);
    expect(page.nextCursor).toBeNull();
  });

  it('refuses an older keyset, or a newer one that does not open, and goes read-only (INV-09)', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const keys = server.account?.keys;
    if (!server.account || !keys) throw new Error('no account');
    server.account = { ...server.account, keys: { ...keys, keysetVersion: 0 } };
    const rolledBack = await (
      await device(server, a.factory, a.api)
    ).engine.unlock({
      password: PASSWORD,
    });
    expect(rolledBack.sync.state).toBe('integrity_error');
    const reopened = await device(server, a.factory, a.api);
    server.account = {
      ...server.account,
      keys: { ...keys, keysetVersion: keys.keysetVersion + 1, keyset: keys.keyset },
    };
    // The same ciphertext under a higher version fails its AAD check: never trusted.
    const forged = await reopened.engine.unlock({ password: PASSWORD });
    expect(forged.sync.state).toBe('integrity_error');
    expect(await code(reopened.engine.save({ draft: login('Blocked') }))).toBe('read_only');
    expect((await reopened.store.device())?.enrolled?.keysetVersion).toBe(keys.keysetVersion);
  });

  it('resumes from AK after a restart, and refuses a key that does not open the keyset (D-27)', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    await a.engine.save({ draft: login('Kept while the worker sleeps') });
    await a.engine.sync();
    const ak = a.engine.accountKeyForResume();
    a.engine.wipeMemory();
    // A fresh engine on the same store and cookie jar stands in for a restarted service worker.
    const restarted = await device(server, a.factory, a.api);
    expect(await code(restarted.engine.resume({ accountKey: crypto.generateKey() }))).toBe(
      'locked',
    );
    const resumed = await restarted.engine.resume({ accountKey: ak });
    expect(resumed.items.map((i) => i.title)).toEqual(['Kept while the worker sleeps']);
    expect(resumed.sync.state).toBe('synced');
    expect(restarted.engine.detail({ id: resumed.items[0]?.id ?? '' }).username).toBe(
      'someone@mail.example',
    );
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

describe('clients after a server restore (characterization, input to D-28)', () => {
  it('a device ahead of the snapshot stops read-only; one at the snapshot keeps syncing', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const b = await secondDevice(server, a);
    await a.engine.save({ draft: login('Before the backup') });
    await a.engine.sync();
    await b.engine.sync();
    const backup = server.snapshot();
    await a.engine.save({ draft: login('After the backup') });
    expect((await a.engine.sync()).state).toBe('synced');

    server.restore(backup);
    // A verified a newer manifest than the server now has (INV-07): nothing is applied.
    const ahead = await a.engine.sync();
    expect(ahead).toMatchObject({ state: 'integrity_error', integrity: 'server_behind' });
    expect(
      a.engine
        .items()
        .map((i) => i.title)
        .sort(),
    ).toEqual(['After the backup', 'Before the backup']);
    expect(await code(a.engine.save({ draft: login('Blocked') }))).toBe('read_only');
    // B never saw the newer state, so the restored server looks current to it.
    expect((await b.engine.sync()).state).toBe('synced');
    expect(b.engine.items().map((i) => i.title)).toEqual(['Before the backup']);
    // The change made after the backup exists only on A.
    expect([...server.items.values()].filter((i) => i.record !== null)).toHaveLength(1);
  });

  it('a device holding a keyset newer than the snapshot stops at its next online unlock', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const backup = server.snapshot();
    await a.engine.rotateSecretKey({ password: PASSWORD });
    server.restore(backup);
    const reopened = await device(server, a.factory, a.api);
    const unlocked = await reopened.engine.unlock({ password: PASSWORD });
    // The server's keyset version went backwards (INV-09); the newer SK stays on this device.
    expect(unlocked.sync).toMatchObject({ state: 'integrity_error', integrity: 'keyset_rollback' });
    expect(server.account?.keys.keysetVersion).toBe(1);
  });
});

describe('clients after a server restore (revised D-28, backup-restore.md §3.6 and §3.12)', () => {
  const RESTORE_ID = '7d0c5f43-2a4e-4c84-9d1b-3f6a2b8e9c10';

  it('in maintenance, keeps the local copy readable and adds nothing; resumes when the server opens', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    await a.engine.save({ draft: login('Kept') });
    await a.engine.sync();
    server.maintenance = true;
    const reopened = await device(server, a.factory, a.api);
    const unlocked = await reopened.engine.unlock({ password: PASSWORD });
    expect(unlocked.sessionProblem).toBe('maintenance');
    expect(unlocked.sync.state).toBe('maintenance');
    expect(unlocked.items.map((i) => i.title)).toEqual(['Kept']);
    expect(await code(reopened.engine.save({ draft: login('Not now') }))).toBe(
      'server_maintenance',
    );
    expect((await reopened.engine.sync()).state).toBe('maintenance');
    expect(await reopened.store.device()).toBeDefined();
    server.maintenance = false;
    expect((await reopened.engine.sync()).state).toBe('synced');
  });

  it('a device ahead of the restored server keeps its newer data read-only and says why', async () => {
    const server = new FakeServer();
    const { a, kit } = await createAccount(server);
    await a.engine.save({ draft: login('Before the backup') });
    await a.engine.sync();
    const backup = server.snapshot();
    await a.engine.save({ draft: login('After the backup') });
    await a.engine.sync();
    // An edit that never reached the server, then the restore.
    server.offline = true;
    await a.engine.save({ draft: login('Pending on this device') });
    server.offline = false;
    server.restoreReviewed(backup, RESTORE_ID);

    const reopened = await device(server, a.factory, a.api);
    const unlocked = await reopened.engine.unlock({ password: PASSWORD });
    expect(unlocked.sync).toMatchObject({ state: 'integrity_error', integrity: 'server_behind' });
    expect(unlocked.sync.serverRestoredAtMs).toBeGreaterThan(0);
    expect(unlocked.items.map((i) => i.title).sort()).toEqual([
      'After the backup',
      'Before the backup',
      'Pending on this device',
    ]);
    expect(await code(reopened.engine.save({ draft: login('Blocked') }))).toBe('read_only');
    // Nothing was erased, and nothing went to the server.
    expect(await reopened.store.device()).toBeDefined();
    expect([...server.items.values()].filter((i) => i.record !== null)).toHaveLength(1);
    expect(await reopened.engine.localState()).toMatchObject({
      pending: 1,
      conflicts: 0,
      exported: false,
      snapshot: { items: 2 },
    });

    // The offline export holds the verified snapshot only, and says so; pending is acknowledged.
    expect(await code(reopened.engine.exportLocal({ password: PASSWORD, recoveryKey: kit }))).toBe(
      'unsynced_changes',
    );
    expect(
      await code(
        reopened.engine.exportLocal({
          password: 'synthetic wrong guess',
          recoveryKey: kit,
          acknowledgeNotIncluded: true,
        }),
      ),
    ).toBe('wrong_password');
    const file = await reopened.engine.exportLocal({
      password: PASSWORD,
      recoveryKey: kit,
      acknowledgeNotIncluded: true,
    });
    expect(file.fileName).toMatch(/^ruvee-export-\d{4}-\d{2}-\d{2}-verified\.ruvee$/);
    expect(file.notIncluded).toEqual({ pending: 1, conflicts: 0 });
    expect(file.snapshot.items).toBe(2);
    const clean = await device(new FakeServer());
    const view = clean.engine.exportOpen({ text: file.text, recoveryKey: kit });
    expect(view.items.map((i) => i.title).sort()).toEqual([
      'After the backup',
      'Before the backup',
    ]);
    expect(view.seq).toBe(file.snapshot.seq);
    expect(server.received.join('\n')).not.toContain('ruvee-export');
    expect(await reopened.engine.localState()).toMatchObject({ exported: true });
  });

  it('starts over only on an explicit, informed request, after an export or an explicit refusal', async () => {
    const server = new FakeServer();
    const { a, kit } = await createAccount(server);
    await a.engine.save({ draft: login('Only here') });
    await a.engine.sync();
    const backup = server.snapshot();
    await a.engine.save({ draft: login('Newer') });
    await a.engine.sync();
    server.restoreReviewed(backup, RESTORE_ID);
    await a.engine.sync();

    const startOver = (p: Partial<Parameters<VaultEngine['startOver']>[0]>) =>
      code(
        a.engine.startOver({
          confirm: 'erase-this-device',
          pendingSeen: 0,
          conflictsSeen: 0,
          ...p,
        }),
      );
    expect(await startOver({})).toBe('export_first');
    expect(await startOver({ withoutExport: true, pendingSeen: 3 })).toBe('unsynced_changes');
    expect(await a.store.device()).toBeDefined();
    await a.engine.exportLocal({ password: PASSWORD, recoveryKey: kit });
    expect(await startOver({})).toBe('resolved');
    expect(await a.store.device()).toBeUndefined();
    expect(await a.engine.phase()).toEqual({ phase: 'new' });
  });

  it('a device enrolled after the snapshot is unknown to the restored server, and is kept', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    await a.engine.save({ draft: login('Shared') });
    await a.engine.sync();
    const backup = server.snapshot();
    const b = await secondDevice(server, a);
    await b.engine.sync();
    server.restoreReviewed(backup, RESTORE_ID);

    const reopened = await device(server, b.factory, b.api);
    const unlocked = await reopened.engine.unlock({ password: PASSWORD });
    expect(unlocked.sessionProblem).toBe('device_unknown');
    expect(unlocked.items.map((i) => i.title)).toEqual(['Shared']);
    expect(await reopened.store.device()).toBeDefined();
    expect(reopened.events).not.toContainEqual({ event: 'ended', reason: 'device_revoked' });
  });

  it('an old session of a device at the snapshot ends; the device signs in again and syncs', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    await a.engine.save({ draft: login('At the snapshot') });
    await a.engine.sync();
    server.restoreReviewed(server.snapshot(), RESTORE_ID);
    expect((await a.engine.sync()).state).toBe('session_expired');
    const reopened = await device(server, a.factory, a.api);
    const unlocked = await reopened.engine.unlock({ password: PASSWORD });
    expect(unlocked.sessionProblem).toBeUndefined();
    expect(unlocked.sync.state).toBe('synced');
    expect(unlocked.sync.serverRestoredAtMs).toBeGreaterThan(0);
  });
});

describe('reopening a restored server (D-30 option B, backup-restore.md §3.13)', () => {
  const RESTORE_ID = '0f0e7d2c-6b5a-4c39-8a27-1e0d9c8b7a65';
  const CODE = `RC1-${'C'.repeat(43)}`;
  const NEW = 'synthetic reopened engine passphrase 2b9e';

  it('reopens with the password on a device that keeps its newer items and pending edit', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    await a.engine.save({ draft: login('Before the backup') });
    await a.engine.sync();
    const backup = server.snapshot();
    await a.engine.save({ draft: login('After the backup') });
    await a.engine.sync();
    server.offline = true;
    await a.engine.save({ draft: login('Pending') });
    server.offline = false;
    server.restoreReopening(backup, RESTORE_ID, CODE);

    const reopened = await device(server, a.factory, a.api);
    const unlocked = await reopened.engine.unlock({ password: PASSWORD });
    expect(unlocked.sessionProblem).toBe('reopening');
    expect(unlocked.sync.state).toBe('reopening');
    expect(await code(reopened.engine.save({ draft: login('Not yet') }))).toBe('server_reopening');
    expect(
      await code(
        reopened.engine.reopenBegin({ reopenCode: `RC1-${'D'.repeat(43)}`, password: PASSWORD }),
      ),
    ).toBe('reopen_failed');
    expect(
      await code(
        reopened.engine.reopenBegin({ reopenCode: CODE, password: 'synthetic wrong guess 4' }),
      ),
    ).toBe('reopen_failed');
    // The kit path would start this browser from nothing: refused while it holds data.
    expect(
      await code(
        reopened.engine.recoveryBegin({
          username: 'synthetic-user',
          recoveryKey: 'RK1-x',
          reopenCode: CODE,
        }),
      ),
    ).not.toBe('resolved');

    await reopened.engine.reopenBegin({ reopenCode: CODE, password: PASSWORD });
    const kit = await reopened.engine.recoverySetPassword({ password: NEW });
    expect(await code(reopened.engine.recoveryFinish())).toBe('kit_mismatch');
    await reopened.engine.recoveryVerifyKit({ recoveryKey: kit.recoveryKey });
    const done = await reopened.engine.recoveryFinish();
    expect(done.reopened).toBe(true);
    expect(server.reopenCode).toBeUndefined();
    // Every local item and the pending edit survive; the device is ahead, so it stays read-only.
    expect(done.items.map((i) => i.title).sort()).toEqual([
      'After the backup',
      'Before the backup',
      'Pending',
    ]);
    expect(done.sync).toMatchObject({
      state: 'integrity_error',
      integrity: 'server_behind',
      pendingCount: 1,
    });
    expect(await reopened.store.device()).toBeDefined();
    // The new password opens this device, the old one no longer does.
    const later = await device(server, a.factory, a.api);
    expect(await code(later.engine.unlock({ password: PASSWORD }))).toBe('wrong_password');
    expect((await later.engine.unlock({ password: NEW })).items).toHaveLength(3);
  });

  it('refuses the kit path on a browser with data, and reopens with the kit on a new one', async () => {
    const server = new FakeServer();
    const { a, kit } = await createAccount(server);
    await a.engine.save({ draft: login('At the snapshot') });
    await a.engine.sync();
    server.restoreReopening(server.snapshot(), RESTORE_ID, CODE);
    expect(
      await code(
        a.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit, reopenCode: CODE }),
      ),
    ).toBe('local_data_present');
    const fresh = await device(server);
    expect(
      await code(
        fresh.engine.recoveryBegin({
          username: 'synthetic-user',
          recoveryKey: kit,
          reopenCode: `RC1-${'E'.repeat(43)}`,
        }),
      ),
    ).toBe('reopen_failed');
    await fresh.engine.recoveryBegin({
      username: 'synthetic-user',
      recoveryKey: kit,
      reopenCode: CODE,
    });
    const newKit = await fresh.engine.recoverySetPassword({ password: NEW });
    expect(newKit.recoveryKey).not.toBe(kit);
    await fresh.engine.recoveryVerifyKit({ recoveryKey: newKit.recoveryKey });
    const done = await fresh.engine.recoveryFinish();
    expect(done.items.map((i) => i.title)).toEqual(['At the snapshot']);
    expect(server.reopenCode).toBeUndefined();
    // The replayed code fails now.
    const other = await device(server);
    expect(
      await code(
        other.engine.recoveryBegin({
          username: 'synthetic-user',
          recoveryKey: newKit.recoveryKey,
          reopenCode: CODE,
        }),
      ),
    ).not.toBe('resolved');
  });

  it('sends a device whose Secret Key changed after the backup to the kit path', async () => {
    const server = new FakeServer();
    const { a } = await createAccount(server);
    const backup = server.snapshot();
    await a.engine.rotateSecretKey({ password: PASSWORD });
    server.restoreReopening(backup, RESTORE_ID, CODE);
    const reopened = await device(server, a.factory, a.api);
    await reopened.engine.unlock({ password: PASSWORD });
    expect(await code(reopened.engine.reopenBegin({ reopenCode: CODE, password: PASSWORD }))).toBe(
      'reopen_needs_kit',
    );
  });
});

describe('portable encrypted export (backup-restore.md §4, D-13 option A)', () => {
  async function exported() {
    const server = new FakeServer();
    const { a, kit } = await createAccount(server);
    await a.engine.save({ draft: login('Exported Mail', 'synthetic-export-pw-1') });
    const gone = await a.engine.save({ draft: login('Deleted before export') });
    await a.engine.trash({ id: gone.id });
    await a.engine.purge({ id: gone.id });
    await a.engine.sync();
    const file = await a.engine.exportVault({ password: PASSWORD, recoveryKey: kit });
    return { server, a, kit, file };
  }

  it('opens on a device with no account, with the kit typed at export time', async () => {
    const { server, a, kit, file } = await exported();
    expect(file.fileName).toMatch(/^ruvee-export-\d{4}-\d{2}-\d{2}\.ruvee$/);
    // Nothing of the export went to the server.
    expect(server.received.join('\n')).not.toContain('ruvee-export');
    const clean = await device(new FakeServer());
    const view = clean.engine.exportOpen({ text: file.text, recoveryKey: kit });
    expect(view.items.map((i) => i.title)).toEqual(['Exported Mail']);
    expect(view.authorDeviceId).toBe(((await a.engine.phase()) as { deviceId: string }).deviceId);
    expect(view.asOfMs).toBeGreaterThan(0);
    const id = view.items[0]?.id ?? '';
    expect(clean.engine.exportSecret({ id })).toBe('synthetic-export-pw-1');
    // Read-only and in memory: nothing was stored on the clean device.
    expect(await clean.store.device()).toBeUndefined();
    clean.engine.exportClose();
    expect(await code(Promise.resolve().then(() => clean.engine.exportSecret({ id })))).toBe(
      'not_found',
    );
  });

  it('refuses another kit, a mistyped kit and a wrong password, before making anything', async () => {
    const { a, kit, file } = await exported();
    const other = crypto.formatRecoveryKey(crypto.generateRecoveryKey().recoveryKey);
    const clean = await device(new FakeServer());
    const open = (recoveryKey: string, text = file.text) =>
      code(Promise.resolve().then(() => clean.engine.exportOpen({ text, recoveryKey })));
    expect(await open(other)).toBe('kit_mismatch');
    expect(await open('RK1-00000')).toBe('invalid_recovery_key');
    expect(await code(a.engine.exportVault({ password: PASSWORD, recoveryKey: 'RK1-0' }))).toBe(
      'invalid_recovery_key',
    );
    expect(
      await code(a.engine.exportVault({ password: 'synthetic wrong guess', recoveryKey: kit })),
    ).toBe('wrong_password');
  });

  it('fails closed on any change to any part of the file', async () => {
    const { kit, file } = await exported();
    const clean = await device(new FakeServer());
    const flip = (text: string, at = 12) =>
      `${text.slice(0, at)}${text[at] === 'A' ? 'B' : 'A'}${text.slice(at + 1)}`;
    type File = Record<string, unknown> & {
      items: { itemId: string; revision: number; record: string | null }[];
      keyset: { version: number; envelope: string };
      manifest: { seq: number; envelope: string };
    };
    const base = JSON.parse(file.text) as File;
    const variant = (change: (f: File) => void) => {
      const f = JSON.parse(file.text) as File;
      change(f);
      return JSON.stringify(f);
    };
    const firstLive = base.items.findIndex((i) => i.record !== null);
    const cases: [string, string, string][] = [
      ['AK wrap', variant((f) => (f.recoveryWrap = flip(String(f.recoveryWrap)))), 'kit_mismatch'],
      [
        'wrap id',
        variant((f) => (f.recoveryKeyId = flip(String(f.recoveryKeyId), 3))),
        'kit_mismatch',
      ],
      ['account id', variant((f) => (f.accountId = crypto.generateUuid())), 'kit_mismatch'],
      ['keyset', variant((f) => (f.keyset.envelope = flip(f.keyset.envelope, 40))), 'integrity'],
      ['keyset version', variant((f) => (f.keyset.version += 1)), 'integrity'],
      ['vault id', variant((f) => (f.vaultId = crypto.generateUuid())), 'integrity'],
      [
        'manifest',
        variant((f) => (f.manifest.envelope = flip(f.manifest.envelope, 60))),
        'integrity',
      ],
      ['manifest seq', variant((f) => (f.manifest.seq += 1)), 'integrity'],
      [
        'a record',
        variant((f) => {
          const item = f.items[firstLive];
          if (item?.record) item.record = flip(item.record, 80);
        }),
        'integrity',
      ],
      [
        'a revision',
        variant((f) => {
          const item = f.items[firstLive];
          if (item) item.revision += 1;
        }),
        'integrity',
      ],
      ['a dropped item', variant((f) => f.items.splice(firstLive, 1)), 'integrity'],
      [
        'a tombstone made live',
        variant((f) => {
          const dead = f.items.find((i) => i.record === null);
          const live = f.items[firstLive];
          if (dead && live) dead.record = live.record;
        }),
        'integrity',
      ],
      [
        'a duplicated item',
        variant((f) => {
          const first = f.items[0];
          if (first) f.items.push(first);
        }),
        'invalid_export',
      ],
      ['reordered items', variant((f) => f.items.reverse()), 'invalid_export'],
      ['another version', variant((f) => (f.version = 2)), 'invalid_export'],
      ['an unknown field', variant((f) => (f.note = 'x')), 'invalid_export'],
      ['a truncated file', file.text.slice(0, -40), 'invalid_export'],
      ['not JSON', 'ruvee', 'invalid_export'],
    ];
    expect(base.items.length).toBe(2);
    for (const [what, text, expected] of cases)
      expect(
        await code(
          Promise.resolve().then(() => clean.engine.exportOpen({ text, recoveryKey: kit })),
        ),
        what,
      ).toBe(expected);
  });
});
