// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { ItemDraft } from '../protocol.js';
import { NetworkError } from '../api.js';
import { DeviceStore } from '../store.js';
import { FakeServer, fakeOpaque } from '../test-support.js';
import { VaultEngine, VaultError } from '../vault-engine.js';

/**
 * Device proof of possession in the engine (docs/security/device-proof.md, D-31 A), against the
 * fake server, which verifies every proof with the same code as the API. Synthetic data only.
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

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (error) {
    return error instanceof VaultError ? error.code : String(error);
  }
};

describe('D-31 device proof in the engine', () => {
  it('registers DPK and AVPK at setup, and the first session is proven', async () => {
    const { server, a } = await account();
    const [id] = [...server.devices.keys()];
    expect(server.devicePublicKeys.get(id ?? '')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(server.akVerifyKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // The device key is stored sealed, never in clear.
    const sealed = await a.store.local('device-key');
    expect(sealed).toBeDefined();
    expect(Buffer.from(sealed ?? new Uint8Array()).toString('latin1')).not.toContain('secretKey');
    expect((await a.engine.sync()).state).toBe('synced');
  });

  it('proves a new session after unlock, and a locked engine cannot sign', async () => {
    const { server, a } = await account();
    await a.engine.save({ draft: note('one') });
    await a.engine.sync();
    a.engine.wipeMemory();
    // The session is gone server-side; the unlock logs in with the device key.
    server.sessionValid = false;
    const again = await device(server, a.factory);
    const unlocked = await again.engine.unlock({ password: PASSWORD });
    expect(unlocked.sessionProblem).toBeUndefined();
    expect(unlocked.sync.state).toBe('synced');
    // Locked: nothing that needs the device key can run.
    again.engine.wipeMemory();
    expect(
      await code(
        again.engine.changePassword({ currentPassword: PASSWORD, newPassword: 'x'.repeat(20) }),
      ),
    ).toBe('locked');
  });

  it('keeps a pre-D-31 device usable offline with its pending edit, and re-enrolls it with the kit', async () => {
    const { server, a, kit } = await account();
    await a.engine.save({ draft: note('Synced') });
    await a.engine.sync();
    server.offline = true;
    await a.engine.save({ draft: note('Pending, never uploaded') });
    await a.engine.idle();
    a.engine.wipeMemory();
    server.offline = false;
    // As after the migration: this device has no key, and the server has none for it.
    const [deviceId] = [...server.devices.keys()];
    server.devicePublicKeys.delete(deviceId ?? '');
    await a.store.apply({ local: { 'device-key': null } });
    server.sessionValid = false;
    const old = await device(server, a.factory);
    const unlocked = await old.engine.unlock({ password: PASSWORD });
    expect(unlocked.sessionProblem).toBe('device_key_missing');
    expect(unlocked.items.map((i) => i.title).sort()).toEqual([
      'Pending, never uploaded',
      'Synced',
    ]);
    expect(unlocked.sync.pendingCount).toBe(1);
    old.engine.wipeMemory();
    // Migration (device-proof.md §9): the Recovery Kit on this browser enrolls a key and keeps
    // the local vault, the pending edit included.
    const migrating = await device(server, a.factory);
    await migrating.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit });
    const newKit = await migrating.engine.recoverySetPassword({ password: PASSWORD });
    await migrating.engine.recoveryVerifyKit({ recoveryKey: newKit.recoveryKey });
    const done = await migrating.engine.recoveryFinish();
    expect(done.recovered?.keptLocal).toEqual({ pending: 1, conflicts: 0 });
    expect(done.sync.state).toBe('synced');
    expect(server.devicePublicKeys.get(deviceId ?? '')).toBeDefined();
    expect([...server.items.values()].filter((i) => i.record !== null)).toHaveLength(2);
  });

  it('still signs after an extension service-worker restart (resume from AK)', async () => {
    const { server, a } = await account();
    const ak = a.engine.accountKeyForResume();
    a.engine.wipeMemory();
    // The extension's tokens survive the restart (the same client); only memory was lost.
    const restarted = await device(server, a.factory, a.api);
    await restarted.engine.resume({ accountKey: ak });
    // A step-up operation signed by the device key: the password change succeeds.
    await restarted.engine.changePassword({
      currentPassword: PASSWORD,
      newPassword: 'synthetic resumed passphrase 91',
    });
    expect((await restarted.engine.sync()).state).toBe('synced');
  });

  it('recovers safely from an enrollment interrupted after approval', async () => {
    const { server, a } = await account();
    const b = await device(server);
    await b.engine.login({ username: 'synthetic-user', password: PASSWORD });
    const started = await a.engine.pairingStart();
    await b.engine.pairingJoin({ code: started.code });
    await a.engine.pairingStatus({ pairingId: started.pairingId });
    await a.engine.pairingApprove({ pairingId: started.pairingId });
    // B's tab closes before it read the reply: its key was only in memory.
    b.engine.wipeMemory();
    const orphan = [...server.devices].find(
      ([, s]) => s === 'active' && server.devicePublicKeys.has(''),
    );
    expect(orphan).toBeUndefined();
    const restarted = await device(server, b.factory);
    const phase = await restarted.engine.login({ username: 'synthetic-user', password: PASSWORD });
    // A new pending device, ready to pair again; the approved row can never be proven.
    if (phase.phase !== 'pending') throw new Error(`expected pending, got ${phase.phase}`);
    expect(server.devices.get(phase.deviceId)).toBe('pending');
  });

  it('logout and lock leave only the sealed device key; nothing can sign until the next unlock', async () => {
    const { a } = await account();
    const held = (a.engine as unknown as { session: { deviceKey: { secretKey: Uint8Array } } })
      .session.deviceKey.secretKey;
    await a.engine.logout();
    // Zeroed in memory, and the engine has no session to sign for.
    expect(held.every((x) => x === 0)).toBe(true);
    expect(
      await code(
        a.engine.changePassword({ currentPassword: PASSWORD, newPassword: 'x'.repeat(20) }),
      ),
    ).toBe('locked');
    // The sealed record stays: this browser is still the same enrolled device.
    expect(await a.store.local('device-key')).toBeDefined();
  });

  it('a session proof whose reply was lost ends in one proven session, not a second proof', async () => {
    const { server, a } = await account();
    a.engine.wipeMemory();
    // A login that carried no proof leaves a pre-proof session (the local wrap did not open).
    let stripProof = true;
    let lost = true;
    const base = server.api();
    const api = new Proxy(base, {
      get(target, key, receiver) {
        const value = Reflect.get(target, key, receiver) as unknown;
        if (typeof value !== 'function') return value;
        const method = value as (...args: unknown[]) => Promise<unknown>;
        if (key === 'loginFinish')
          return (body: { deviceProof?: string }) => {
            const { deviceProof, ...rest } = body;
            return method.call(target, stripProof ? rest : { ...rest, deviceProof });
          };
        if (key === 'sessionProof')
          return async (body: unknown) => {
            await method.call(target, body);
            if (lost) {
              lost = false;
              // Applied by the server; the reply never arrives.
              throw new NetworkError('offline');
            }
          };
        return method.bind(target);
      },
    });
    server.sessionValid = false;
    const first = await device(server, a.factory, api);
    expect((await first.engine.unlock({ password: PASSWORD })).sessionProblem).toBe(
      'device_key_missing',
    );
    first.engine.wipeMemory();
    stripProof = false;
    // The next unlock proves that session; the reply is lost, so it logs in again with the key.
    const second = await device(server, a.factory, api);
    const view = await second.engine.unlock({ password: PASSWORD });
    expect(view.sessionProblem).toBeUndefined();
    expect(view.sync.state).toBe('synced');
    expect(lost).toBe(false);
  });
});
