// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { Api } from '../api.js';
import type { ItemDraft } from '../protocol.js';
import { DeviceStore } from '../store.js';
import { FakeServer, fakeOpaque } from '../test-support.js';
import { VaultEngine, VaultError } from '../vault-engine.js';

/**
 * Pre-deployment review, findings R19, R22 and the R23 key-zeroing items
 * (docs/security/predeployment-review.md), as regressions in the shared engine. Synthetic data
 * only.
 */

const PASSWORD = 'synthetic engine passphrase 4c1e';
let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

async function device(
  server: FakeServer,
  options: {
    factory?: IDBFactory;
    api?: Api;
    crypto?: RuveeCrypto;
    wrapStore?: (s: DeviceStore) => DeviceStore;
  } = {},
) {
  const factory = options.factory ?? new IDBFactory();
  const opened = await DeviceStore.open(factory);
  const store = options.wrapStore ? options.wrapStore(opened) : opened;
  const engine = new VaultEngine({
    crypto: options.crypto ?? crypto,
    api: options.api ?? server.api(),
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

/**
 * `api` whose `method` waits, once, until the test releases it: an operation caught mid-flight.
 * The first call after `arm()` waits (armed at once unless `armed: false`).
 */
function paused(api: Api, method: keyof Api, armed = true) {
  let reached!: () => void;
  let release!: () => void;
  const atCall = new Promise<void>((resolve) => (reached = resolve));
  const gate = new Promise<void>((resolve) => (release = resolve));
  let once = armed;
  const wrapped = new Proxy(api, {
    get(target, key, receiver) {
      const value = Reflect.get(target, key, receiver) as unknown;
      if (key !== method || typeof value !== 'function') return value;
      return async (...args: unknown[]) => {
        if (once) {
          once = false;
          reached();
          await gate;
        }
        return (value as (...a: unknown[]) => unknown).apply(target, args);
      };
    },
  });
  return {
    api: wrapped,
    atCall,
    release,
    arm: () => {
      once = true;
    },
  };
}

const zero = (bytes: Uint8Array) => bytes.every((b) => b === 0);

describe('REVIEW R19 (regression): a lock during an operation leaves nothing unlocked', () => {
  it('an unlock caught by the lock before its session exists does not install one afterwards', async () => {
    const { server, a } = await account();
    await a.engine.save({ draft: note('Kept') });
    await a.engine.sync();
    a.engine.wipeMemory();
    let reached!: () => void;
    let release!: () => void;
    const atRead = new Promise<void>((resolve) => (reached = resolve));
    const gate = new Promise<void>((resolve) => (release = resolve));
    // Unlock reads the sealed checkpoint before it builds the session: the lock lands there.
    const wrapStore = (store: DeviceStore) =>
      new Proxy(store, {
        get(target, key, receiver) {
          const value = Reflect.get(target, key, receiver) as unknown;
          if (typeof value !== 'function') return value;
          const method = value as (...args: unknown[]) => Promise<unknown>;
          if (key !== 'local') return method.bind(target);
          return async (name: string) => {
            if (name === 'checkpoint') {
              reached();
              await gate;
            }
            return method.call(target, name);
          };
        },
      });
    const b = await device(server, { factory: a.factory, wrapStore });
    const unlocking = b.engine.unlock({ password: PASSWORD });
    await atRead;
    b.engine.wipeMemory();
    release();
    // Before: the unlock resolved afterwards with a session and AK (the extension then stored AK
    // back in chrome.storage.session, and the next message resumed from it).
    expect(await code(unlocking)).toBe('locked');
    expect(() => b.engine.accountKeyForResume()).toThrow();
  });

  it('an unlock still waiting on the server when the lock comes ends locked, and writes nothing', async () => {
    const { server, a } = await account();
    await a.engine.save({ draft: note('Kept') });
    await a.engine.sync();
    a.engine.wipeMemory();
    server.sessionValid = false;
    const gate = paused(server.api(), 'loginStart');
    const b = await device(server, { factory: a.factory, api: gate.api });
    const unlocking = b.engine.unlock({ password: PASSWORD });
    await gate.atCall;
    // The extension locks (auto-lock, the Lock button) while the unlock waits on the network.
    b.engine.wipeMemory();
    gate.release();
    // Before: the unlock resolved, the engine held AK again, and the extension stored it back.
    expect(await code(unlocking)).toBe('locked');
    expect(() => b.engine.accountKeyForResume()).toThrow();
    expect(() => b.engine.items()).toThrow();
    // Nothing it would have written after the lock reached the store: a new unlock opens it all.
    const c = await device(server, { factory: a.factory });
    const view = await c.engine.unlock({ password: PASSWORD });
    expect(view.items.map((i) => i.title)).toEqual(['Kept']);
    expect(view.sync.state).toBe('synced');
  });

  it('a sync caught by the lock does not seal records under the zeroed keys', async () => {
    const { server, a } = await account();
    await a.engine.save({ draft: note('Before') });
    await a.engine.sync();
    const gate = paused(server.api(), 'changes', false);
    const b = await device(server, { factory: a.factory, api: gate.api });
    a.engine.wipeMemory();
    await b.engine.unlock({ password: PASSWORD });
    await b.engine.idle();
    gate.arm();
    const syncing = b.engine.sync();
    await gate.atCall;
    b.engine.wipeMemory();
    gate.release();
    expect(await code(syncing)).toBe('locked');
    const c = await device(server, { factory: a.factory });
    const view = await c.engine.unlock({ password: PASSWORD });
    expect(view.items.map((i) => i.title)).toEqual(['Before']);
  });
});

describe('REVIEW R22 (regression): start-over counts conflicts; an import never queues twice', () => {
  it('refuses to erase a device whose conflicts the user was not shown', async () => {
    const { server, a } = await account();
    const item = await a.engine.save({ draft: note('Shared') });
    await a.engine.sync();
    const startedB = await a.engine.pairingStart();
    const b = await device(server);
    await b.engine.login({ username: 'synthetic-user', password: PASSWORD });
    await b.engine.pairingJoin({ code: startedB.code });
    await a.engine.pairingStatus({ pairingId: startedB.pairingId });
    await b.engine.pairingWait();
    await a.engine.pairingApprove({ pairingId: startedB.pairingId });
    await b.engine.pairingWait();
    await b.engine.sync();
    server.offline = true;
    await a.engine.save({ draft: { ...note('Shared (A)'), id: item.id } });
    await b.engine.save({ draft: { ...note('Shared (B)'), id: item.id } });
    await Promise.all([a.engine.idle(), b.engine.idle()]);
    server.offline = false;
    await a.engine.sync();
    await b.engine.sync();
    expect(await b.engine.localState()).toMatchObject({ pending: 0, conflicts: 1 });
    // The user saw 0 pending and was never told about the conflict: nothing is erased.
    const erase = (conflictsSeen: number) =>
      code(
        b.engine.startOver({
          confirm: 'erase-this-device',
          withoutExport: true,
          pendingSeen: 0,
          conflictsSeen,
        }),
      );
    expect(await erase(0)).toBe('unsynced_changes');
    expect(await b.store.device()).toBeDefined();
    // Shown both counts: erased.
    expect(await erase(1)).toBe('ok');
    expect(await b.store.device()).toBeUndefined();
  });

  it('feeds the next import batch only into an empty pending queue', async () => {
    const source = await account();
    for (let n = 0; n < 150; n++) await source.a.engine.save({ draft: note(`Note ${String(n)}`) });
    await source.a.engine.idle();
    const file = await source.a.engine.exportVault({ password: PASSWORD, recoveryKey: source.kit });
    const server = new FakeServer();
    const b = await device(server);
    const kit = await b.engine.setupBegin({
      bootstrapToken: 'T'.repeat(43),
      username: 'synthetic-import',
      password: PASSWORD,
    });
    await b.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
    await b.engine.setupFinish();
    b.engine.exportOpen({ text: file.text, recoveryKey: source.kit });
    // The first commit lands, the second batch is queued and then the connection drops.
    server.commitBudget = 1;
    await b.engine.importIntoEmptyVault();
    const session = (
      b.engine as unknown as {
        session: {
          pending: { itemId: string }[];
          inflight?: { mutations: { itemId: string }[] };
        };
      }
    ).session;
    const queued = () => [
      ...session.pending.map((m) => m.itemId),
      ...(session.inflight?.mutations ?? []).map((m) => m.itemId),
    ];
    const before = queued();
    expect(before.length).toBeGreaterThan(0);
    // Before: the rows of the commit in flight (not synced yet) were queued a second time.
    await (b.engine as unknown as { feedImport: (s: unknown) => Promise<void> }).feedImport(
      session,
    );
    expect(queued()).toEqual(before);
    expect(new Set(queued()).size).toBe(before.length);
    server.commitBudget = undefined;
    const done = await b.engine.sync();
    expect(done.import).toMatchObject({ state: 'complete', uploaded: 150 });
    expect(b.engine.items().filter((i) => i.conflict !== null)).toHaveLength(0);
    expect(server.items.size).toBe(150);
  });
});

describe('REVIEW R23 (regression): keys are zeroed on lock and on failed unlocks', () => {
  it('a lock during an unfinished recovery zeroes what the Recovery Kit unlocked', async () => {
    const { server, kit } = await account();
    const fresh = await device(server);
    await fresh.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit });
    const pending = (
      fresh.engine as unknown as {
        recovery: { accountKey: Uint8Array; secretKey: Uint8Array; vaultKey: Uint8Array };
      }
    ).recovery;
    const held = [pending.accountKey, pending.secretKey, pending.vaultKey];
    expect(held.some(zero)).toBe(false);
    fresh.engine.wipeMemory();
    // Before: the unfinished recovery kept AK, SK and VK after the lock.
    expect(held.every(zero)).toBe(true);
    expect(await code(fresh.engine.recoverySetPassword({ password: PASSWORD }))).toBe(
      'recovery_failed',
    );
  });

  it('an unlock whose keyset does not open zeroes the AK it unwrapped', async () => {
    const { server, a } = await account();
    a.engine.wipeMemory();
    const record = await a.store.device();
    if (!record?.enrolled) throw new Error('not enrolled');
    const keyset = record.enrolled.keyset.slice();
    keyset[keyset.length - 1] = (keyset[keyset.length - 1] ?? 0) ^ 1;
    await a.store.putDevice({ ...record, enrolled: { ...record.enrolled, keyset } });
    const unwrapped: Uint8Array[] = [];
    const watching: RuveeCrypto = {
      ...crypto,
      unwrapAccountKey: (input) => {
        const key = crypto.unwrapAccountKey(input);
        unwrapped.push(key);
        return key;
      },
    };
    const b = await device(server, { factory: a.factory, crypto: watching });
    expect(await code(b.engine.unlock({ password: PASSWORD }))).not.toBe('ok');
    expect(unwrapped).toHaveLength(1);
    // Before: AK stayed in memory after the failed unlock.
    expect(unwrapped.every(zero)).toBe(true);
  });

  it('a recovery whose keyset does not open zeroes the AK the kit unwrapped', async () => {
    const { server, kit } = await account();
    server.corruptKeyset = true;
    const unwrapped: Uint8Array[] = [];
    const watching: RuveeCrypto = {
      ...crypto,
      unwrapAccountKeyForRecovery: (input) => {
        const key = crypto.unwrapAccountKeyForRecovery(input);
        unwrapped.push(key);
        return key;
      },
    };
    const fresh = await device(server, { crypto: watching });
    expect(
      await code(fresh.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit })),
    ).toBe('integrity');
    expect(unwrapped).toHaveLength(1);
    expect(unwrapped.every(zero)).toBe(true);
  });
});
