// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { ItemDraft } from '../protocol.js';
import { DeviceStore } from '../store.js';
import { ApiError, createApi, NetworkError, SAME_ORIGIN } from '../api.js';
import { FakeServer, fakeOpaque } from '../test-support.js';
import { VaultEngine, VaultError } from '../vault-engine.js';

/**
 * Follow-up review (docs/security/followup-review.md): reproductions of confirmed client defects.
 * Each test states the correct behaviour and is marked `fails` while the defect exists; when a
 * fix lands, the test starts passing and vitest reports it, so the mark must be removed then.
 * Synthetic data only.
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

async function account(server = new FakeServer(), api = server.api()) {
  const a = await device(server, undefined, api);
  const kit = await a.engine.setupBegin({
    bootstrapToken: 'T'.repeat(43),
    username: 'Synthetic-User',
    password: PASSWORD,
  });
  await a.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
  await a.engine.setupFinish();
  return { server, a };
}

async function paired(server: FakeServer, a: Awaited<ReturnType<typeof device>>) {
  const b = await device(server);
  await b.engine.login({ username: 'synthetic-user', password: PASSWORD });
  const started = await a.engine.pairingStart();
  await b.engine.pairingJoin({ code: started.code });
  await a.engine.pairingStatus({ pairingId: started.pairingId });
  await b.engine.pairingWait();
  await a.engine.pairingApprove({ pairingId: started.pairingId });
  await b.engine.pairingWait();
  await b.engine.sync();
  return b;
}

describe('FOLLOW-UP reproductions (client engine)', () => {
  // F-2 (fixed): two engines on one IndexedDB each wrote their whole state from memory, so the
  // second one silently erased the first one's unsynced edits. The engine that loads state last
  // now claims the store; the other one's writes are refused and it locks (store.ts).
  it('an edit the first engine saved before a second one opened survives', async () => {
    const { server, a } = await account();
    await a.engine.sync();
    server.offline = true;
    await a.engine.save({ draft: note('Saved in tab 1') });
    await a.engine.idle();
    const tab2 = await device(server, a.factory);
    const opened = await tab2.engine.unlock({ password: PASSWORD });
    expect(opened.items.map((i) => i.title)).toContain('Saved in tab 1');
    await tab2.engine.save({ draft: note('Saved in tab 2') });
    await tab2.engine.idle();
    tab2.engine.wipeMemory();
    const reopened = await device(server, a.factory);
    const view = await reopened.engine.unlock({ password: PASSWORD });
    expect(view.items.map((i) => i.title).sort()).toEqual(['Saved in tab 1', 'Saved in tab 2']);
  });

  it('two engines on one store never drop an edit they reported as saved', async () => {
    const { server, a } = await account();
    await a.engine.sync();
    const tab2 = await device(server, a.factory);
    await tab2.engine.unlock({ password: PASSWORD });
    server.offline = true;
    // The first engine loaded earlier: its save is refused and reported, and it locks.
    expect(await code(a.engine.save({ draft: note('Saved in tab 1') }))).toBe('open_elsewhere');
    expect(await code(a.engine.save({ draft: note('Again in tab 1') }))).toBe('locked');
    expect(await code(tab2.engine.save({ draft: note('Saved in tab 2') }))).toBe('ok');
    await tab2.engine.idle();
    tab2.engine.wipeMemory();
    const reopened = await device(server, a.factory);
    const view = await reopened.engine.unlock({ password: PASSWORD });
    expect(view.items.map((i) => i.title)).toEqual(['Saved in tab 2']);
  });

  it('the engine that loses the store emits open_elsewhere and keeps no keys', async () => {
    const { server, a } = await account();
    const events: unknown[] = [];
    const tab1 = await device(server, a.factory);
    // A second engine whose events we can see.
    const store = tab1.store;
    const engine = new VaultEngine({
      crypto,
      api: server.api(),
      store,
      opaque: fakeOpaque,
      origin: 'http://127.0.0.1:3101',
      platform: 'web',
      now: () => Date.now(),
      emit: (event) => events.push(event),
    });
    a.engine.wipeMemory();
    await engine.unlock({ password: PASSWORD });
    const tab2 = await device(server, a.factory);
    await tab2.engine.unlock({ password: PASSWORD });
    server.offline = true;
    expect(await code(engine.save({ draft: note('Too late') }))).toBe('open_elsewhere');
    expect(events).toContainEqual({ event: 'ended', reason: 'open_elsewhere' });
    expect(() => engine.items()).toThrow();
  });

  // F-3 (fixed): an offline edit of an item in "deleted here, edited elsewhere" conflict, then "mine".
  it('resolving a conflict never queues two mutations of one item', async () => {
    const { server, a } = await account();
    const x = await a.engine.save({ draft: note('X') });
    await a.engine.sync();
    const b = await paired(server, a);
    server.offline = true;
    await a.engine.trash({ id: x.id });
    await a.engine.purge({ id: x.id });
    await a.engine.idle();
    server.offline = false;
    await b.engine.save({ draft: { ...note('X edited on B'), id: x.id } });
    await b.engine.sync();
    await a.engine.sync();
    const conflict = a.engine.items().find((i) => i.id === x.id)?.conflict;
    expect(conflict).toBe('edited_after_delete');
    server.offline = true;
    await a.engine.save({ draft: { ...note('X edited on A during the conflict'), id: x.id } });
    await a.engine.resolveConflict({ id: x.id, choice: 'mine' });
    await a.engine.idle();
    server.offline = false;
    const before = server.received.length;
    await a.engine.sync();
    const commits = server.received
      .slice(before)
      .filter((body) => body.includes('"mutations"'))
      .map((body) => (JSON.parse(body) as { mutations: { itemId: string }[] }).mutations);
    expect(commits.length).toBeGreaterThan(0);
    for (const mutations of commits) {
      const ids = mutations.map((m) => m.itemId);
      // The API refuses a commit naming one item twice (sync.service.ts checkCommit).
      expect(new Set(ids).size).toBe(ids.length);
    }
    // "Keep mine" was the deletion: it reaches the server and the device is synced again.
    expect(a.engine.items().some((i) => i.id === x.id)).toBe(false);
    await b.engine.sync();
    expect(b.engine.items().some((i) => i.id === x.id)).toBe(false);
  });

  // F-4 (fixed): a password change made on a device that has not seen a Secret Key rotation.
  it('a password change from a device with an older Secret Key keeps the account usable', async () => {
    const { server, a } = await account();
    await a.engine.sync();
    const b = await paired(server, a);
    // A replaces the Secret Key (for example after removing a lost device); B stays unlocked.
    await a.engine.rotateSecretKey({ password: PASSWORD });
    const NEW = 'synthetic changed passphrase 8b7e';
    expect(
      await code(b.engine.changePassword({ currentPassword: PASSWORD, newPassword: NEW })),
    ).toBe('ok');
    // A, which holds the current Secret Key, must open the new server wrap with the new password.
    a.engine.wipeMemory();
    server.sessionValid = false;
    const again = await device(server, a.factory);
    expect(await code(again.engine.unlock({ password: NEW }))).toBe('ok');
  });

  // F-12: an unlock that fails after installing its session (here: the stored device key does not
  // open) used to leave the engine unlocked, with AK in memory.
  it('an unlock that fails after installing its session leaves nothing unlocked', async () => {
    const { a } = await account();
    await a.store.apply({ local: { 'device-key': new Uint8Array(96).fill(7) } });
    a.engine.wipeMemory();
    expect(await code(a.engine.unlock({ password: PASSWORD }))).not.toBe('ok');
    expect(() => a.engine.items()).toThrow();
  });

  // F-13: a lock that lands while an operation runs, which then fails, keeps nothing either.
  it('a lock during an operation that then fails leaves no session behind', async () => {
    const { a } = await account();
    await a.store.apply({ local: { 'device-key': new Uint8Array(96).fill(7) } });
    a.engine.wipeMemory();
    const unlocking = code(a.engine.unlock({ password: PASSWORD }));
    a.engine.wipeMemory();
    expect(await unlocking).not.toBe('ok');
    expect(() => a.engine.items()).toThrow();
  });

  // F-15: a proxy's error page during pairing used to burn the pairing as a MAC failure.
  it('a non-API error page tells the client nothing about the pairing request', async () => {
    const server = new FakeServer();
    const api = server.api();
    const { a: b } = await account(server, api);
    const { pairingId } = await b.engine.pairingStart();
    const realState = api.pairingState;
    api.pairingState = () => Promise.reject(new NetworkError('unexpected_error'));
    expect(await code(b.engine.pairingStatus({ pairingId }))).toBe('offline');
    expect(server.pairingCancels).toEqual([]);
    // Still hosted: the next poll goes on normally.
    api.pairingState = realState;
    expect(await b.engine.pairingStatus({ pairingId })).toEqual({ state: 'waiting' });
    // A success whose body breaks the contract still burns it.
    api.pairingState = () => Promise.reject(new NetworkError('unexpected_response'));
    expect(await b.engine.pairingStatus({ pairingId })).toEqual({ state: 'failed' });
    expect(server.pairingCancels).toEqual([{ pairingId, reason: 'mac_failed' }]);
  });

  it('the API client tells a non-API error page from a malformed success', async () => {
    const reply = (status: number, body: string, type: string) => () =>
      Promise.resolve(new Response(body, { status, headers: { 'Content-Type': type } }));
    const reason = async (run: () => Promise<unknown>) => {
      try {
        await run();
        return 'ok';
      } catch (error) {
        return error instanceof NetworkError ? error.reason : String(error);
      }
    };
    const real = globalThis.fetch;
    try {
      const api = createApi({ ...SAME_ORIGIN, baseUrl: 'http://127.0.0.1:9/api/v1' });
      globalThis.fetch = reply(502, '<html>Bad Gateway</html>', 'text/html');
      expect(await reason(() => api.pairingState('A'.repeat(43)))).toBe('unexpected_error');
      globalThis.fetch = reply(200, '{"state":"nonsense"}', 'application/json');
      expect(await reason(() => api.pairingState('A'.repeat(43)))).toBe('unexpected_response');
    } finally {
      globalThis.fetch = real;
    }
  });

  // F-17: one refused proof (an expired or replaced nonce) used to be reported as a missing device
  // key, which sends the user to re-enroll with the Recovery Kit.
  it('a refused proof is reported as retryable, and trying again works', async () => {
    const server = new FakeServer();
    const api = server.api();
    const { a } = await account(server, api);
    const real = api.rotateSecretKey;
    api.rotateSecretKey = () =>
      Promise.reject(new ApiError(401, 'device_proof_failed', undefined, undefined));
    expect(await code(a.engine.rotateSecretKey({ password: PASSWORD }))).toBe('proof_rejected');
    api.rotateSecretKey = real;
    expect(await code(a.engine.rotateSecretKey({ password: PASSWORD }))).toBe('ok');
  });
});
