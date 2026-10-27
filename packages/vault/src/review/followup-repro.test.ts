// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { ItemDraft } from '../protocol.js';
import { DeviceStore } from '../store.js';
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
  // F-2: two tabs of one browser run two engines on one IndexedDB; each writes its own memory.
  it.fails('two engines on one store keep both tabs’ unsynced edits', async () => {
    const { server, a } = await account();
    await a.engine.sync();
    const tab2 = await device(server, a.factory);
    await tab2.engine.unlock({ password: PASSWORD });
    server.offline = true;
    await a.engine.save({ draft: note('Saved in tab 1') });
    await a.engine.idle();
    await tab2.engine.save({ draft: note('Saved in tab 2') });
    await tab2.engine.idle();
    a.engine.wipeMemory();
    tab2.engine.wipeMemory();
    const reopened = await device(server, a.factory);
    const view = await reopened.engine.unlock({ password: PASSWORD });
    expect(view.items.map((i) => i.title).sort()).toEqual(['Saved in tab 1', 'Saved in tab 2']);
  });

  // F-3: an offline edit of an item in "deleted here, edited elsewhere" conflict, then "mine".
  it.fails('resolving a conflict never queues two mutations of one item', async () => {
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
  });

  // F-4: a password change made on a device that has not seen a Secret Key rotation.
  it.fails(
    'a password change from a device with an older Secret Key keeps the account usable',
    async () => {
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
    },
  );
});
