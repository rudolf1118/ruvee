// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { Api } from '../api.js';
import type { ItemDraft } from '../protocol.js';
import { DeviceStore } from '../store.js';
import { FakeServer, fakeOpaque } from '../test-support.js';
import { VaultEngine, VaultError } from '../vault-engine.js';

/**
 * Follow-up review S-5: in a recovery on a browser that holds this account's vault, the account
 * id and `AK`'s id are authenticated by the recovery wrap and the vault id by the keyset; only the
 * device id is the server's word. A server that answers with another device id for the same
 * account, key and vault must not be able to present the local vault as "another account's",
 * whose erasure one checkbox confirms. Synthetic data only.
 */

const PASSWORD = 'synthetic engine passphrase 4c1e';
let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

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

async function engineOn(factory: IDBFactory, api: Api) {
  return new VaultEngine({
    crypto,
    api,
    store: await DeviceStore.open(factory),
    opaque: fakeOpaque,
    origin: 'http://127.0.0.1:3101',
    platform: 'web',
    now: () => Date.now(),
    emit: () => undefined,
  });
}

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (error) {
    return error instanceof VaultError ? error.code : String(error);
  }
};

/** An account with an unsynced edit on this browser, locked, and its Recovery Kit. */
async function forgotten() {
  const server = new FakeServer();
  const factory = new IDBFactory();
  const api = server.api();
  const a = await engineOn(factory, api);
  const kit = await a.setupBegin({
    bootstrapToken: 'T'.repeat(43),
    username: 'Synthetic-User',
    password: PASSWORD,
  });
  await a.setupVerifyKit({ recoveryKey: kit.recoveryKey });
  await a.setupFinish();
  server.offline = true;
  await a.save({ draft: note('Unsynced on this browser') });
  await a.idle();
  server.offline = false;
  a.wipeMemory();
  return { server, factory, api, kit: kit.recoveryKey };
}

/** The same server, but recovery start names another device id. */
function lyingAboutDevice(api: Api): Api {
  return {
    ...api,
    recoveryStart: async (body) => ({
      ...(await api.recoveryStart(body)),
      deviceId: crypto.generateUuid(),
    }),
  };
}

describe('S-5: a recovery whose server changes the device id', () => {
  it('is refused as an integrity failure, not offered as another account to erase', async () => {
    const { factory, api, kit } = await forgotten();
    const engine = await engineOn(factory, lyingAboutDevice(api));
    expect(await code(engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit }))).toBe(
      'integrity',
    );
    // Confirming the erasure does not help: it is the same account, so nothing is erased.
    expect(
      await code(
        engine.recoveryBegin({
          username: 'synthetic-user',
          recoveryKey: kit,
          replaceLocalData: true,
        }),
      ),
    ).toBe('integrity');
    const kept = await (await engineOn(factory, api)).phase();
    expect(kept.phase).toBe('enrolled');
  });

  it('an honest server keeps the local vault, its unsynced edit included', async () => {
    const { factory, api, kit } = await forgotten();
    const engine = await engineOn(factory, api);
    await engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit });
    const fresh = await engine.recoverySetPassword({ password: 'synthetic recovered lantern 93' });
    await engine.recoveryVerifyKit({ recoveryKey: fresh.recoveryKey });
    const done = await engine.recoveryFinish();
    expect(done.recovered?.keptLocal?.pending).toBe(1);
  });
});
