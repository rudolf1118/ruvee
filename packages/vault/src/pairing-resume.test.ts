// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { Api } from './api.js';
import { DeviceStore } from './store.js';
import { FakeServer, fakeOpaque } from './test-support.js';
import { VaultEngine, VaultError } from './vault-engine.js';

/**
 * Device B's join outlives the UI that started it (rehearsal finding A-07): the extension popup
 * closes while the user approves on device A, and its service worker may restart meanwhile.
 * Synthetic data only.
 */

const PASSWORD = 'synthetic pairing passphrase 9d2a';
const TOKEN = 'T'.repeat(43);
const MINUTE = 60_000;

let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

/** A clock the test moves; every engine of one test shares it. */
function clock() {
  let offset = 0;
  return {
    now: () => Date.now() + offset,
    advance: (ms: number) => {
      offset += ms;
    },
  };
}

interface Browser {
  engine: VaultEngine;
  api: Api;
  factory: IDBFactory;
}

/** One browser profile: its device store and its session survive an engine restart. */
async function browser(
  server: FakeServer,
  now: () => number,
  same?: { factory: IDBFactory; api: Api },
): Promise<Browser> {
  const factory = same?.factory ?? new IDBFactory();
  const api = same?.api ?? server.api();
  const engine = new VaultEngine({
    crypto,
    api,
    store: await DeviceStore.open(factory),
    opaque: fakeOpaque,
    origin: 'http://127.0.0.1:3101',
    platform: 'web',
    now,
    emit: () => undefined,
  });
  return { engine, api, factory };
}

async function code(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return 'resolved';
  } catch (e) {
    return e instanceof VaultError ? e.code : String(e);
  }
}

async function accountAndPendingBrowser() {
  const server = new FakeServer();
  const time = clock();
  const a = await browser(server, time.now);
  const kit = await a.engine.setupBegin({
    bootstrapToken: TOKEN,
    username: 'Synthetic-Pairer',
    password: PASSWORD,
  });
  await a.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
  await a.engine.setupFinish();
  const b = await browser(server, time.now);
  await b.engine.login({ username: 'synthetic-pairer', password: PASSWORD });
  return { server, time, a, b };
}

describe('pairing that outlives its UI', () => {
  it('reports the join locally, so a reopened UI resumes it instead of offering a new code', async () => {
    const { a, b } = await accountAndPendingBrowser();
    expect(b.engine.pairingJoinState()).toEqual({ state: 'none' });
    const started = await a.engine.pairingStart();
    await b.engine.pairingJoin({ code: started.code });
    expect(b.engine.pairingJoinState()).toMatchObject({ state: 'joined', needsPassword: false });
    await a.engine.pairingStatus({ pairingId: started.pairingId });
    await a.engine.pairingApprove({ pairingId: started.pairingId });
    expect((await b.engine.pairingWait()).state).toBe('enrolled');
    expect(b.engine.pairingJoinState()).toEqual({ state: 'none' });
    // A second poller (the popup next to the worker's own loop) sees the same outcome.
    expect((await b.engine.pairingWait()).state).toBe('enrolled');
  });

  it('finishes after the login password expired: polls and proves first, then asks only for the password', async () => {
    const { server, time, a, b } = await accountAndPendingBrowser();
    time.advance(8 * MINUTE);
    const started = await a.engine.pairingStart();
    await b.engine.pairingJoin({ code: started.code });
    await a.engine.pairingStatus({ pairingId: started.pairingId });
    await a.engine.pairingApprove({ pairingId: started.pairingId });
    // The password from the login (10 minutes) is gone; the join (10 minutes from joining) is not.
    time.advance(3 * MINUTE);
    expect(b.engine.pairingJoinState()).toMatchObject({ state: 'joined', needsPassword: true });
    expect(await code(b.engine.pairingWait())).toBe('password_required');
    // The poll reached the server and proved the session at once (before its ten minutes ran out).
    expect(server.pairings.get(started.pairingId)?.state).toBe('approved');
    expect(b.engine.pairingJoinState()).toMatchObject({ state: 'joined', needsPassword: true });
    // The way to finish: the password for this join, never a second join.
    expect(await code(b.engine.pairingJoin({ code: started.code, password: PASSWORD }))).toBe(
      'pairing_interrupted',
    );
    expect(await code(b.engine.pairingWait({ password: 'synthetic wrong guess 3' }))).toBe(
      'wrong_password',
    );
    const joined = await b.engine.pairingWait({ password: PASSWORD });
    expect(joined.state).toBe('enrolled');
    expect(await b.engine.phase()).toMatchObject({ phase: 'enrolled' });
  });

  it('waits without the password until the approval arrives', async () => {
    const { time, a, b } = await accountAndPendingBrowser();
    time.advance(9 * MINUTE);
    const started = await a.engine.pairingStart();
    await b.engine.pairingJoin({ code: started.code });
    time.advance(2 * MINUTE);
    expect(await b.engine.pairingWait()).toEqual({ state: 'waiting' });
  });

  it('survives a restart of the process that holds it, without keeping the password', async () => {
    const { a, b, server, time } = await accountAndPendingBrowser();
    const started = await a.engine.pairingStart();
    await b.engine.pairingJoin({ code: started.code });
    const snapshot = b.engine.pairingJoinSnapshot();
    expect(snapshot).toBeDefined();
    expect(JSON.stringify(snapshot)).not.toContain(PASSWORD);
    b.engine.wipeMemory();

    // The same browser profile and session; a new engine with nothing in memory.
    const restarted = await browser(server, time.now, b);
    expect(restarted.engine.pairingJoinState()).toEqual({ state: 'none' });
    expect(await restarted.engine.pairingJoinRestore(snapshot)).toBe(true);
    expect(restarted.engine.pairingJoinState()).toMatchObject({
      state: 'joined',
      needsPassword: true,
    });
    expect(await restarted.engine.pairingWait()).toEqual({ state: 'waiting' });
    await a.engine.pairingStatus({ pairingId: started.pairingId });
    await a.engine.pairingApprove({ pairingId: started.pairingId });
    expect(await code(restarted.engine.pairingWait())).toBe('password_required');
    expect((await restarted.engine.pairingWait({ password: PASSWORD })).state).toBe('enrolled');
    // The device key made before the restart is the one enrolled: the device proves it again.
    const again = await browser(server, time.now, restarted);
    expect((await again.engine.unlock({ password: PASSWORD })).items).toEqual([]);
  });

  it('restores a snapshot only for the same pending device and before the join expires', async () => {
    const { a, b, server, time } = await accountAndPendingBrowser();
    const started = await a.engine.pairingStart();
    await b.engine.pairingJoin({ code: started.code });
    const snapshot = b.engine.pairingJoinSnapshot();
    const other = await browser(server, time.now);
    await other.engine.login({ username: 'synthetic-pairer', password: PASSWORD });
    expect(await other.engine.pairingJoinRestore(snapshot)).toBe(false);
    const same = await browser(server, time.now, b);
    expect(await same.engine.pairingJoinRestore({ ...snapshot, secret: '!' })).toBe(false);
    expect(await same.engine.pairingJoinRestore('not a snapshot')).toBe(false);
    time.advance(11 * MINUTE);
    expect(await same.engine.pairingJoinRestore(snapshot)).toBe(false);
    expect(same.engine.pairingJoinState()).toEqual({ state: 'none' });
  });

  it('names a join the server no longer accepts, so the UI can offer a new login', async () => {
    const { a, b, server, time } = await accountAndPendingBrowser();
    const started = await a.engine.pairingStart();
    await b.engine.pairingJoin({ code: started.code });
    await a.engine.pairingStatus({ pairingId: started.pairingId });
    await a.engine.pairingApprove({ pairingId: started.pairingId });
    // The join is lost (a browser restart clears memory-only storage) after the approval.
    b.engine.wipeMemory();
    const lost = await browser(server, time.now, b);
    expect(await code(lost.engine.pairingWait())).toBe('pairing_expired');
    const next = await a.engine.pairingStart();
    expect(await code(lost.engine.pairingJoin({ code: next.code, password: PASSWORD }))).toBe(
      'pairing_interrupted',
    );
    // A new login starts a new pending device, which pairs normally.
    expect(
      await lost.engine.login({ username: 'synthetic-pairer', password: PASSWORD }),
    ).toMatchObject({ phase: 'pending' });
    const third = await a.engine.pairingStart();
    await lost.engine.pairingJoin({ code: third.code });
    await a.engine.pairingStatus({ pairingId: third.pairingId });
    await a.engine.pairingApprove({ pairingId: third.pairingId });
    expect((await lost.engine.pairingWait()).state).toBe('enrolled');
  });
});
