// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { ItemDraft } from './protocol.js';
import { DeviceStore, STORES } from './store.js';
import { FakeServer, fakeOpaque } from './test-support.js';
import { totpCodes } from './totp.js';
import { VaultEngine, VaultError } from './vault-engine.js';

/** Authenticator codes in the engine (D-35, totp-authenticator.md §4, §11 T1). */

const PASSWORD = 'synthetic totp passphrase 7f2a';
const TOKEN = 'T'.repeat(43);
// RFC 6238's SHA-1 seed; distinctive enough to search for in what the server and store hold.
const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
const OTHER_SECRET = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';
const URI = `otpauth://totp/Synthetic:someone?secret=${SECRET.toLowerCase()}&issuer=Synthetic&digits=8`;
const T = 1_111_111_109_000;

let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

async function device(server: FakeServer, clock: { now: number }, factory = new IDBFactory()) {
  const store = await DeviceStore.open(factory);
  const engine = new VaultEngine({
    crypto,
    api: server.api(),
    store,
    opaque: fakeOpaque,
    origin: 'http://127.0.0.1:3101',
    platform: 'web',
    now: () => clock.now,
    emit: () => undefined,
  });
  return { engine, store, factory };
}

async function account(clock = { now: T }) {
  const server = new FakeServer();
  const a = await device(server, clock);
  const kit = await a.engine.setupBegin({
    bootstrapToken: TOKEN,
    username: 'Synthetic-User',
    password: PASSWORD,
  });
  await a.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
  await a.engine.setupFinish();
  await a.engine.phase();
  return { server, a, kit: kit.recoveryKey, clock };
}

const login = (extra: Partial<ItemDraft> = {}): ItemDraft => ({
  type: 'login',
  title: 'Synthetic Mail',
  username: 'someone@mail.example',
  password: 'synthetic-item-secret',
  urls: ['https://mail.example'],
  notes: '',
  noteText: '',
  tags: [],
  favorite: false,
  ...extra,
});

async function code(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
    return 'resolved';
  } catch (e) {
    return e instanceof VaultError ? e.code : String(e);
  }
}

describe('authenticator codes in the engine', () => {
  it('stores the canonical secret, returns codes not the secret, and sends only ciphertext', async () => {
    const { server, a } = await account();
    const saved = await a.engine.save({ draft: login({ totp: URI }) });
    await a.engine.sync();

    const detail = a.engine.detail({ id: saved.id });
    expect(detail.hasTotp).toBe(true);
    expect(JSON.stringify(detail)).not.toContain(SECRET);

    const view = await a.engine.totp({ id: saved.id });
    const expected = await totpCodes(
      { secret: SECRET, algorithm: 'SHA1', digits: 8, period: 30 },
      T,
    );
    expect(view).toEqual({
      code: '07081804', // RFC 6238 Appendix B, SHA-1, T = 1111111109
      nextCode: expected.nextCode,
      digits: 8,
      period: 30,
      validUntilMs: expected.validUntilMs,
      clockSkewMs: null,
    });
    expect(JSON.stringify(view)).not.toContain(SECRET);

    // INV-01 and INV-16: the secret is in neither the requests nor the device store.
    expect(server.received.join('\n')).not.toContain(SECRET);
    expect(server.received.join('\n').toLowerCase()).not.toContain(SECRET.toLowerCase());
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
    expect(dump.join('\n')).not.toContain(SECRET);
  });

  it('follows the device clock', async () => {
    const { a, clock } = await account();
    const saved = await a.engine.save({ draft: login({ totp: SECRET }) });
    const first = await a.engine.totp({ id: saved.id });
    clock.now = first.validUntilMs;
    const second = await a.engine.totp({ id: saved.id });
    expect(second.code).toBe(first.nextCode);
    expect(second.validUntilMs).toBe(first.validUntilMs + 30_000);
  });

  it('keeps the secret when a draft leaves it out, replaces it, and removes it with null', async () => {
    const { a } = await account();
    const saved = await a.engine.save({ draft: login({ totp: SECRET }) });
    const original = await a.engine.totp({ id: saved.id });

    // An edit of the title: the draft carries no `totp`, the secret is kept.
    await a.engine.save({ draft: login({ id: saved.id, title: 'Renamed' }) });
    expect(a.engine.detail({ id: saved.id })).toMatchObject({ title: 'Renamed', hasTotp: true });
    expect((await a.engine.totp({ id: saved.id })).code).toBe(original.code);

    // Favorite, trash and restore rewrite the body and keep the field too.
    await a.engine.setFavorite({ id: saved.id, favorite: true });
    await a.engine.trash({ id: saved.id });
    await a.engine.restore({ id: saved.id });
    expect((await a.engine.totp({ id: saved.id })).code).toBe(original.code);

    await a.engine.save({ draft: login({ id: saved.id, totp: OTHER_SECRET }) });
    expect((await a.engine.totp({ id: saved.id })).code).not.toBe(original.code);

    await a.engine.save({ draft: login({ id: saved.id, totp: null }) });
    expect(a.engine.detail({ id: saved.id }).hasTotp).toBe(false);
    expect(await code(a.engine.totp({ id: saved.id }))).toBe('not_found');
  });

  it('refuses an invalid authenticator as a whole and leaves the item unchanged', async () => {
    const { a } = await account();
    const saved = await a.engine.save({ draft: login({ totp: SECRET }) });
    for (const bad of ['not base32!', `otpauth://hotp/x?secret=${SECRET}`, 'GEZDGNBV'])
      expect(await code(a.engine.save({ draft: login({ id: saved.id, totp: bad }) }))).toBe(
        'invalid_item',
      );
    expect(a.engine.detail({ id: saved.id }).hasTotp).toBe(true);
    // A note never carries one, whatever the draft says.
    const note = await a.engine.save({
      draft: { ...login({ totp: SECRET }), type: 'note', noteText: 'synthetic note' },
    });
    expect(a.engine.detail({ id: note.id }).hasTotp).toBe(false);
  });

  it('has no code for a note, a login without one, an unknown id, or a locked vault', async () => {
    const { a } = await account();
    const plain = await a.engine.save({ draft: login() });
    const note = await a.engine.save({
      draft: { ...login(), type: 'note', noteText: 'synthetic note' },
    });
    const withCode = await a.engine.save({ draft: login({ totp: SECRET }) });
    expect(a.engine.detail({ id: plain.id }).hasTotp).toBe(false);
    expect(await code(a.engine.totp({ id: plain.id }))).toBe('not_found');
    expect(await code(a.engine.totp({ id: note.id }))).toBe('not_found');
    expect(await code(a.engine.totp({ id: crypto.generateUuid() }))).toBe('not_found');
    a.engine.wipeMemory();
    expect(await code(a.engine.totp({ id: withCode.id }))).toBe('locked');
  });

  it('syncs to a second device, and travels in the encrypted export', async () => {
    const { server, a, kit, clock } = await account();
    const saved = await a.engine.save({ draft: login({ totp: SECRET }) });
    await a.engine.sync();
    const expected = await a.engine.totp({ id: saved.id });

    const file = await a.engine.exportVault({ password: PASSWORD, recoveryKey: kit });
    const clean = await device(new FakeServer(), clock);
    const view = clean.engine.exportOpen({ text: file.text, recoveryKey: kit });
    expect(view.items[0]).toMatchObject({ title: 'Synthetic Mail', hasTotp: true });
    expect(file.text).not.toContain(SECRET);

    // The second device reads the record from the same server and computes the same code.
    const b = await device(server, clock);
    await b.engine.login({ username: 'synthetic-user', password: PASSWORD });
    const started = await a.engine.pairingStart();
    await b.engine.pairingJoin({ code: started.code });
    await a.engine.pairingStatus({ pairingId: started.pairingId });
    await b.engine.pairingWait();
    await a.engine.pairingApprove({ pairingId: started.pairingId });
    expect((await b.engine.pairingWait()).state).toBe('enrolled');
    await b.engine.sync();
    expect((await b.engine.totp({ id: saved.id })).code).toBe(expected.code);
  });
});
