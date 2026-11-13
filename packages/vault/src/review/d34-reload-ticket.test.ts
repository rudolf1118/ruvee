// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { Api } from '../api.js';
import { toB64 } from '../bytes.js';
import type { ItemDraft, ReloadTicket } from '../protocol.js';
import { DeviceStore } from '../store.js';
import { FakeServer, fakeOpaque } from '../test-support.js';
import { VaultEngine, VaultError } from '../vault-engine.js';

/**
 * D-34 web reload tickets in the engine (docs/security/web-reload-unlock.md §5, INV-25). A
 * "reload" is a new engine on the same IndexedDB and the same API session (the cookie survives a
 * reload); it gets only what the page kept in `sessionStorage`. Synthetic data only.
 */

const PASSWORD = 'synthetic engine passphrase 4c1e';
const IDLE = 900;
let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

async function device(
  server: FakeServer,
  factory = new IDBFactory(),
  api: Api = server.api(),
  platform: 'web' | 'extension' = 'web',
) {
  const store = await DeviceStore.open(factory);
  const engine = new VaultEngine({
    crypto,
    api,
    store,
    opaque: fakeOpaque,
    origin: 'http://127.0.0.1:3101',
    platform,
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

async function unlockedTab() {
  const server = new FakeServer();
  const tab = await device(server);
  const kit = await tab.engine.setupBegin({
    bootstrapToken: 'T'.repeat(43),
    username: 'Synthetic-User',
    password: PASSWORD,
  });
  await tab.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
  await tab.engine.setupFinish();
  await tab.engine.save({ draft: note('kept across reloads') });
  await tab.engine.sync();
  return { server, tab };
}

/** The page reloads: the worker and its memory are gone; IndexedDB and the cookie are kept. */
async function reload(
  server: FakeServer,
  tab: { engine: VaultEngine; factory: IDBFactory; api: Api },
) {
  tab.engine.wipeMemory();
  return device(server, tab.factory, tab.api);
}

async function issued(engine: VaultEngine): Promise<ReloadTicket> {
  const ticket = await engine.reloadTicketIssue({ idleSeconds: IDLE });
  if (!ticket) throw new Error('no ticket');
  return ticket;
}

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (error) {
    return error instanceof VaultError ? error.code : String(error);
  }
};

describe('D-34 web reload ticket in the engine', () => {
  it('resumes after a reload without the password, then issues a new ticket', async () => {
    const { server, tab } = await unlockedTab();
    const ticket = await issued(tab.engine);
    expect(server.reloadTickets.size).toBe(1);
    const next = await reload(server, tab);
    expect((await next.engine.phase()).phase).toBe('enrolled');
    const vault = await next.engine.reloadTicketResume(ticket);
    expect(vault.items.map((i) => i.title)).toEqual(['kept across reloads']);
    // Single use: the server forgot it.
    expect(server.reloadTickets.size).toBe(0);
    const again = await issued(next.engine);
    expect(again.ticketId).not.toBe(ticket.ticketId);
    expect(server.reloadTickets.size).toBe(1);
  });

  it('keeps AK and the server half out of what the page holds', async () => {
    const { tab } = await unlockedTab();
    const ticket = await issued(tab.engine);
    const ak = tab.engine.accountKeyForResume();
    const text = JSON.stringify(ticket);
    expect(text).not.toContain(toB64(ak));
    expect(Object.keys(ticket).sort()).toEqual(['envelope', 'tabHalf', 'ticketId']);
  });

  it('is single use: a second resume with the same ticket stays locked', async () => {
    const { server, tab } = await unlockedTab();
    const ticket = await issued(tab.engine);
    const first = await reload(server, tab);
    await first.engine.reloadTicketResume(ticket);
    const second = await reload(server, first);
    expect(await code(second.engine.reloadTicketResume(ticket))).toBe('locked');
    expect(await code(Promise.resolve().then(() => second.engine.items()))).toBe('locked');
  });

  it('lock (drop) ends it on the server', async () => {
    const { server, tab } = await unlockedTab();
    const ticket = await issued(tab.engine);
    await tab.engine.reloadTicketDrop();
    expect(server.reloadTickets.size).toBe(0);
    const next = await reload(server, tab);
    expect(await code(next.engine.reloadTicketResume(ticket))).toBe('locked');
  });

  it('ends 3 minutes after the last heartbeat (closed tab)', async () => {
    const { server, tab } = await unlockedTab();
    const ticket = await issued(tab.engine);
    const entry = server.reloadTickets.get(ticket.ticketId);
    if (entry) entry.expiresAtMs = Date.now() - 1;
    const next = await reload(server, tab);
    expect(await code(next.engine.reloadTicketResume(ticket))).toBe('locked');
  });

  it('ends after the auto-lock period without activity', async () => {
    const { server, tab } = await unlockedTab();
    const ticket = await issued(tab.engine);
    const entry = server.reloadTickets.get(ticket.ticketId);
    if (entry) entry.idleExpiresAtMs = Date.now() - 1;
    const next = await reload(server, tab);
    expect(await code(next.engine.reloadTicketResume(ticket))).toBe('locked');
  });

  it('ends with logout', async () => {
    const { server, tab } = await unlockedTab();
    const ticket = await issued(tab.engine);
    await tab.engine.logout();
    expect(server.reloadTickets.size).toBe(0);
    const next = await device(server, tab.factory, tab.api);
    expect(await code(next.engine.reloadTicketResume(ticket))).toBe('locked');
  });

  it('offline, a reload stays locked; the password still unlocks offline (D-23)', async () => {
    const { server, tab } = await unlockedTab();
    const ticket = await issued(tab.engine);
    server.offline = true;
    const next = await reload(server, tab);
    expect(await code(next.engine.reloadTicketResume(ticket))).toBe('locked');
    const vault = await next.engine.unlock({ password: PASSWORD });
    expect(vault.items.map((i) => i.title)).toEqual(['kept across reloads']);
  });

  it('refuses another session, a wrong tab half and an altered envelope', async () => {
    const { server, tab } = await unlockedTab();
    const ticket = await issued(tab.engine);
    // A copy of the tab's storage used with another session (another cookie).
    const elsewhere = await device(server, tab.factory, server.api());
    expect(await code(elsewhere.engine.reloadTicketResume(ticket))).toBe('locked');

    const t2 = await issued(tab.engine);
    const wrongHalf = await reload(server, tab);
    expect(
      await code(
        wrongHalf.engine.reloadTicketResume({ ...t2, tabHalf: toB64(new Uint8Array(32)) }),
      ),
    ).toBe('locked');

    await wrongHalf.engine.unlock({ password: PASSWORD });
    const t3 = await issued(wrongHalf.engine);
    const altered = await reload(server, wrongHalf);
    const bytes = Buffer.from(t3.envelope, 'base64url');
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 1;
    expect(
      await code(
        altered.engine.reloadTicketResume({ ...t3, envelope: bytes.toString('base64url') }),
      ),
    ).toBe('locked');
    expect(await code(altered.engine.reloadTicketResume({ ...t3, ticketId: 'x' }))).toBe('locked');
  });

  it('heartbeats keep it; one the server lost is replaced while the tab is unlocked', async () => {
    const { server, tab } = await unlockedTab();
    const ticket = await issued(tab.engine);
    const entry = server.reloadTickets.get(ticket.ticketId);
    if (entry) {
      entry.expiresAtMs = Date.now() + 1000;
      entry.idleExpiresAtMs = Date.now() + 1000;
    }
    expect(await tab.engine.reloadTicketHeartbeat({ active: true, idleSeconds: IDLE })).toBeNull();
    expect(entry?.expiresAtMs).toBeGreaterThan(Date.now() + 170_000);
    expect(entry?.idleExpiresAtMs).toBeGreaterThan(Date.now() + 800_000);
    // The tab slept past the limit: the next heartbeat gets a new ticket.
    server.reloadTickets.clear();
    const replaced = await tab.engine.reloadTicketHeartbeat({ active: false, idleSeconds: IDLE });
    expect(replaced?.ticketId).toBeDefined();
    expect(replaced?.ticketId).not.toBe(ticket.ticketId);
    // Offline: nothing changes, nothing is thrown.
    server.offline = true;
    expect(await tab.engine.reloadTicketHeartbeat({ active: true, idleSeconds: IDLE })).toBeNull();
  });

  it('a locked engine issues and heartbeats nothing; the extension never uses tickets', async () => {
    const { server, tab } = await unlockedTab();
    tab.engine.wipeMemory();
    expect(await code(tab.engine.reloadTicketIssue({ idleSeconds: IDLE }))).toBe('locked');
    expect(await code(tab.engine.reloadTicketHeartbeat({ active: true, idleSeconds: IDLE }))).toBe(
      'locked',
    );
    const ext = await device(server, new IDBFactory(), server.api(), 'extension');
    expect(await code(ext.engine.reloadTicketIssue({ idleSeconds: IDLE }))).toBe('internal');
  });
});
