// @vitest-environment node
import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import type { Api } from './api.js';
import { EXPORT_MAX_ITEMS, openExport } from './export-file.js';
import type { ItemDraft, VaultEvent } from './protocol.js';
import { DeviceStore } from './store.js';
import { FakeServer, fakeOpaque } from './test-support.js';
import { VaultEngine, VaultError } from './vault-engine.js';

/**
 * Import into a fresh installation (backup-restore.md §4.4a). The fixed fixture in
 * test/fixtures was generated once from export-v1.expected.json (see the README there); the
 * expected contents are that hand-written file, not output of the code under test.
 */

const FIXTURES = new URL('../test/fixtures/', import.meta.url);
const fixture = (name: string) => readFileSync(new URL(name, FIXTURES), 'utf8');
const SOURCE_PASSWORD = 'synthetic fixture source passphrase 2b';
const PASSWORD = 'synthetic import destination passphrase 9d';
const TOKEN = 'T'.repeat(43);

interface ExpectedItem {
  type: 'login' | 'note';
  title: string;
  username?: string;
  password?: string;
  urls?: string[];
  notes?: string;
  noteText?: string;
  tags: string[];
  favorite: boolean;
  trashedAtMs: number | null;
  createdAtMs: number;
  updatedAtMs: number;
}
interface Expected {
  asOfMs: number;
  deletedCount: number;
  items: ExpectedItem[];
}
const expected = JSON.parse(fixture('export-v1.expected.json')) as Expected;
function fixtureItem(n: number): ExpectedItem {
  const item = expected.items[n];
  if (!item) throw new Error(`no fixture item ${String(n)}`);
  return item;
}
// Plaintext sentinels are the fixture's distinctive values (8+ characters): a short one such as
// "owner" also occurs in unrelated synthetic usernames.

let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

interface Device {
  engine: VaultEngine;
  api: Api;
  store: DeviceStore;
  factory: IDBFactory;
  events: VaultEvent[];
}

async function device(
  server: FakeServer,
  options: { factory?: IDBFactory; api?: Api; now?: () => number } = {},
): Promise<Device> {
  const factory = options.factory ?? new IDBFactory();
  const api = options.api ?? server.api();
  const store = await DeviceStore.open(factory);
  const events: VaultEvent[] = [];
  const engine = new VaultEngine({
    crypto,
    api,
    store,
    opaque: fakeOpaque,
    origin: 'http://127.0.0.1:3101',
    platform: 'web',
    now: options.now ?? (() => Date.now()),
    emit: (e) => events.push(e),
  });
  return { engine, api, store, factory, events };
}

async function setUp(d: Device, username: string, password = PASSWORD): Promise<string> {
  const kit = await d.engine.setupBegin({ bootstrapToken: TOKEN, username, password });
  await d.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
  await d.engine.setupFinish();
  return kit.recoveryKey;
}

async function code(run: () => unknown): Promise<string> {
  try {
    await run();
    return 'resolved';
  } catch (e) {
    return e instanceof VaultError ? e.code : String(e);
  }
}

const draftOf = (i: ExpectedItem): ItemDraft => ({
  type: i.type,
  title: i.title,
  username: i.username ?? '',
  password: i.password ?? '',
  urls: i.urls ?? [],
  notes: i.notes ?? '',
  noteText: i.noteText ?? '',
  tags: i.tags,
  favorite: i.favorite,
});

/** What an import must reproduce, read back through the destination's own engine. */
function contents(d: Device): ExpectedItem[] {
  return d.engine
    .items()
    .map((summary) => {
      const item = d.engine.detail({ id: summary.id });
      const common = {
        type: item.type,
        title: item.title,
        tags: [...item.tags],
        favorite: item.favorite,
        trashedAtMs: item.trashed ? (trashedAt.get(item.title) ?? -1) : null,
        createdAtMs: item.createdAtMs,
        updatedAtMs: item.updatedAtMs,
      };
      return item.type === 'login'
        ? {
            ...common,
            username: item.username,
            password: d.engine.secret({ id: item.id }),
            urls: [...item.urls],
            notes: item.notes,
          }
        : { ...common, noteText: item.noteText };
    })
    .sort((a, b) => a.title.localeCompare(b.title));
}
/** The view model has `trashed` but not its time; the time is checked from the hand-written file. */
const trashedAt = new Map(
  expected.items.filter((i) => i.trashedAtMs !== null).map((i) => [i.title, i.trashedAtMs]),
);
const sortedExpected = () => [...expected.items].sort((a, b) => a.title.localeCompare(b.title));

describe('the fixed v1 export fixture', () => {
  it.runIf(process.env.WRITE_EXPORT_FIXTURE === '1')('is regenerated on request', async () => {
    let clock = expected.items[0]?.createdAtMs ?? 0;
    const source = await device(new FakeServer(), { now: () => clock });
    const kit = await setUp(source, 'synthetic-fixture-source', SOURCE_PASSWORD);
    const ids = new Map<string, string>();
    for (const item of expected.items) {
      clock = item.createdAtMs;
      ids.set(item.title, (await source.engine.save({ draft: draftOf(item) })).id);
      await source.engine.idle();
    }
    const bank = expected.items.find((i) => i.trashedAtMs !== null);
    if (!bank?.trashedAtMs) throw new Error('fixture needs one trashed item');
    clock = bank.trashedAtMs;
    await source.engine.trash({ id: ids.get(bank.title) ?? '' });
    await source.engine.idle();
    const gone = await source.engine.save({
      draft: { ...draftOf(bank), title: 'Synthetic Deleted' },
    });
    await source.engine.idle();
    await source.engine.trash({ id: gone.id });
    await source.engine.idle();
    clock = expected.asOfMs;
    await source.engine.purge({ id: gone.id });
    await source.engine.idle();
    const file = await source.engine.exportVault({ password: SOURCE_PASSWORD, recoveryKey: kit });
    writeFileSync(new URL('export-v1.ruvee', FIXTURES), `${file.text}\n`);
    writeFileSync(new URL('export-v1.recovery-key.txt', FIXTURES), `${kit}\n`);
  });

  let text = '';
  let kit = '';
  beforeAll(() => {
    if (process.env.WRITE_EXPORT_FIXTURE === '1') return;
    text = fixture('export-v1.ruvee').trim();
    kit = fixture('export-v1.recovery-key.txt').trim();
  });

  it('has the documented structure, checked without the export reader', () => {
    const file = JSON.parse(text) as Record<string, unknown> & {
      items: { itemId: string; record: string | null }[];
      keyset: { envelope: string };
      manifest: { envelope: string };
    };
    expect(Object.keys(file).sort()).toEqual(
      [
        'accountId',
        'akEpoch',
        'akId',
        'format',
        'items',
        'keyset',
        'manifest',
        'recoveryKeyId',
        'recoveryWrap',
        'vaultId',
        'version',
      ].sort(),
    );
    expect([file.format, file.version]).toEqual(['ruvee-export', 1]);
    // Envelope v1 header: "RV", format 1, algorithm 1, then the purpose byte.
    const header = (b64: string) => [...Buffer.from(b64, 'base64url').subarray(0, 5)];
    expect(header(String(file.recoveryWrap))).toEqual([0x52, 0x56, 1, 1, 0x02]);
    expect(header(file.keyset.envelope)).toEqual([0x52, 0x56, 1, 1, 0x03]);
    expect(header(file.manifest.envelope)).toEqual([0x52, 0x56, 1, 1, 0x06]);
    expect(Buffer.from(String(file.recoveryWrap), 'base64url')).toHaveLength(93);
    expect(Buffer.from(file.manifest.envelope, 'base64url')).toHaveLength(198);
    const live = file.items.filter((i) => i.record !== null);
    expect(live).toHaveLength(expected.items.length);
    expect(file.items.length - live.length).toBe(expected.deletedCount);
    for (const i of live)
      expect(
        Buffer.from(i.record ?? '', 'base64url')
          .subarray(0, 3)
          .toString(),
      ).toBe('RVI');
    const ids = file.items.map((i) => i.itemId);
    expect([...ids].sort()).toEqual(ids);
    // No plaintext anywhere in the file.
    for (const item of expected.items)
      for (const value of [item.title, item.password, item.noteText, item.username])
        if (value && value.length >= 8) expect(text).not.toContain(value);
  });

  it('opens with its Recovery Key and holds exactly the hand-written items', async () => {
    const viewer = await device(new FakeServer());
    const view = viewer.engine.exportOpen({ text, recoveryKey: kit });
    expect(view.asOfMs).toBe(expected.asOfMs);
    expect(view.deletedCount).toBe(expected.deletedCount);
    expect(view.items.map((i) => i.title).sort()).toEqual(
      expected.items.map((i) => i.title).sort(),
    );
  });
});

describe('import into a fresh installation', () => {
  interface Source {
    accountId: string;
    vaultId: string;
    akId: string;
    keyset: { envelope: string };
    manifest: { envelope: string };
    items: { itemId: string; record: string | null }[];
  }
  let source: Source;
  let text = '';
  let kit = '';
  beforeAll(() => {
    text = fixture('export-v1.ruvee').trim();
    kit = fixture('export-v1.recovery-key.txt').trim();
    source = JSON.parse(text) as Source;
  });
  const sha = (value: string) => createHash('sha256').update(value).digest('hex');

  it('reproduces every item under new keys, ids and history, and uploads nothing old', async () => {
    const before = sha(text);
    const server = new FakeServer();
    const b = await device(server);
    const newKit = await setUp(b, 'synthetic-import-owner');
    const view = b.engine.exportOpen({ text, recoveryKey: kit });
    expect(view.items).toHaveLength(expected.items.length);
    const status = await b.engine.importIntoEmptyVault();
    expect(status.import).toEqual({
      state: 'complete',
      total: expected.items.length,
      uploaded: expected.items.length,
      sourceAsOfMs: expected.asOfMs,
    });
    expect(contents(b)).toEqual(sortedExpected());

    // New account, vault, keys and item ids; a history of this vault's own.
    const account = server.account;
    if (!account) throw new Error('no account');
    expect(account.accountId).not.toBe(source.accountId);
    expect(account.vault.id).not.toBe(source.vaultId);
    expect(account.keys.akId).not.toBe(source.akId);
    expect(account.keys.keyset).not.toBe(source.keyset.envelope);
    expect(newKit).not.toBe(kit);
    const sourceIds = new Set(source.items.map((i) => i.itemId));
    expect([...server.items.keys()].filter((id) => sourceIds.has(id))).toEqual([]);
    expect([...server.items.values()].every((i) => i.revision === 1)).toBe(true);
    expect(server.items.size).toBe(expected.items.length);
    // The source manifest chain is not transplanted: the new chain is genesis plus the import.
    expect(server.manifests.map((m) => m.manifest)).not.toContain(source.manifest.envelope);

    // Nothing of the source went to the server: not its records, kit, keyset or any plaintext.
    const wire = server.received.join('\n');
    for (const i of source.items) if (i.record) expect(wire).not.toContain(i.record);
    for (const secret of [kit, kit.replace(/-/g, ''), source.keyset.envelope, 'ruvee-export'])
      expect(wire).not.toContain(secret);
    for (const item of expected.items)
      for (const value of [item.title, item.password, item.noteText, item.username])
        if (value && value.length >= 8) expect(wire, value).not.toContain(value);

    // Only the new device exists; no session, device or trust came from the export.
    expect(server.devices.size).toBe(1);
    // The export is unchanged, and the new credentials open the vault after a restart.
    expect(sha(text)).toBe(before);
    const restarted = await device(server, { factory: b.factory, api: b.api });
    const unlocked = await restarted.engine.unlock({ password: PASSWORD });
    expect(unlocked.sync.import?.state).toBe('complete');
    expect(contents(restarted)).toEqual(sortedExpected());
  });

  it('refuses a wrong kit, tampering, other versions and oversized input before anything', async () => {
    const server = new FakeServer();
    const b = await device(server);
    const other = crypto.formatRecoveryKey(crypto.generateRecoveryKey().recoveryKey);
    const open = (t: string, k = kit) =>
      code(() => b.engine.exportOpen({ text: t, recoveryKey: k }));
    expect(await open(text, other)).toBe('kit_mismatch');
    const parsed = JSON.parse(text) as Record<string, unknown> & {
      manifest: { seq: number };
      items: { revision: number }[];
    };
    expect(await open(JSON.stringify({ ...parsed, version: 2 }))).toBe('invalid_export');
    expect(await open(JSON.stringify({ ...parsed, format: 'other' }))).toBe('invalid_export');
    expect(
      await open(
        JSON.stringify({
          ...parsed,
          manifest: { ...parsed.manifest, seq: parsed.manifest.seq + 1 },
        }),
      ),
    ).toBe('integrity');
    expect(await open(text.slice(0, Math.floor(text.length / 2)))).toBe('invalid_export');
    // Input limits: the item count, and the size (lowered here; the default is 512 MiB).
    const many = Array.from({ length: EXPORT_MAX_ITEMS + 1 }, () => parsed.items[0]);
    expect(await open(JSON.stringify({ ...parsed, items: many }))).toBe('invalid_export');
    expect(await code(() => openExport(crypto, text, kit, { maxChars: text.length - 1 }))).toBe(
      'invalid_export',
    );
    // Nothing was created by any of this.
    expect(server.account).toBeUndefined();
    expect(await b.store.device()).toBeUndefined();
  });

  it('cancelling before the import starts leaves nothing, or only an empty new account', async () => {
    const server = new FakeServer();
    const b = await device(server);
    b.engine.exportOpen({ text, recoveryKey: kit });
    b.engine.exportClose();
    expect(server.account).toBeUndefined();
    await setUp(b, 'synthetic-import-cancelled');
    // The export was closed: there is nothing to import, and nothing was queued.
    expect(await code(() => b.engine.importIntoEmptyVault())).toBe('not_found');
    expect(server.items.size).toBe(0);
    expect(await b.store.importsCount()).toBe(0);
  });

  it('refuses a vault that holds anything, and a second import', async () => {
    const server = new FakeServer();
    const b = await device(server);
    await setUp(b, 'synthetic-import-nonempty');
    await b.engine.save({ draft: draftOf(fixtureItem(0)) });
    b.engine.exportOpen({ text, recoveryKey: kit });
    expect(await code(() => b.engine.importIntoEmptyVault())).toBe('vault_not_empty');
    const c = await device(new FakeServer());
    await setUp(c, 'synthetic-import-twice');
    c.engine.exportOpen({ text, recoveryKey: kit });
    await c.engine.importIntoEmptyVault();
    c.engine.exportOpen({ text, recoveryKey: kit });
    expect(await code(() => c.engine.importIntoEmptyVault())).toBe('vault_not_empty');
  });
});

describe('interrupted imports', () => {
  /** An export of 250 items, so the import takes three commits. */
  async function largeExport(): Promise<{ text: string; kit: string; titles: string[] }> {
    const source = await device(new FakeServer());
    const kit = await setUp(source, 'synthetic-large-source');
    const titles: string[] = [];
    for (let n = 0; n < 250; n++) {
      const title = `Synthetic note ${String(n).padStart(3, '0')}`;
      titles.push(title);
      await source.engine.save({
        draft: { ...draftOf(fixtureItem(2)), title },
      });
    }
    await source.engine.idle();
    const file = await source.engine.exportVault({ password: PASSWORD, recoveryKey: kit });
    return { text: file.text, kit, titles };
  }
  // One synthetic 250-item export for both tests below, built once: it is identical for both and
  // only read, and building it (250 saves and an export) is most of each test's time.
  let large: { text: string; kit: string; titles: string[] };
  beforeAll(async () => {
    large = await largeExport();
  });

  it('resumes after the connection drops mid-upload and a browser restart, without duplicates', async () => {
    const { text, kit, titles } = large;
    const server = new FakeServer();
    const b = await device(server);
    await setUp(b, 'synthetic-import-interrupted');
    b.engine.exportOpen({ text, recoveryKey: kit });
    server.commitBudget = 1;
    const partial = await b.engine.importIntoEmptyVault();
    expect(partial.import).toMatchObject({ state: 'uploading', total: 250, uploaded: 100 });
    expect(server.items.size).toBe(100);
    // Never complete while partial, and nothing else can be written meanwhile.
    expect(await code(() => b.engine.save({ draft: draftOf(fixtureItem(0)) }))).toBe(
      'import_in_progress',
    );

    server.commitBudget = undefined;
    const restarted = await device(server, { factory: b.factory, api: b.api });
    const unlocked = await restarted.engine.unlock({ password: PASSWORD });
    expect(unlocked.sync.import).toMatchObject({ state: 'complete', total: 250, uploaded: 250 });
    expect(server.items.size).toBe(250);
    expect(
      restarted.engine
        .items()
        .map((i) => i.title)
        .sort(),
    ).toEqual(titles);
    expect(await restarted.store.importsCount()).toBe(0);
  });

  it('does not duplicate items when a commit is applied but its response is lost', async () => {
    const { text, kit, titles } = large;
    const server = new FakeServer();
    const b = await device(server);
    await setUp(b, 'synthetic-import-lost-response');
    b.engine.exportOpen({ text, recoveryKey: kit });
    server.loseNextCommitResponse = true;
    const first = await b.engine.importIntoEmptyVault();
    expect(first.import?.state).toBe('uploading');
    const done = await b.engine.sync();
    expect(done.import).toMatchObject({ state: 'complete', uploaded: 250 });
    expect(server.items.size).toBe(250);
    expect(
      b.engine
        .items()
        .map((i) => i.title)
        .sort(),
    ).toEqual(titles);
  });
});
