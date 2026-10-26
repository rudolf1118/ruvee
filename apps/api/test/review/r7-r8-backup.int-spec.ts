import { mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import pg from 'pg';
import { openBackup } from '../../src/admin/backup-files.js';
import { parseDbTarget, readDumpDatabase } from '../../src/admin/db-target.js';
import { pgToolsFromEnv, type PgTools } from '../../src/admin/pg-tools.js';
import { createBackup, knownMigrations, restoreBackup } from '../../src/admin/server-restore.js';
import { startHarness, type Harness } from '../support/api-harness.js';
import { testBackupKey, type TestBackupKey } from '../support/backup-keys.js';
import { createTempDatabase, migrate, query } from '../support/temp-database.js';

/**
 * Regression for predeployment-review R7 (and, below, R8). Every database here is created on this
 * suite's own throwaway server and dropped afterwards; the non-synthetic one has a production-like
 * name but lives only in the task container.
 */
const MIGRATIONS = knownMigrations(new URL('../../prisma/migrations', import.meta.url).pathname);
const tools = pgToolsFromEnv();
const config = {
  publicOrigin: 'http://127.0.0.1:3100',
  sessionCookieSecure: 'true' as const,
  extensionOrigins: '',
};
/** A database whose name the synthetic-only check must refuse. */
const NON_SYNTHETIC = 'ruvee_production_like_r7';
const SERVER_URL = process.env.DATABASE_URL ?? '';

async function admin(sql: string) {
  const c = new pg.Client({ connectionString: SERVER_URL });
  await c.connect();
  try {
    await c.query(sql);
  } finally {
    await c.end();
  }
}

const otherUrl = () => {
  const u = new URL(SERVER_URL);
  u.pathname = `/${NON_SYNTHETIC}`;
  return u.toString();
};

async function dumpSql(manifestPath: string, digest: string, key: TestBackupKey) {
  const opened = await openBackup({
    manifestPath,
    identityPath: key.identityPath,
    trustedDigest: digest,
  });
  const { plaintext } = await opened.decryptDump();
  const run = tools.toSql();
  const chunks: Buffer[] = [];
  run.stdout.on('data', (c: Buffer) => chunks.push(c));
  await pipeline(plaintext, run.stdin);
  await run.done;
  return Buffer.concat(chunks).toString('utf8');
}

describe('REVIEW R7 (regression): a backup reads exactly the database that was checked', () => {
  let h: Harness;
  let key: TestBackupKey;
  let outDir: string;

  beforeAll(async () => {
    h = await startHarness();
    key = await testBackupKey();
    outDir = mkdtempSync(join(tmpdir(), 'ruvee-review-r7-'));
    await admin(`DROP DATABASE IF EXISTS ${NON_SYNTHETIC}`);
    await admin(`CREATE DATABASE ${NON_SYNTHETIC}`);
    await query(otherUrl(), `CREATE TABLE review_r7_marker_table (x int)`);
  }, 60_000);

  afterAll(async () => {
    await admin(`DROP DATABASE IF EXISTS ${NON_SYNTHETIC} WITH (FORCE)`);
    await h.close();
    rmSync(outDir, { recursive: true, force: true });
    key.drop();
  });

  const backup = (databaseUrl: string, extra: Partial<Parameters<typeof createBackup>[0]> = {}) =>
    createBackup({
      databaseUrl,
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
      ...extra,
    });

  it('refuses every connection-string override before connecting or dumping', async () => {
    const overrides = [
      `dbname=${NON_SYNTHETIC}`,
      'service=prod',
      'options=-c%20search_path%3Devil',
      'host=10.0.0.9',
      'sslmode=disable',
    ];
    for (const q of overrides) {
      const url = new URL(h.db.url);
      url.search = `?${q}`;
      await expect(backup(url.toString()), q).rejects.toMatchObject({ stage: 'backup' });
    }
    await expect(backup(`${h.db.url}#${NON_SYNTHETIC}`)).rejects.toMatchObject({ stage: 'backup' });
    const multi = h.db.url.replace('@127.0.0.1:', '@127.0.0.1,10.0.0.9:');
    await expect(backup(multi)).rejects.toMatchObject({ stage: 'backup' });
    await expect(backup(otherUrl())).rejects.toThrow(/synthetic/);
    expect(readdirSync(outDir)).toEqual([]);
    expect(() => parseDbTarget(`${h.db.url}?dbname=x`)).toThrow(/query parameters/);
  });

  it('ignores inherited PG* variables: the dump is of the checked database', async () => {
    const saved = { ...process.env };
    process.env.PGDATABASE = NON_SYNTHETIC;
    process.env.PGOPTIONS = '-c search_path=evil';
    process.env.PGSERVICE = 'prod';
    try {
      const b = await backup(h.db.url);
      const sql = await dumpSql(b.manifestPath, b.digest, key);
      expect(sql).toContain('CREATE TABLE public.accounts');
      expect(sql).not.toContain('review_r7_marker_table');
      rmSync(outDir, { recursive: true, force: true });
      outDir = mkdtempSync(join(tmpdir(), 'ruvee-review-r7-'));
    } finally {
      process.env = saved;
    }
  });

  it('fails, publishing nothing, when pg_dump itself read another database', async () => {
    // A tool redirected somewhere the checks could not see (a wrong RUVEE_PG_TOOLS_HOST, a
    // service file): it dumps the non-synthetic database whatever it is asked for.
    const redirected: PgTools = {
      ...tools,
      dump: (_target, exclude) => tools.dump(parseDbTarget(otherUrl()), exclude),
    };
    await expect(backup(h.db.url, { tools: redirected })).rejects.toThrow(
      /pg_dump read another database/,
    );
    expect(readdirSync(outDir)).toEqual([]);
  });

  it('reads the database name pg_dump records in its archive header', async () => {
    const run = tools.dump(parseDbTarget(otherUrl()), { tables: [], schemas: [] });
    const chunks: Buffer[] = [];
    for await (const c of run.stdout as AsyncIterable<Buffer>) chunks.push(c);
    await run.done;
    expect(readDumpDatabase(Buffer.concat(chunks))).toBe(NON_SYNTHETIC);
    expect(readDumpDatabase(Buffer.concat(chunks).subarray(0, 20))).toBeNull();
  });

  it('refuses a restore target URL with query parameters', async () => {
    const b = await backup(h.db.url, { now: () => new Date(Date.now() + 3000) });
    const target = new URL(h.db.url);
    target.pathname = '/ruvee_it_000000000000';
    target.search = `?dbname=${NON_SYNTHETIC}`;
    await expect(
      restoreBackup({
        manifestPath: b.manifestPath,
        identityPath: key.identityPath,
        trustedDigest: b.digest,
        targetDatabaseUrl: target.toString(),
        tools,
        migrate,
        knownMigrations: MIGRATIONS,
      }),
    ).rejects.toThrow(/query parameters/);
    const [marker] = await query<{ n: string }>(
      otherUrl(),
      `SELECT count(*) AS n FROM pg_tables WHERE schemaname = 'public'`,
    );
    expect(marker?.n).toBe('1');
  });
});

describe('REVIEW R8: SQL inside a restored dump (still the pre-fix behaviour)', () => {
  let h: Harness;
  let key: TestBackupKey;
  let outDir: string;

  beforeAll(async () => {
    process.env.DATABASE_URL = SERVER_URL;
    vi.resetModules();
    h = await startHarness();
    key = await testBackupKey();
    outDir = mkdtempSync(join(tmpdir(), 'ruvee-review-r8-'));
  }, 60_000);

  afterAll(async () => {
    await h.close();
    rmSync(outDir, { recursive: true, force: true });
    key.drop();
  });

  it('R8: SQL inside a restored dump can open the guard itself (vulnerable)', async () => {
    await query(
      h.db.url,
      `CREATE FUNCTION public.review_r8_hostile(x int) RETURNS boolean LANGUAGE plpgsql AS $$
       BEGIN
         IF to_regclass('public.ruvee_restore_guard') IS NOT NULL THEN
           EXECUTE 'UPDATE public.ruvee_restore_guard SET state = ''open''';
         END IF;
         RETURN true;
       END $$`,
    );
    await query(
      h.db.url,
      `CREATE TABLE public.review_r8_rows (x int CHECK (public.review_r8_hostile(x)))`,
    );
    await query(h.db.url, `INSERT INTO public.review_r8_rows VALUES (1)`);
    const b = await createBackup({
      databaseUrl: h.db.url,
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
    });
    process.env.DATABASE_URL = SERVER_URL;
    const target = await createTempDatabase();
    try {
      const result = await restoreBackup({
        manifestPath: b.manifestPath,
        identityPath: key.identityPath,
        trustedDigest: false,
        targetDatabaseUrl: target.url,
        tools,
        migrate,
        knownMigrations: MIGRATIONS,
      });
      expect('removed' in result).toBe(true);
      const [guard] = await query<{ state: string }>(
        target.url,
        'SELECT state FROM ruvee_restore_guard',
      );
      expect(guard?.state).toBe('open');
    } finally {
      await target.drop();
      process.env.DATABASE_URL = h.db.url;
    }
  });
});
