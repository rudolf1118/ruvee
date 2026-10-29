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
  opened.cleanup();
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
    const run = tools.dump(parseDbTarget(otherUrl()), { tables: [], tableData: [], schemas: [] });
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
        runtimeRole: h.db.runtime.name,
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

describe('REVIEW R8 (regression): SQL inside a restored dump cannot reach restore authority', () => {
  let key: TestBackupKey;
  let outDir: string;
  let n = 0;

  beforeAll(async () => {
    process.env.DATABASE_URL = SERVER_URL;
    key = await testBackupKey();
    outDir = mkdtempSync(join(tmpdir(), 'ruvee-review-r8-'));
  }, 60_000);

  afterAll(() => {
    rmSync(outDir, { recursive: true, force: true });
    key.drop();
  });

  /**
   * A backup, made by the real tool, of a synthetic Ruvee database with `statements` added: what
   * a compromised server could produce. Restored with its genuine digest, so provenance does not
   * help; only the restore's own boundary can.
   */
  async function hostileRestore(statements: string[]) {
    process.env.DATABASE_URL = SERVER_URL;
    const source = await createTempDatabase();
    const target = await createTempDatabase();
    try {
      // Made with the test's superuser view, beyond what any Ruvee role could do: the hostile
      // dump may hold anything. Only the restore, as the operator, is the boundary under test.
      migrate(source.url);
      for (const sql of statements) await query(source.url, sql);
      const b = await createBackup({
        databaseUrl: source.url,
        outDir,
        tools,
        recipient: key.recipient,
        syntheticTestOnly: true,
        config,
        now: () => new Date(Date.now() + 60_000 * ++n),
      });
      const outcome = await restoreBackup({
        manifestPath: b.manifestPath,
        identityPath: key.identityPath,
        trustedDigest: b.digest,
        targetDatabaseUrl: target.operator.url,
        runtimeRole: target.runtime.name,
        tools,
        migrate,
        knownMigrations: MIGRATIONS,
      }).then(
        (r) => ({ ok: true as const, r }),
        (e: unknown) => ({ ok: false as const, e: e as { stage?: string; message?: string } }),
      );
      const [guard] = await query<{ state: string; loader_role: string }>(
        target.url,
        'SELECT state, loader_role FROM ruvee_control.restore_guard',
      );
      // This restore's own loader role (other suites may be restoring at the same time).
      const [roles] = await query<{ n: string }>(
        SERVER_URL,
        `SELECT count(*) AS n FROM pg_roles WHERE rolname = $1`,
        [guard?.loader_role ?? ''],
      );
      return { outcome, guard: guard?.state, loaderRoles: Number(roles?.n) };
    } finally {
      await target.drop();
      await source.drop();
    }
  }

  const HOSTILE_FN = `CREATE FUNCTION public.review_r8_hostile(x int) RETURNS boolean LANGUAGE plpgsql AS $$
     BEGIN
       IF to_regclass('ruvee_control.restore_guard') IS NOT NULL THEN
         EXECUTE 'UPDATE ruvee_control.restore_guard SET state = ''open''';
       END IF;
       RETURN true;
     END $$`;

  it('a CHECK constraint that opens the guard during LOAD fails: the loader has no access', async () => {
    const r = await hostileRestore([
      HOSTILE_FN,
      `CREATE TABLE public.review_r8_rows (x int CHECK (public.review_r8_hostile(x)))`,
      `INSERT INTO public.review_r8_rows VALUES (1)`,
    ]);
    expect(r.outcome.ok).toBe(false);
    if (!r.outcome.ok) expect(r.outcome.e.stage).toBe('load');
    expect(r.guard).toBe('restoring');
    expect(r.loaderRoles).toBe(0);
  });

  it.each([
    ['a function planted for later', [HOSTILE_FN]],
    [
      'a trigger on a Ruvee table',
      [
        `CREATE FUNCTION public.review_r8_t() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`,
        `CREATE TRIGGER review_r8 BEFORE INSERT ON public.sessions FOR EACH ROW EXECUTE FUNCTION public.review_r8_t()`,
      ],
    ],
    ['a view', [`CREATE VIEW public.review_r8_view AS SELECT 1 AS x`]],
    [
      'a rule',
      [`CREATE RULE review_r8_rule AS ON INSERT TO public.pairings DO ALSO NOTIFY review_r8`],
    ],
    [
      'another schema',
      [`CREATE SCHEMA review_r8_schema`, `CREATE TABLE review_r8_schema.t (x int)`],
    ],
    [
      'a table shadowing the guard name in public',
      [`CREATE TABLE public.restore_guard (id int, state text)`],
    ],
    ['a domain type', [`CREATE DOMAIN public.review_r8_domain AS int`]],
    ['row security', [`ALTER TABLE public.accounts ENABLE ROW LEVEL SECURITY`]],
  ])('refuses a dump containing %s, and leaves the guard closed', async (_label, statements) => {
    const r = await hostileRestore(statements);
    expect(r.outcome.ok).toBe(false);
    if (!r.outcome.ok) {
      expect(r.outcome.e.stage).toBe('load');
      // Refused by the loader's privileges during LOAD (pg_restore fails) or by the object check
      // after it; either way at LOAD, before anything could run as the application role.
      expect(r.outcome.e.message).toMatch(/objects Ruvee never creates|pg_restore failed/);
    }
    expect(r.guard).toBe('restoring');
    expect(r.loaderRoles).toBe(0);
  });

  // Follow-up review S-2: the allowed tables themselves, changed. Names alone match, so only a
  // comparison of their definitions can see it.
  it.each([
    [
      'a dropped CHECK constraint',
      ['ALTER TABLE public.devices DROP CONSTRAINT devices_pending_not_enrolled'],
    ],
    ['a dropped unique index', ['DROP INDEX public.sessions_secret_hash_key']],
    [
      'a changed column default',
      ['ALTER TABLE public.sessions ALTER COLUMN revoked_at SET DEFAULT now()'],
    ],
    ['an extra column', ['ALTER TABLE public.accounts ADD COLUMN review_s2 int']],
    ['a changed column type', ['ALTER TABLE public.devices ALTER COLUMN platform TYPE text']],
  ])('refuses a dump whose allowed table has %s', async (_label, statements) => {
    const r = await hostileRestore(statements);
    expect(r.outcome.ok).toBe(false);
    // Checked after migration, first thing in APPLY POLICY, before anything is opened.
    if (!r.outcome.ok) {
      expect(r.outcome.e.stage).toBe('policy');
      expect(r.outcome.e.message).toMatch(/defined differently/);
    }
    expect(r.guard).toBe('restoring');
    expect(r.loaderRoles).toBe(0);
  });
});
