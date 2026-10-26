import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import pg from 'pg';
import { openBackup } from '../../src/admin/backup-files.js';
import { pgToolsFromEnv } from '../../src/admin/pg-tools.js';
import { createBackup, knownMigrations, restoreBackup } from '../../src/admin/server-restore.js';
import { startHarness, type Harness } from '../support/api-harness.js';
import { testBackupKey, type TestBackupKey } from '../support/backup-keys.js';
import { createTempDatabase, migrate, query } from '../support/temp-database.js';

/**
 * Pre-deployment review, findings R7 and R8 (docs/security/predeployment-review.md). These tests
 * describe the CURRENT behaviour and are expected to fail once the findings are fixed. Every
 * database is created on this suite's own throwaway server and dropped afterwards.
 */
const MIGRATIONS = knownMigrations(new URL('../../prisma/migrations', import.meta.url).pathname);
const tools = pgToolsFromEnv();
const config = {
  publicOrigin: 'http://127.0.0.1:3100',
  sessionCookieSecure: 'true' as const,
  extensionOrigins: '',
};
/** A database whose name the synthetic-only check must refuse. */
const NON_SYNTHETIC = 'review_r7_not_synthetic';
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

describe('REVIEW R7/R8: backup tool boundaries', () => {
  let h: Harness;
  let key: TestBackupKey;
  let outDir: string;

  beforeAll(async () => {
    h = await startHarness();
    key = await testBackupKey();
    outDir = mkdtempSync(join(tmpdir(), 'ruvee-review-r7-'));
    await admin(`DROP DATABASE IF EXISTS ${NON_SYNTHETIC}`);
    await admin(`CREATE DATABASE ${NON_SYNTHETIC}`);
    const other = new URL(SERVER_URL);
    other.pathname = `/${NON_SYNTHETIC}`;
    await query(other.toString(), `CREATE TABLE review_r7_marker_table (x int)`);
  }, 60_000);

  afterAll(async () => {
    await admin(`DROP DATABASE IF EXISTS ${NON_SYNTHETIC} WITH (FORCE)`);
    await h.close();
    rmSync(outDir, { recursive: true, force: true });
    key.drop();
  });

  it('R7: a ?dbname= parameter makes pg_dump back up a database the synthetic check never saw (vulnerable)', async () => {
    // The path names the synthetic database (it passes the name check and has migrations);
    // the query parameter is what pg_dump connects to.
    const url = new URL(h.db.url);
    url.searchParams.set('dbname', NON_SYNTHETIC);
    const backup = await createBackup({
      databaseUrl: url.toString(),
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
    });
    const opened = await openBackup({
      manifestPath: backup.manifestPath,
      identityPath: key.identityPath,
      trustedDigest: backup.digest,
    });
    const { plaintext } = await opened.decryptDump();
    const run = tools.toSql();
    const chunks: Buffer[] = [];
    run.stdout.on('data', (c: Buffer) => chunks.push(c));
    await pipeline(plaintext, run.stdin);
    await run.done;
    const sql = Buffer.concat(chunks).toString('utf8');
    expect(sql).toContain('review_r7_marker_table');
    expect(sql).not.toContain('accounts');
  });

  it('R8: SQL inside a restored dump can open the guard itself, skipping review and reopening (vulnerable)', async () => {
    // A source database with a hostile CHECK constraint, evaluated for each row pg_restore
    // copies in, inside the restore's own transaction. (With an unchecked or forged backup, or
    // one made by a compromised server, this is attacker SQL.)
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
    const backup = await createBackup({
      databaseUrl: h.db.url,
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
      now: () => new Date(Date.now() + 5000),
    });
    process.env.DATABASE_URL = SERVER_URL;
    const target = await createTempDatabase();
    try {
      const result = await restoreBackup({
        manifestPath: backup.manifestPath,
        identityPath: key.identityPath,
        trustedDigest: false,
        targetDatabaseUrl: target.url,
        tools,
        migrate,
        knownMigrations: MIGRATIONS,
      });
      // The restore reports success, as if it had ended in review...
      expect('removed' in result).toBe(true);
      // ...but the guard is already open: no review, no reopening code, nothing closed.
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
