import pg from 'pg';
import { initInstallation, InstallationError } from '../../src/admin/installation.js';
import { startHarness, type Harness } from '../support/api-harness.js';
import { createTempDatabase, initFresh, migrate, query } from '../support/temp-database.js';

/**
 * Regression for predeployment-review R14: the gate opens only on an explicit answer, and only
 * `open` is cached. Before the fix, a database without a guard counted as open (`none`) and that
 * answer was cached, so an API that touched a future restore target stayed open after the guard
 * appeared. Synthetic, empty databases only.
 */
const SERVER_URL = process.env.DATABASE_URL ?? '';
const KEYS = '/api/v1/account/keys';

async function migratedDatabase() {
  process.env.DATABASE_URL = SERVER_URL;
  const db = await createTempDatabase();
  migrate(db.url);
  return db;
}

async function serve(db: Awaited<ReturnType<typeof createTempDatabase>>) {
  vi.resetModules();
  return startHarness({ database: db });
}

const errorOf = async (h: Harness, path = KEYS) => {
  const res = await h.get(path);
  return { status: res.status, error: (res.body as { error?: string }).error };
};

describe('REVIEW R14 (regression): no missing or stale state opens the gate', () => {
  let h: Harness | undefined;

  afterEach(async () => {
    await h?.close();
    h = undefined;
    process.env.DATABASE_URL = SERVER_URL;
  });

  it('serves nothing but health on a database that was never initialized', async () => {
    const served = await serve(await migratedDatabase());
    h = served;
    expect(await errorOf(served)).toEqual({ status: 503, error: 'maintenance' });
    expect((await served.get('/health/live')).status).toBe(200);
    // Many requests at once get the same answer: nothing in between opens it.
    const all = await Promise.all(Array.from({ length: 20 }, () => errorOf(served)));
    expect(new Set(all.map((r) => `${String(r.status)} ${String(r.error)}`))).toEqual(
      new Set(['503 maintenance']),
    );
  });

  it('sees every later state of a restore target at once: closed answers are never cached', async () => {
    const db = await migratedDatabase();
    h = await serve(db);
    // The API touched the database before the restore tool did (the R14 scenario).
    expect(await errorOf(h)).toEqual({ status: 503, error: 'maintenance' });
    await query(db.url, 'CREATE SCHEMA ruvee_control');
    // An interrupted PREPARE: the schema without the guard table.
    expect(await errorOf(h)).toEqual({ status: 503, error: 'maintenance' });
    await query(
      db.url,
      'CREATE TABLE ruvee_control.restore_guard (id smallint PRIMARY KEY, state text NOT NULL)',
    );
    // The guard table without its row.
    expect(await errorOf(h)).toEqual({ status: 503, error: 'maintenance' });
    await query(db.url, `INSERT INTO ruvee_control.restore_guard VALUES (1, 'restoring')`);
    expect(await errorOf(h)).toEqual({ status: 503, error: 'maintenance' });
    await query(db.url, `UPDATE ruvee_control.restore_guard SET state = 'not-a-state'`);
    expect(await errorOf(h)).toEqual({ status: 503, error: 'maintenance' });
    await query(db.url, `UPDATE ruvee_control.restore_guard SET state = 'reopening'`);
    expect(await errorOf(h)).toEqual({ status: 503, error: 'reopening' });
    await query(db.url, `UPDATE ruvee_control.restore_guard SET state = 'open'`);
    // Open: the request reaches authentication.
    expect(await errorOf(h)).toEqual({ status: 401, error: 'unauthenticated' });
  });

  it('a restore guard decides even next to a fresh-installation row', async () => {
    const db = await migratedDatabase();
    await initFresh(db.url);
    await query(
      db.url,
      'CREATE TABLE ruvee_control.restore_guard (id smallint PRIMARY KEY, state text NOT NULL)',
    );
    await query(db.url, `INSERT INTO ruvee_control.restore_guard VALUES (1, 'review')`);
    h = await serve(db);
    expect(await errorOf(h)).toEqual({ status: 503, error: 'maintenance' });
  });

  it('opens a fresh installation only after `init`, which refuses a database twice', async () => {
    const db = await migratedDatabase();
    await initFresh(db.url);
    h = await serve(db);
    expect(await errorOf(h)).toEqual({ status: 401, error: 'unauthenticated' });
    const c = new pg.Client({ connectionString: db.url });
    await c.connect();
    try {
      await expect(initInstallation(c)).rejects.toBeInstanceOf(InstallationError);
    } finally {
      await c.end();
    }
  });

  it('`init` refuses a restored database, so it can never skip a reopening', async () => {
    const db = await migratedDatabase();
    try {
      await query(db.url, 'CREATE SCHEMA ruvee_control');
      await query(db.url, 'CREATE TABLE ruvee_control.restore_guard (id smallint, state text)');
      const c = new pg.Client({ connectionString: db.url });
      await c.connect();
      try {
        await expect(initInstallation(c)).rejects.toThrow(/opens only by its reopening/);
      } finally {
        await c.end();
      }
    } finally {
      await db.drop();
    }
  });
});
