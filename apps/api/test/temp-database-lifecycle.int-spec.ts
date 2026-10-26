import { randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { startHarness } from './support/api-harness.js';
import { createTempDatabase, dropDatabase, dropTracked, query } from './support/temp-database.js';

/**
 * Test-resource lifecycle: a temporary database is dropped on every failure path, by its exact
 * name, and nothing the tests did not create is dropped. Synthetic, empty databases only.
 */
const SERVER_URL = process.env.DATABASE_URL ?? '';

const exists = async (name: string) =>
  (
    await query<{ n: string }>(
      SERVER_URL,
      'SELECT count(*) AS n FROM pg_database WHERE datname = $1',
      [name],
    )
  )[0]?.n === '1';

describe('temporary databases are dropped on failure paths', () => {
  afterEach(() => {
    process.env.DATABASE_URL = SERVER_URL;
  });

  it('records each database in the run ledger before creating it', async () => {
    const db = await createTempDatabase();
    try {
      const dir = process.env.RUVEE_IT_LEDGER_DIR ?? '';
      expect(dir).not.toBe('');
      const ledger = readdirSync(dir)
        .map((f) => readFileSync(join(dir, f), 'utf8'))
        .join('');
      expect(ledger).toContain(`"name":"${db.name}"`);
    } finally {
      await db.drop();
    }
  });

  it('drops what a failed test left, and only that', async () => {
    const forgotten = await createTempDatabase();
    // Same naming pattern, but not created by this process: never dropped by the safety net.
    const foreign = `ruvee_it_${randomBytes(6).toString('hex')}`;
    await query(SERVER_URL, `CREATE DATABASE "${foreign}"`);
    try {
      expect(await dropTracked()).toContain(forgotten.name);
      expect(await exists(forgotten.name)).toBe(false);
      expect(await exists(foreign)).toBe(true);
    } finally {
      await dropDatabase(SERVER_URL, foreign);
    }
  });

  it('drops the database of a harness whose app fails to start', async () => {
    const saved = process.env.OPAQUE_SERVER_SETUP_FILE;
    process.env.OPAQUE_SERVER_SETUP_FILE = 'test/fixtures/does-not-exist';
    vi.resetModules();
    try {
      await expect(startHarness()).rejects.toThrow();
    } finally {
      process.env.OPAQUE_SERVER_SETUP_FILE = saved;
      vi.resetModules();
    }
    // The harness dropped its own database itself: nothing is left for the safety net.
    expect(await dropTracked()).toEqual([]);
  }, 60_000);

  it('refuses to drop a name the tests do not create', async () => {
    await expect(dropDatabase(SERVER_URL, 'ruvee_test')).rejects.toThrow(/did not create/);
    await expect(dropDatabase(SERVER_URL, 'ruvee_it_x; DROP DATABASE ruvee_test')).rejects.toThrow(
      /did not create/,
    );
  });
});
