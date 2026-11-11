import { join } from 'node:path';
import pg from 'pg';
import { EXPECTED_SCHEMA, schemaFingerprint } from '../../src/admin/schema-fingerprint.js';
import { knownMigrations } from '../../src/admin/server-restore.js';
import { createTempDatabase, migrate } from '../support/temp-database.js';

/**
 * Keeps `EXPECTED_SCHEMA` (follow-up review S-2) equal to what the migrations create. When a
 * migration changes the schema this fails and prints the new values to put there.
 */
describe('the restore schema fingerprint', () => {
  it('matches a freshly migrated database at the newest migration', async () => {
    const db = await createTempDatabase();
    try {
      migrate(db.url);
      const client = new pg.Client({ connectionString: db.url });
      await client.connect();
      let actual: string;
      try {
        actual = await schemaFingerprint(client);
      } finally {
        await client.end();
      }
      const migrations = knownMigrations(join(import.meta.dirname, '../../prisma/migrations'));
      const newest = migrations.at(-1) ?? '';
      expect(
        { migration: EXPECTED_SCHEMA.migration, fingerprint: EXPECTED_SCHEMA.fingerprint },
        `update EXPECTED_SCHEMA in src/admin/schema-fingerprint.ts to { migration: '${newest}', fingerprint: '${actual}' }`,
      ).toEqual({ migration: newest, fingerprint: actual });
    } finally {
      await db.drop();
    }
  }, 60_000);
});
