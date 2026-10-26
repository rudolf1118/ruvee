import { COLUMN_CLASSES } from '../src/database/column-classes.js';
import {
  createTempDatabase,
  migrate,
  query,
  runSqlFile,
  type TempDatabase,
} from './support/temp-database.js';

/** Newest first, the order in which their down scripts run. */
const MIGRATIONS = [
  'prisma/migrations/20261026090000_session_superseded',
  'prisma/migrations/20261025160000_token_sessions',
  'prisma/migrations/20261025150000_secret_key_rotated_event',
  'prisma/migrations/20261025140000_recovery_failed_event',
  'prisma/migrations/20261025130000_pairings_and_device_state',
  'prisma/migrations/20261025120000_web_vault_initial',
];

describe('migrations against an empty, task-created database', () => {
  let db: TempDatabase;

  beforeAll(async () => {
    db = await createTempDatabase();
  });

  afterAll(async () => {
    await db.drop();
  });

  it('applies, has exactly the classified columns (INV-10), enforces its checks, and rolls back', async () => {
    migrate(db.url);

    const rows = await query<{ table_name: string; column_name: string }>(
      db.url,
      `SELECT table_name, column_name FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name <> '_prisma_migrations'`,
    );
    const actual = rows.map((r) => `${r.table_name}.${r.column_name}`).sort();
    const documented = Object.entries(COLUMN_CLASSES)
      .flatMap(([table, columns]) => Object.keys(columns).map((c) => `${table}.${c}`))
      .sort();
    expect(actual).toEqual(documented);

    // A byte-length CHECK and the tombstone CHECK, on their own, without the API in front.
    await query(db.url, `INSERT INTO accounts (id, username_normalized) VALUES ($1, 'synthetic')`, [
      '11111111-1111-4111-8111-111111111111',
    ]);
    await expect(
      query(db.url, `INSERT INTO vaults (id, account_id, vk_id) VALUES ($1, $2, $3)`, [
        '22222222-2222-4222-8222-222222222222',
        '11111111-1111-4111-8111-111111111111',
        Buffer.alloc(15),
      ]),
    ).rejects.toThrow(/vaults_vk_id_length/);
    await query(db.url, `INSERT INTO vaults (id, account_id, vk_id) VALUES ($1, $2, $3)`, [
      '22222222-2222-4222-8222-222222222222',
      '11111111-1111-4111-8111-111111111111',
      Buffer.alloc(16),
    ]);
    await expect(
      query(
        db.url,
        `INSERT INTO vault_items (vault_id, item_id, revision, record, tombstone, updated_seq)
         VALUES ($1, $2, 1, NULL, false, 1)`,
        ['22222222-2222-4222-8222-222222222222', '33333333-3333-4333-8333-333333333333'],
      ),
    ).rejects.toThrow(/vault_items_tombstone/);
    // Deleting the account cascades to its vault.
    await query(db.url, `DELETE FROM accounts`);
    expect(await query(db.url, `SELECT 1 FROM vaults`)).toEqual([]);

    // A pending device can be revoked (the second migration's rule), and an active one needs an
    // enrolment method.
    await query(db.url, `INSERT INTO accounts (id, username_normalized) VALUES ($1, 'synthetic')`, [
      '11111111-1111-4111-8111-111111111111',
    ]);
    await query(
      db.url,
      `INSERT INTO devices (id, account_id, platform, status) VALUES ($1, $2, 'web', 'revoked')`,
      ['44444444-4444-4444-8444-444444444444', '11111111-1111-4111-8111-111111111111'],
    );
    await expect(
      query(
        db.url,
        `INSERT INTO devices (id, account_id, platform, status) VALUES ($1, $2, 'web', 'active')`,
        ['55555555-5555-4555-8555-555555555555', '11111111-1111-4111-8111-111111111111'],
      ),
    ).rejects.toThrow(/devices_active_enrolled/);
    await query(db.url, `DELETE FROM accounts`);

    for (const migration of MIGRATIONS) await runSqlFile(db.url, `${migration}/down.sql`);
    const left = await query<{ table_name: string }>(
      db.url,
      `SELECT table_name FROM information_schema.tables
       WHERE table_schema = 'public' AND table_name <> '_prisma_migrations'`,
    );
    expect(left).toEqual([]);
    const types = await query(
      db.url,
      `SELECT typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
       WHERE n.nspname = 'public' AND t.typtype = 'e'`,
    );
    expect(types).toEqual([]);

    // The migration applies again after the rollback.
    migrate(db.url);
  });
});
