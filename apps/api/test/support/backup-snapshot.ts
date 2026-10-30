import { query } from './temp-database.js';

/**
 * Format-neutral backup scaffolding (backup-restore.md §6): a consistent copy of every table at
 * one moment, and putting it back. It models what any server backup does to the database, a
 * pg_dump or a volume snapshot alike, without deciding how M1 takes or stores one. Test-only.
 */

const SNAPSHOT_SCHEMA = 'ruvee_test_snapshot';

async function tables(url: string): Promise<string[]> {
  const rows = await query<{ table_name: string }>(
    url,
    `SELECT table_name FROM information_schema.tables
     WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
       AND table_name <> '_prisma_migrations'
     ORDER BY table_name`,
  );
  return rows.map((r) => r.table_name);
}

/** Copies every table in one repeatable-read transaction, so the copy is one consistent state. */
export async function takeSnapshot(url: string): Promise<void> {
  const names = await tables(url);
  const statements = [
    'BEGIN ISOLATION LEVEL REPEATABLE READ',
    `DROP SCHEMA IF EXISTS ${SNAPSHOT_SCHEMA} CASCADE`,
    `CREATE SCHEMA ${SNAPSHOT_SCHEMA}`,
    ...names.map((t) => `CREATE TABLE ${SNAPSHOT_SCHEMA}."${t}" AS TABLE public."${t}"`),
    'COMMIT',
  ];
  await query(url, statements.join(';\n'));
}

/**
 * Replaces every row with the snapshot's, as restoring that backup would. Foreign keys are not
 * checked during the copy (the snapshot is consistent by construction); this needs a role that
 * may set session_replication_role, as the test databases' owners can.
 */
export async function restoreSnapshot(url: string): Promise<void> {
  const names = await tables(url);
  const statements = [
    'BEGIN',
    "SET LOCAL session_replication_role = 'replica'",
    `TRUNCATE ${names.map((t) => `public."${t}"`).join(', ')}`,
    ...names.map((t) => `INSERT INTO public."${t}" SELECT * FROM ${SNAPSHOT_SCHEMA}."${t}"`),
    'COMMIT',
  ];
  await query(url, statements.join(';\n'));
}
