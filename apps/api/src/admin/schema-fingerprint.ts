import { createHash } from 'node:crypto';
import type pg from 'pg';

/**
 * Follow-up review S-2: a restored dump passed when its tables had the right names, whatever their
 * columns, constraints, defaults or indexes. A forged backup could drop a CHECK or a unique index,
 * or change a default, and still be restored. The restore now compares the definitions of the
 * restored public schema, after migration, with those of a freshly migrated database.
 *
 * `EXPECTED_SCHEMA` is that fresh database's fingerprint at the newest migration. The integration
 * test `schema-fingerprint.int-spec.ts` migrates a new database and fails, printing the new value,
 * whenever a migration changes it; update it together with the migration.
 */
export const EXPECTED_SCHEMA = {
  migration: '20261029090000_shared_limits',
  fingerprint: '28b5c668ddae44818dcd6bd5b80e37a2081fdf69884993a404ebd8d35a307d6a',
} as const;

/**
 * One line per definition, sorted, then SHA-256: columns (type, nullability, default, identity,
 * generation, collation), constraints and indexes (as PostgreSQL prints them), enum labels in
 * order, and sequences. Object ids and data are not part of it. Read-only.
 */
export async function schemaFingerprint(c: pg.Client): Promise<string> {
  const lines: string[] = [];
  const add = async (kind: string, sql: string) => {
    const { rows } = await c.query<{ line: string }>(sql);
    for (const r of rows) lines.push(`${kind}\t${r.line}`);
  };
  await add(
    'column',
    `SELECT concat_ws(' | ', r.relname, a.attname, format_type(a.atttypid, a.atttypmod),
              a.attnotnull::text, coalesce(pg_get_expr(d.adbin, d.adrelid), ''),
              a.attidentity::text, a.attgenerated::text, coalesce(co.collname, '')) AS line
       FROM pg_attribute a
       JOIN pg_class r ON r.oid = a.attrelid
       JOIN pg_namespace n ON n.oid = r.relnamespace
       LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
       LEFT JOIN pg_collation co ON co.oid = a.attcollation AND a.attcollation <> 0
         AND co.collname <> 'default'
      WHERE n.nspname = 'public' AND r.relkind = 'r' AND a.attnum > 0 AND NOT a.attisdropped`,
  );
  await add(
    'constraint',
    `SELECT concat_ws(' | ', r.relname, con.conname, con.contype::text,
              pg_get_constraintdef(con.oid, true)) AS line
       FROM pg_constraint con
       JOIN pg_class r ON r.oid = con.conrelid
       JOIN pg_namespace n ON n.oid = r.relnamespace
      WHERE n.nspname = 'public'`,
  );
  await add(
    'index',
    `SELECT concat_ws(' | ', tablename, indexname, indexdef) AS line
       FROM pg_indexes WHERE schemaname = 'public'`,
  );
  await add(
    'enum',
    `SELECT concat_ws(' | ', t.typname, string_agg(e.enumlabel, ',' ORDER BY e.enumsortorder)) AS line
       FROM pg_type t
       JOIN pg_namespace n ON n.oid = t.typnamespace
       JOIN pg_enum e ON e.enumtypid = t.oid
      WHERE n.nspname = 'public'
      GROUP BY t.typname`,
  );
  await add(
    'sequence',
    `SELECT concat_ws(' | ', sequencename, data_type::text, start_value::text, increment_by::text,
              min_value::text, max_value::text, cycle::text) AS line
       FROM pg_sequences WHERE schemaname = 'public'`,
  );
  lines.sort();
  return createHash('sha256').update(lines.join('\n')).digest('hex');
}
