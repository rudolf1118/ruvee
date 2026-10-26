import { randomBytes } from 'node:crypto';
import type pg from 'pg';
import { TABLE_INVENTORY } from './backup-inventory.js';

/**
 * Restore authority kept out of reach of the SQL a dump contains (predeployment-review R8).
 *
 * A dump is executed as SQL by `pg_restore`. The restore's own state (the guard and the reopening
 * codes) therefore lives in a schema, `ruvee_control`, owned by the restore tool's admin role,
 * and `pg_restore` connects as a separate **loader role** made for this one restore: it may only
 * connect and create objects in `public`, and has no privilege at all on `ruvee_control`. After
 * loading, the restored objects are checked against what Ruvee itself creates (tables of the
 * inventory, their indexes, sequences and constraints, enums); anything else, such as a function,
 * trigger, rule, view, policy, extension or another schema, is refused, because it could run later
 * as the application role. Only then are the objects handed to the admin role and the loader role
 * dropped.
 */

export const CONTROL_SCHEMA = 'ruvee_control';
export const GUARD_TABLE = `${CONTROL_SCHEMA}.restore_guard`;

const ident = (name: string) => `"${name.replace(/"/g, '""')}"`;

export interface LoaderRole {
  readonly name: string;
  readonly password: string;
}

/** Objects of a brand-new database's own schemas; anything beyond them means not empty. */
export async function assertEmptyDatabase(c: pg.Client): Promise<boolean> {
  const { rows } = await c.query<{ n: string }>(`
    SELECT
      (SELECT count(*) FROM pg_class r JOIN pg_namespace n ON n.oid = r.relnamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast'))
    + (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema'))
    + (SELECT count(*) FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast'))
    + (SELECT count(*) FROM pg_namespace
        WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public', 'pg_toast')
          AND nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%')
    + (SELECT count(*) FROM pg_extension WHERE extname <> 'plpgsql')
    + (SELECT count(*) FROM pg_largeobject_metadata) AS n`);
  return Number(rows[0]?.n) === 0;
}

/** PREPARE, as the admin role: the control schema, owned by it, with nothing granted to anyone. */
export async function createControlSchema(c: pg.Client): Promise<void> {
  await c.query(`CREATE SCHEMA ${CONTROL_SCHEMA}`);
  await c.query(`REVOKE ALL ON SCHEMA ${CONTROL_SCHEMA} FROM PUBLIC`);
}

/** The loader role's name for a restore; recorded in the guard so a stray one can be found. */
export const loaderRoleName = (restoreId: string) =>
  `ruvee_loader_${restoreId.replace(/-/g, '').slice(0, 16)}`;

/**
 * At the start of LOAD, as the admin role: the loader role, with only CONNECT on this database
 * and USAGE/CREATE on `public`. PUBLIC loses its default privileges on this database (CONNECT,
 * TEMPORARY). The password is random, used once by `pg_restore`, and never shown.
 */
export async function createLoader(
  c: pg.Client,
  database: string,
  name: string,
): Promise<LoaderRole> {
  const loader: LoaderRole = { name, password: randomBytes(32).toString('base64url') };
  await c.query(
    `CREATE ROLE ${ident(loader.name)} LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE
       NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 2 PASSWORD ${c.escapeLiteral(loader.password)}`,
  );
  await c.query(`REVOKE ALL ON DATABASE ${ident(database)} FROM PUBLIC`);
  await c.query(`GRANT CONNECT ON DATABASE ${ident(database)} TO ${ident(loader.name)}`);
  await c.query(`GRANT USAGE, CREATE ON SCHEMA public TO ${ident(loader.name)}`);
  return loader;
}

/** What a restored dump may contain: the inventory's tables and Prisma's migration table. */
const ALLOWED_TABLES = new Set([...Object.keys(TABLE_INVENTORY), '_prisma_migrations']);

/**
 * After LOAD, as the admin role: every object the dump created must be one Ruvee itself creates.
 * Returns the problems found (none means acceptable). Read-only.
 */
export async function restoredObjectProblems(c: pg.Client): Promise<string[]> {
  const problems: string[] = [];
  const count = async (label: string, sql: string) => {
    const { rows } = await c.query<{ n: string }>(sql);
    if (Number(rows[0]?.n) !== 0) problems.push(`${label} (${String(rows[0]?.n)})`);
  };
  const notSystem = `NOT IN ('pg_catalog', 'information_schema')`;
  await count(
    'functions or procedures',
    `SELECT count(*) AS n FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname ${notSystem}`,
  );
  await count('triggers', `SELECT count(*) AS n FROM pg_trigger WHERE NOT tgisinternal`);
  await count(
    'rules or views',
    `SELECT count(*) AS n FROM pg_rewrite rw JOIN pg_class r ON r.oid = rw.ev_class
       JOIN pg_namespace n ON n.oid = r.relnamespace WHERE n.nspname ${notSystem}`,
  );
  await count('row security policies', `SELECT count(*) AS n FROM pg_policy`);
  await count('event triggers', `SELECT count(*) AS n FROM pg_event_trigger`);
  await count('extensions', `SELECT count(*) AS n FROM pg_extension WHERE extname <> 'plpgsql'`);
  await count(
    'schemas',
    `SELECT count(*) AS n FROM pg_namespace
       WHERE nspname NOT IN ('pg_catalog', 'information_schema', 'public', 'pg_toast', '${CONTROL_SCHEMA}')
         AND nspname NOT LIKE 'pg_temp_%' AND nspname NOT LIKE 'pg_toast_temp_%'`,
  );
  await count(
    'relations other than tables, indexes and sequences',
    `SELECT count(*) AS n FROM pg_class r JOIN pg_namespace n ON n.oid = r.relnamespace
       WHERE n.nspname = 'public' AND r.relkind NOT IN ('r', 'i', 'S')`,
  );
  await count(
    'types other than enums and table row types',
    `SELECT count(*) AS n FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
       WHERE n.nspname = 'public'
         AND NOT (t.typtype = 'e')
         AND NOT (t.typtype = 'c' AND EXISTS (SELECT 1 FROM pg_class r WHERE r.oid = t.typrelid AND r.relkind IN ('r', 'S', 'i')))
         AND NOT (t.typtype = 'b' AND t.typelem <> 0 AND t.typname LIKE '\\_%')`,
  );
  for (const catalog of [
    'pg_collation',
    'pg_conversion',
    'pg_operator',
    'pg_opclass',
    'pg_opfamily',
    'pg_ts_config',
    'pg_ts_dict',
    'pg_ts_parser',
    'pg_ts_template',
  ]) {
    await count(
      catalog,
      `SELECT count(*) AS n FROM ${catalog} o JOIN pg_namespace n ON n.oid = o.${namespaceColumn(catalog)}
         WHERE n.nspname ${notSystem}`,
    );
  }
  await count('foreign servers', `SELECT count(*) AS n FROM pg_foreign_server`);
  await count('publications', `SELECT count(*) AS n FROM pg_publication`);
  await count('large objects', `SELECT count(*) AS n FROM pg_largeobject_metadata`);
  await count(
    'tables row security enabled',
    `SELECT count(*) AS n FROM pg_class r JOIN pg_namespace n ON n.oid = r.relnamespace
       WHERE n.nspname = 'public' AND (r.relrowsecurity OR r.relforcerowsecurity)`,
  );
  const tables = await c.query<{ name: string }>(
    `SELECT relname AS name FROM pg_class r JOIN pg_namespace n ON n.oid = r.relnamespace
       WHERE n.nspname = 'public' AND r.relkind = 'r'`,
  );
  const present = new Set(tables.rows.map((t) => t.name));
  const unknown = [...present].filter((t) => !ALLOWED_TABLES.has(t));
  if (unknown.length > 0) problems.push(`tables Ruvee never creates (${String(unknown.length)})`);
  const missing = [...ALLOWED_TABLES].filter((t) => !present.has(t));
  if (missing.length > 0) problems.push(`missing Ruvee tables (${String(missing.length)})`);
  return problems;
}

const NAMESPACE_COLUMN: Readonly<Record<string, string>> = {
  pg_collation: 'collnamespace',
  pg_conversion: 'connamespace',
  pg_operator: 'oprnamespace',
  pg_opclass: 'opcnamespace',
  pg_opfamily: 'opfnamespace',
  pg_ts_config: 'cfgnamespace',
  pg_ts_dict: 'dictnamespace',
  pg_ts_parser: 'prsnamespace',
  pg_ts_template: 'tmplnamespace',
};

function namespaceColumn(catalog: string): string {
  const column = NAMESPACE_COLUMN[catalog];
  if (!column) throw new Error(`no namespace column for ${catalog}`);
  return column;
}

/** Hands the loader's objects to the admin role and removes the loader role. */
export async function retireLoader(c: pg.Client, loader: string): Promise<void> {
  const exists = await c.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [loader]);
  if (exists.rowCount === 0) return;
  // A non-superuser admin role needs membership to reassign (CREATEROLE grants ADMIN OPTION).
  await c.query(`GRANT ${ident(loader)} TO CURRENT_USER`).catch(() => undefined);
  await c.query(`REASSIGN OWNED BY ${ident(loader)} TO CURRENT_USER`);
  await c.query(`DROP OWNED BY ${ident(loader)}`);
  await c.query(`DROP ROLE ${ident(loader)}`);
}
