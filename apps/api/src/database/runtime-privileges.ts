/**
 * What the API's own database role may do (follow-up review F-25; database-roles.md). The running
 * API connects as a **runtime role** that owns nothing, cannot create anything, and has only the
 * data access below. Schema changes run as a separate owner role; the restore state in
 * `ruvee_control` belongs to the operator role, and the API changes it only through the
 * reopening functions (restore-control.ts), never with its own UPDATE.
 *
 * This list is the whole grant: `ruvee-admin grant-runtime` applies exactly it, and
 * `privilegeProblems` reports anything the role holds beyond it (an extra table privilege, a
 * column grant, ownership, CREATE, membership in another role). A table added by a migration
 * gets nothing until it is listed here.
 */

export type TablePrivilege = 'SELECT' | 'INSERT' | 'UPDATE' | 'DELETE';

export interface RuntimeGrant {
  /** Privileges on the whole table. */
  readonly table: readonly TablePrivilege[];
  /** Privileges on single columns only, beyond `table`. */
  readonly columns?: Readonly<Partial<Record<TablePrivilege, readonly string[]>>>;
}

/** Tables in `public`; the keys are exactly TABLE_INVENTORY's (a test checks it). */
export const RUNTIME_GRANTS: Readonly<Record<string, RuntimeGrant>> = {
  // UPDATE on one column only so that `SELECT … FOR UPDATE` may lock an account row (pairing).
  accounts: { table: ['SELECT', 'INSERT'], columns: { UPDATE: ['created_at'] } },
  opaque_credentials: { table: ['SELECT', 'INSERT', 'UPDATE'] },
  account_keys: { table: ['SELECT', 'INSERT', 'UPDATE'] },
  devices: { table: ['SELECT', 'INSERT', 'UPDATE'] },
  sessions: { table: ['SELECT', 'INSERT', 'UPDATE'] },
  refresh_tokens: { table: ['SELECT', 'INSERT', 'UPDATE'] },
  auth_throttle: { table: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] },
  // Setup tokens are issued on the host (`ruvee-admin bootstrap-token`); the API only uses them.
  bootstrap_tokens: { table: ['SELECT', 'UPDATE'] },
  security_events: { table: ['SELECT', 'INSERT'] },
  pairings: { table: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] },
  proof_nonces: { table: ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] },
  vaults: { table: ['SELECT', 'INSERT', 'UPDATE'] },
  vault_items: { table: ['SELECT', 'INSERT', 'UPDATE'] },
  vault_commits: { table: ['SELECT', 'INSERT'] },
};

/**
 * Tables in `ruvee_control`: read access to the two columns the maintenance gate needs (and the
 * key its query names). Nothing on the reopening codes: those go through the functions.
 */
export const RUNTIME_CONTROL_GRANTS: Readonly<Record<string, RuntimeGrant>> = {
  installation: { table: [], columns: { SELECT: ['id', 'origin'] } },
  restore_guard: { table: [], columns: { SELECT: ['id', 'state'] } },
  reopen_codes: { table: [] },
};

/** The reopening functions the runtime role may execute (`schema.name(argument types)`). */
export const RUNTIME_FUNCTIONS = [
  'ruvee_control.reopen_code_find(p_code_hash bytea)',
  'ruvee_control.reopen_code_failed(p_code_id uuid)',
  'ruvee_control.reopen_code_consume(p_code_id uuid, p_session_id uuid, p_via text)',
  'ruvee_control.reopen_session_via(p_session_id uuid, p_account_id uuid)',
  'ruvee_control.reopen_complete(p_session_id uuid)',
] as const;

/** Runs one parameterized query; node-pg and Prisma both fit. */
export type PrivilegeQuery = (sql: string, params: unknown[]) => Promise<Record<string, unknown>[]>;

const SYSTEM_SCHEMAS = `('pg_catalog', 'information_schema', 'pg_toast')`;
const COLUMN_PRIVILEGES = ['SELECT', 'INSERT', 'UPDATE', 'REFERENCES'] as const;
const TABLE_PRIVILEGES = [
  'SELECT',
  'INSERT',
  'UPDATE',
  'DELETE',
  'TRUNCATE',
  'REFERENCES',
  'TRIGGER',
  'MAINTAIN',
] as const;

function expectedFor(schema: string, table: string): RuntimeGrant | undefined {
  if (schema === 'public') return RUNTIME_GRANTS[table];
  if (schema === 'ruvee_control') return RUNTIME_CONTROL_GRANTS[table];
  return undefined;
}

/**
 * Everything `role` may do in the current database beyond the list above, as short descriptions
 * that name objects and privileges but never data. Empty means the role is exactly the runtime
 * role this file describes. Read-only; any role may run it, the runtime role included (only OIDs
 * are passed to the privilege functions, so no schema needs to be visible).
 */
export async function privilegeProblems(query: PrivilegeQuery, role: string): Promise<string[]> {
  const problems: string[] = [];
  const [attrs] = await query(
    `SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls,
       (SELECT count(*) FROM pg_auth_members m WHERE m.member = r.oid)::int AS memberships,
       ((SELECT count(*) FROM pg_namespace WHERE nspowner = r.oid)
        + (SELECT count(*) FROM pg_class WHERE relowner = r.oid)
        + (SELECT count(*) FROM pg_proc WHERE proowner = r.oid)
        + (SELECT count(*) FROM pg_type WHERE typowner = r.oid)
        + (SELECT count(*) FROM pg_largeobject_metadata WHERE lomowner = r.oid)
        + (SELECT count(*) FROM pg_database WHERE datname = current_database() AND datdba = r.oid)
       )::int AS owned,
       (SELECT count(*) FROM pg_default_acl d, aclexplode(d.defaclacl) a WHERE a.grantee = r.oid)::int
         AS default_grants,
       has_database_privilege(r.oid, current_database(), 'CREATE') AS db_create,
       has_database_privilege(r.oid, current_database(), 'TEMPORARY') AS db_temp,
       has_database_privilege(r.oid, current_database(), 'CONNECT') AS db_connect
     FROM pg_roles r WHERE r.rolname = $1`,
    [role],
  );
  if (!attrs) return [`the role ${role} does not exist`];
  for (const attr of [
    'rolsuper',
    'rolcreaterole',
    'rolcreatedb',
    'rolreplication',
    'rolbypassrls',
  ] as const)
    if (attrs[attr] === true) problems.push(`role attribute ${attr.slice(3).toUpperCase()}`);
  if (Number(attrs.memberships) > 0) problems.push('member of another role');
  if (Number(attrs.owned) > 0) problems.push('owns objects in this database');
  if (Number(attrs.default_grants) > 0) problems.push('receives default privileges');
  if (attrs.db_create === true) problems.push('CREATE on the database');
  if (attrs.db_temp === true) problems.push('TEMPORARY on the database');
  if (attrs.db_connect !== true) problems.push('missing CONNECT on the database');

  const schemas = await query(
    `SELECT n.nspname AS name,
       has_schema_privilege(r.oid, n.oid, 'USAGE') AS usage,
       has_schema_privilege(r.oid, n.oid, 'CREATE') AS create
     FROM pg_namespace n, pg_roles r
     WHERE r.rolname = $1 AND n.nspname NOT IN ${SYSTEM_SCHEMAS}
       AND n.nspname NOT LIKE 'pg_temp_%' AND n.nspname NOT LIKE 'pg_toast_temp_%'`,
    [role],
  );
  for (const s of schemas) {
    const name = String(s.name);
    if (s.create === true) problems.push(`CREATE on schema ${name}`);
    const expected = name === 'public' || name === 'ruvee_control';
    if (s.usage === true && !expected) problems.push(`USAGE on schema ${name}`);
    if (s.usage !== true && expected) problems.push(`missing USAGE on schema ${name}`);
  }

  const relations = await query(
    `SELECT n.nspname AS schema, c.relname AS name, c.relkind::text AS kind,
       ARRAY(SELECT p FROM unnest($2::text[]) p WHERE has_table_privilege(r.oid, c.oid, p)) AS granted
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace, pg_roles r
     WHERE r.rolname = $1 AND c.relkind IN ('r', 'p', 'v', 'm', 'f', 'S')
       AND n.nspname NOT IN ${SYSTEM_SCHEMAS}`,
    [role, TABLE_PRIVILEGES],
  );
  for (const rel of relations) {
    const where = `${String(rel.schema)}.${String(rel.name)}`;
    const granted = new Set(rel.granted as string[]);
    const expected =
      rel.kind === 'S' ? undefined : expectedFor(String(rel.schema), String(rel.name));
    for (const p of TABLE_PRIVILEGES) {
      const want = expected?.table.includes(p as TablePrivilege) ?? false;
      if (granted.has(p) && !want) problems.push(`${p} on ${where}`);
      if (!granted.has(p) && want) problems.push(`missing ${p} on ${where}`);
    }
  }

  const columns = await query(
    `SELECT n.nspname AS schema, c.relname AS name, a.attname AS column,
       ARRAY(SELECT p FROM unnest($2::text[]) p
             WHERE has_column_privilege(r.oid, c.oid, a.attnum, p)) AS granted
     FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid
       JOIN pg_namespace n ON n.oid = c.relnamespace, pg_roles r
     WHERE r.rolname = $1 AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
       AND a.attnum > 0 AND NOT a.attisdropped AND n.nspname NOT IN ${SYSTEM_SCHEMAS}`,
    [role, COLUMN_PRIVILEGES],
  );
  for (const col of columns) {
    const where = `${String(col.schema)}.${String(col.name)}.${String(col.column)}`;
    const granted = new Set(col.granted as string[]);
    const expected = expectedFor(String(col.schema), String(col.name));
    for (const p of COLUMN_PRIVILEGES) {
      const want =
        expected !== undefined &&
        (expected.table.includes(p as TablePrivilege) ||
          (expected.columns?.[p as TablePrivilege]?.includes(String(col.column)) ?? false));
      if (granted.has(p) && !want) problems.push(`${p} on ${where}`);
      if (!granted.has(p) && want) problems.push(`missing ${p} on ${where}`);
    }
  }

  const functions = await query(
    `SELECT n.nspname || '.' || p.proname || '(' || pg_get_function_identity_arguments(p.oid) || ')'
         AS name,
       has_function_privilege(r.oid, p.oid, 'EXECUTE') AS execute
     FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace, pg_roles r
     WHERE r.rolname = $1 AND n.nspname NOT IN ${SYSTEM_SCHEMAS}`,
    [role],
  );
  const allowed = new Set<string>(RUNTIME_FUNCTIONS);
  for (const f of functions) {
    const name = String(f.name);
    if (f.execute === true && !allowed.has(name)) problems.push(`EXECUTE on ${name}`);
    if (f.execute !== true && allowed.has(name)) problems.push(`missing EXECUTE on ${name}`);
  }
  return problems;
}
