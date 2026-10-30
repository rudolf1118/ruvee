import type pg from 'pg';
import {
  RUNTIME_CONTROL_GRANTS,
  RUNTIME_GRANTS,
  privilegeProblems,
  type RuntimeGrant,
} from '../database/runtime-privileges.js';
import { installReopenFunctions } from './reopen-functions.js';

/**
 * Database roles (follow-up review F-25; docs/architecture/database-roles.md):
 *
 * - **runtime** (`DATABASE_URL` of the API): data access from RUNTIME_GRANTS only; owns nothing,
 *   creates nothing, no role attributes, no memberships.
 * - **owner**: owns the `public` schema and every object in it; `prisma migrate deploy` runs as
 *   it. Its credentials are never given to the API.
 * - **operator** (`ruvee-admin` on the host): owns the database and `ruvee_control`, may create
 *   the restore's temporary loader role (CREATEROLE), and inherits the owner role, so it can
 *   restore, migrate a restored database and hand objects to the owner.
 * - **loader**: one per restore, made and dropped by the operator (restore-control.ts).
 *
 * The cluster administrator (a superuser) creates the three roles and the database once; the
 * statements are below so the guide and the tests use the same ones.
 */

export interface RoleNames {
  readonly owner: string;
  readonly operator: string;
  readonly runtime: string;
}

export const ident = (name: string) => `"${name.replace(/"/g, '""')}"`;

const ROLE_NAME = /^[a-z_][a-z0-9_]{0,62}$/;

export class RoleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RoleError';
  }
}

/** A role name as `ruvee-admin` accepts it from configuration: plain, unquoted, lower case. */
export function checkRoleName(name: string | undefined, what: string): string {
  if (!name || !ROLE_NAME.test(name))
    throw new RoleError(`${what} must be a plain lower-case role name`);
  return name;
}

/** As a superuser, once per cluster: the three roles, without passwords (set them separately). */
export function roleSetupStatements(names: RoleNames): string[] {
  const none = 'NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS';
  return [
    `CREATE ROLE ${ident(names.owner)} LOGIN ${none} NOCREATEROLE NOINHERIT`,
    `CREATE ROLE ${ident(names.operator)} LOGIN ${none} CREATEROLE INHERIT`,
    `GRANT ${ident(names.owner)} TO ${ident(names.operator)} WITH INHERIT TRUE, SET TRUE`,
    `CREATE ROLE ${ident(names.runtime)} LOGIN ${none} NOCREATEROLE NOINHERIT`,
  ];
}

/**
 * As a superuser, connected to a new, empty database (`CREATE DATABASE … OWNER <operator>`): the
 * owner takes `public`, and PUBLIC loses its default access. The same for a restore target.
 */
export function databaseSetupStatements(database: string, names: RoleNames): string[] {
  return [
    `ALTER DATABASE ${ident(database)} OWNER TO ${ident(names.operator)}`,
    `REVOKE ALL ON DATABASE ${ident(database)} FROM PUBLIC`,
    // The runtime role connects from the start, so a database that is not set up yet answers
    // `maintenance` (it can read that there is no control schema), never "unavailable".
    `GRANT CONNECT ON DATABASE ${ident(database)} TO ${ident(names.owner)}, ${ident(names.runtime)}`,
    `ALTER SCHEMA public OWNER TO ${ident(names.owner)}`,
    `REVOKE ALL ON SCHEMA public FROM PUBLIC`,
  ];
}

/**
 * As a superuser, connected to a database set up before F-25 (everything owned by one admin
 * role, the API connecting as it), after `roleSetupStatements`: the same end state as a new
 * database. Then `ruvee-admin grant-runtime` as the operator, and the API's DATABASE_URL moves to
 * the runtime role. Changes ownership and privileges only, never a row.
 */
export function existingDatabaseStatements(database: string, names: RoleNames): string[] {
  const owner = ident(names.owner);
  const operator = ident(names.operator);
  return [
    ...databaseSetupStatements(database, names),
    `DO $$ DECLARE r record; BEGIN
      FOR r IN SELECT c.relname, c.relkind FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'public' AND c.relkind IN ('r', 'S') LOOP
        EXECUTE format('ALTER %s public.%I OWNER TO ${owner.replace(/'/g, "''")}',
          CASE r.relkind WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, r.relname);
      END LOOP;
      FOR r IN SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
          WHERE n.nspname = 'public' AND t.typtype = 'e' LOOP
        EXECUTE format('ALTER TYPE public.%I OWNER TO ${owner.replace(/'/g, "''")}', r.typname);
      END LOOP;
      IF to_regnamespace('ruvee_control') IS NOT NULL THEN
        EXECUTE 'ALTER SCHEMA ruvee_control OWNER TO ${operator.replace(/'/g, "''")}';
        EXECUTE 'REVOKE ALL ON SCHEMA ruvee_control FROM PUBLIC';
        FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'ruvee_control' AND c.relkind = 'r' LOOP
          EXECUTE format('ALTER TABLE ruvee_control.%I OWNER TO ${operator.replace(/'/g, "''")}',
            r.relname);
        END LOOP;
      END IF;
    END $$`,
  ];
}

/**
 * Refuses to run administrative steps as a superuser (a restored dump's SQL would run with its
 * rights, §3.2b) or as the runtime role. Returns the connected role.
 */
export async function assertOperator(c: pg.Client, runtimeRole: string): Promise<string> {
  const { rows } = await c.query<{ name: string; superuser: boolean; createrole: boolean }>(
    `SELECT current_user AS name, rolsuper AS superuser, rolcreaterole AS createrole
     FROM pg_roles WHERE rolname = current_user`,
  );
  const me = rows[0];
  if (!me) throw new RoleError('the connected role is unknown');
  if (me.superuser)
    throw new RoleError(
      'connect as the operator role, not a superuser: a restored dump runs with the rights of the role that loads it',
    );
  if (me.name === runtimeRole)
    throw new RoleError('connect as the operator role, not the API runtime role');
  return me.name;
}

/** The role that owns `public`: the schema owner. Never the operator itself or the runtime role. */
export async function schemaOwner(c: pg.Client, runtimeRole: string): Promise<string> {
  const { rows } = await c.query<{ owner: string; superuser: boolean; me: string }>(
    `SELECT r.rolname AS owner, r.rolsuper AS superuser, current_user AS me
     FROM pg_namespace n JOIN pg_roles r ON r.oid = n.nspowner WHERE n.nspname = 'public'`,
  );
  const row = rows[0];
  if (
    !row ||
    row.superuser ||
    row.owner === row.me ||
    row.owner === runtimeRole ||
    row.owner === 'pg_database_owner'
  )
    throw new RoleError(
      'the public schema must be owned by the schema owner role (not a superuser, the operator or the runtime role); see the database roles guide',
    );
  return row.owner;
}

/**
 * Hands every object in `public` that is not the schema owner's to it (after a restore's LOAD and
 * MIGRATE ran as the operator). Indexes and row types follow their tables. Returns how many.
 */
export async function normalizeOwnership(c: pg.Client, owner: string): Promise<number> {
  const relations = await c.query<{ name: string; kind: string }>(
    `SELECT c.relname AS name, c.relkind::text AS kind FROM pg_class c
     JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles r ON r.oid = c.relowner
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'S') AND r.rolname <> $1`,
    [owner],
  );
  for (const rel of relations.rows)
    await c.query(
      `ALTER ${rel.kind === 'S' ? 'SEQUENCE' : 'TABLE'} public.${ident(rel.name)} OWNER TO ${ident(owner)}`,
    );
  const types = await c.query<{ name: string }>(
    `SELECT t.typname AS name FROM pg_type t
     JOIN pg_namespace n ON n.oid = t.typnamespace JOIN pg_roles r ON r.oid = t.typowner
     WHERE n.nspname = 'public' AND t.typtype = 'e' AND r.rolname <> $1`,
    [owner],
  );
  for (const type of types.rows)
    await c.query(`ALTER TYPE public.${ident(type.name)} OWNER TO ${ident(owner)}`);
  return relations.rows.length + types.rows.length;
}

async function exists(c: pg.Client, regclass: string): Promise<boolean> {
  const { rows } = await c.query<{ t: string | null }>(`SELECT to_regclass($1)::text AS t`, [
    regclass,
  ]);
  return Boolean(rows[0]?.t);
}

function grantStatements(schema: string, table: string, grant: RuntimeGrant, role: string) {
  const target = `${schema}.${ident(table)}`;
  const statements: string[] = [];
  if (grant.table.length > 0)
    statements.push(`GRANT ${grant.table.join(', ')} ON ${target} TO ${ident(role)}`);
  for (const [privilege, columns] of Object.entries(grant.columns ?? {}))
    statements.push(
      `GRANT ${privilege} (${columns.map(ident).join(', ')}) ON ${target} TO ${ident(role)}`,
    );
  return statements;
}

/**
 * `ruvee-admin grant-runtime`, also run by `init` and by a restore's APPLY POLICY: as the operator,
 * inside the caller's transaction, sets the runtime role's privileges in this database to
 * exactly RUNTIME_GRANTS (everything else it held here is revoked first), installs the reopening
 * functions where a restore guard exists, and then checks the result. Refuses a runtime role
 * with any role attribute, membership or ownership, and a table nobody classified.
 */
export async function applyRuntimeGrants(c: pg.Client, runtimeRole: string): Promise<void> {
  await assertRuntimeRoleUsable(c, runtimeRole);

  const tables = await c.query<{ name: string }>(
    `SELECT c.relname AS name FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p') AND c.relname <> '_prisma_migrations'`,
  );
  const unclassified = tables.rows.map((t) => t.name).filter((t) => !(t in RUNTIME_GRANTS));
  if (unclassified.length > 0)
    throw new RoleError(
      `tables without a runtime classification (runtime-privileges.ts): ${unclassified.join(', ')}`,
    );

  const role = ident(runtimeRole);
  const control = await c.query<{ s: string | null }>(
    `SELECT to_regnamespace('ruvee_control')::text AS s`,
  );
  const hasControl = Boolean(control.rows[0]?.s);
  // Start from nothing in this database, then grant the list.
  await c.query(`REVOKE ALL ON DATABASE ${ident(await database(c))} FROM PUBLIC, ${role}`);
  await c.query(`REVOKE ALL ON SCHEMA public FROM ${role}`);
  await c.query(`REVOKE ALL ON ALL TABLES IN SCHEMA public FROM ${role}`);
  await c.query(`REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM ${role}`);
  await c.query(`REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM ${role}`);
  if (hasControl) {
    await c.query(`REVOKE ALL ON SCHEMA ruvee_control FROM ${role}`);
    await c.query(`REVOKE ALL ON ALL TABLES IN SCHEMA ruvee_control FROM ${role}`);
    await c.query(`REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ruvee_control FROM ${role}`);
  }
  await c.query(`GRANT CONNECT ON DATABASE ${ident(await database(c))} TO ${role}`);
  await c.query(`GRANT USAGE ON SCHEMA public TO ${role}`);
  for (const [table, grant] of Object.entries(RUNTIME_GRANTS))
    for (const sql of grantStatements('public', table, grant, runtimeRole)) await c.query(sql);
  if (hasControl) {
    await c.query(`GRANT USAGE ON SCHEMA ruvee_control TO ${role}`);
    for (const [table, grant] of Object.entries(RUNTIME_CONTROL_GRANTS))
      if (await exists(c, `ruvee_control.${table}`))
        for (const sql of grantStatements('ruvee_control', table, grant, runtimeRole))
          await c.query(sql);
    if (
      (await exists(c, 'ruvee_control.restore_guard')) &&
      (await exists(c, 'ruvee_control.reopen_codes'))
    )
      await installReopenFunctions(c, runtimeRole);
  }
  const after = await privilegeProblems(rows(c), runtimeRole);
  if (after.length > 0)
    throw new RoleError(`the runtime role's privileges are not as listed: ${after.join(', ')}`);
}

const rows = (c: pg.Client) => (sql: string, params: unknown[]) =>
  c.query(sql, params).then((r) => r.rows as Record<string, unknown>[]);

/**
 * The runtime role exists and is a plain role: no attribute, no membership, owning nothing here.
 * Privileges it holds are not checked here: `applyRuntimeGrants` replaces them.
 */
export async function assertRuntimeRoleUsable(c: pg.Client, runtimeRole: string): Promise<void> {
  checkRoleName(runtimeRole, 'the runtime role');
  const unusable = (await privilegeProblems(rows(c), runtimeRole)).filter(
    (p) =>
      p.startsWith('role attribute') ||
      p === 'member of another role' ||
      p === 'owns objects in this database' ||
      p.endsWith('does not exist'),
  );
  if (unusable.length > 0)
    throw new RoleError(`the runtime role cannot be used: ${unusable.join(', ')}`);
}

async function database(c: pg.Client): Promise<string> {
  const { rows } = await c.query<{ db: string }>('SELECT current_database() AS db');
  return rows[0]?.db ?? '';
}
