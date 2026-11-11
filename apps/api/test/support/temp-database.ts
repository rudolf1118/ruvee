import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { appendFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import pg from 'pg';

/**
 * Integration tests never migrate the database in DATABASE_URL. They create a uniquely named
 * database on the same server (`ruvee_it_<random>`), migrate that, and drop it afterwards.
 * The role in DATABASE_URL therefore needs CREATEDB and CREATEROLE (a superuser in CI).
 *
 * Each database gets its own three roles (database-roles.md, F-25), named after it
 * (`<name>_owner`, `<name>_operator`, `<name>_runtime`) and made with the same statements the
 * guide gives the cluster administrator. The API under test connects as the runtime role,
 * migrations run as the owner and `ruvee-admin` steps as the operator; the URL in DATABASE_URL
 * (`url`) is only the test's own view, to set up and inspect.
 */
const PREFIX = 'ruvee_it_';
/** Exactly the names this module creates; nothing else is ever dropped. */
export const TEMP_DATABASE_NAME = /^ruvee_it_[0-9a-f]{12}$/;

/**
 * Every database this test process created and has not dropped yet, with the server it is on.
 * `dropTracked` (run after each test file, db-lifecycle.setup.ts) drops what a failed or timed-out
 * test left; the ledger (db-ledger.global.ts) covers a worker that died before that.
 */
const tracked = new Map<string, string>();

/** Only the name: the run's teardown connects with its own DATABASE_URL, so no URL is stored. */
function recordInLedger(name: string): void {
  const dir = process.env.RUVEE_IT_LEDGER_DIR;
  if (!dir) return;
  appendFileSync(join(dir, `${String(process.pid)}.txt`), `${name}\n`, { mode: 0o600 });
}

/**
 * The server URL as this process first saw it. A harness later points DATABASE_URL at its own
 * temporary database, so a URL recorded afterwards may name a database that is gone by now.
 */
const ORIGINAL_SERVER_URL = process.env.DATABASE_URL;

/** A URL on the same server that connects through a database the tests did not create. */
function maintenanceUrl(serverUrl: string): string {
  const database = new URL(serverUrl).pathname.slice(1);
  if (!TEMP_DATABASE_NAME.test(database)) return serverUrl;
  const fallback = ORIGINAL_SERVER_URL;
  if (!fallback || TEMP_DATABASE_NAME.test(new URL(fallback).pathname.slice(1)))
    throw new Error('no non-temporary database to connect through');
  return fallback;
}

const ROLE_SUFFIXES = ['owner', 'operator', 'runtime'] as const;

/** Drops one database by its exact, checked name, and then its three roles by theirs. */
export async function dropDatabase(serverUrl: string, name: string): Promise<void> {
  if (!TEMP_DATABASE_NAME.test(name))
    throw new Error('refusing to drop a database the test did not create');
  const client = new pg.Client({ connectionString: maintenanceUrl(serverUrl) });
  await client.connect();
  try {
    await client.query(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`);
    // The roles own nothing anywhere else; the operator is dropped before the owner it inherits.
    for (const suffix of ['runtime', 'operator', 'owner'])
      await client.query(`DROP ROLE IF EXISTS "${name}_${suffix}"`);
  } finally {
    await client.end();
  }
}

/** Drops every database this process created and did not drop; returns their names. */
export async function dropTracked(): Promise<string[]> {
  const left = [...tracked];
  for (const [name, serverUrl] of left) {
    await dropDatabase(serverUrl, name);
    tracked.delete(name);
  }
  return left.map(([name]) => name);
}
const apiRoot = new URL('../../', import.meta.url);

function adminUrl(): string {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error('DATABASE_URL must point at a PostgreSQL server for integration tests');
  // A harness points DATABASE_URL at its own temporary database, which may be gone by now.
  return maintenanceUrl(url);
}

function withDatabase(url: string, database: string): string {
  const u = new URL(url);
  u.pathname = `/${database}`;
  return u.toString();
}

export interface TempRole {
  readonly name: string;
  readonly url: string;
}

export interface TempDatabase {
  readonly name: string;
  /** The test's own superuser view of this database: setup and inspection only. */
  readonly url: string;
  /** The schema owner: migrations. */
  readonly owner: TempRole;
  /** The operator: `ruvee-admin` (init, backup, restore and review). */
  readonly operator: TempRole;
  /** The API's runtime role. */
  readonly runtime: TempRole;
  drop(): Promise<void>;
}

function roleUrl(serverUrl: string, database: string, role: string, password: string): string {
  const u = new URL(withDatabase(serverUrl, database));
  u.username = role;
  u.password = password;
  return u.toString();
}

export async function createTempDatabase(): Promise<TempDatabase> {
  const name = `${PREFIX}${randomBytes(6).toString('hex')}`;
  // Captured now: a harness later points DATABASE_URL at the temporary database itself.
  const serverUrl = adminUrl();
  const names = {
    owner: `${name}_owner`,
    operator: `${name}_operator`,
    runtime: `${name}_runtime`,
  };
  const passwords = Object.fromEntries(
    ROLE_SUFFIXES.map((r) => [r, randomBytes(18).toString('base64url')]),
  ) as Record<(typeof ROLE_SUFFIXES)[number], string>;
  const { databaseSetupStatements, roleSetupStatements } =
    await import('../../src/admin/database-roles.js');
  const admin = new pg.Client({ connectionString: serverUrl });
  await admin.connect();
  try {
    // Recorded before it exists: a process killed between the two still has it in the ledger.
    recordInLedger(name);
    tracked.set(name, serverUrl);
    for (const sql of roleSetupStatements(names)) await admin.query(sql);
    for (const r of ROLE_SUFFIXES)
      await admin.query(`ALTER ROLE "${names[r]}" PASSWORD ${admin.escapeLiteral(passwords[r])}`);
    await admin.query(`CREATE DATABASE "${name}" OWNER "${names.operator}"`);
  } finally {
    await admin.end();
  }
  const inDb = new pg.Client({ connectionString: withDatabase(serverUrl, name) });
  await inDb.connect();
  try {
    for (const sql of databaseSetupStatements(name, names)) await inDb.query(sql);
  } finally {
    await inDb.end();
  }
  const role = (r: (typeof ROLE_SUFFIXES)[number]): TempRole => ({
    name: names[r],
    url: roleUrl(serverUrl, name, names[r], passwords[r]),
  });
  return {
    name,
    url: withDatabase(serverUrl, name),
    owner: role('owner'),
    operator: role('operator'),
    runtime: role('runtime'),
    async drop() {
      await dropDatabase(serverUrl, name);
      tracked.delete(name);
    },
  };
}

/**
 * `ruvee-admin init`'s effect, as the operator: the database becomes a fresh installation the API
 * serves, and the runtime role gets its list.
 */
export async function initFresh(db: TempDatabase): Promise<void> {
  const { initInstallation } = await import('../../src/admin/installation.js');
  const client = new pg.Client({ connectionString: db.operator.url });
  await client.connect();
  try {
    await initInstallation(client, db.runtime.name);
  } finally {
    await client.end();
  }
}

/** `prisma migrate deploy` against the given database; throws with Prisma's output on failure. */
export function migrate(url: string): void {
  const result = spawnSync('node_modules/.bin/prisma', ['migrate', 'deploy'], {
    cwd: apiRoot.pathname,
    env: { ...process.env, DATABASE_URL: url, PRISMA_HIDE_UPDATE_MESSAGE: '1' },
    encoding: 'utf8',
  });
  if (result.status !== 0)
    throw new Error(`prisma migrate deploy failed:\n${result.stdout}${result.stderr}`);
}

export async function runSqlFile(url: string, relativePath: string): Promise<void> {
  const sql = await readFile(new URL(relativePath, apiRoot), 'utf8');
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    await client.query(sql);
  } finally {
    await client.end();
  }
}

export async function query<T extends pg.QueryResultRow>(
  url: string,
  text: string,
  values: unknown[] = [],
): Promise<T[]> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    return (await client.query<T>(text, values)).rows;
  } finally {
    await client.end();
  }
}
