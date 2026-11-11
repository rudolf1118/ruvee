// Test-only: a throwaway `ruvee_e2e_<hex>` database with its own three roles (schema owner,
// operator, API runtime), made on the PostgreSQL server in RUVEE_E2E_ADMIN_DATABASE_URL with the
// statements docs/guides/database-roles.md gives the cluster administrator (the built
// src/admin/database-roles.ts). The browser tests then migrate as the owner, run `ruvee-admin` as
// the operator and serve the API as the runtime role, as deployed (follow-up review F-25). Only
// these exact names are ever created or dropped. Synthetic data only.
import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { databaseSetupStatements, roleSetupStatements } from '../dist/admin/database-roles.js';

export const E2E_DATABASE = /^ruvee_e2e_[0-9a-f]{12}$/;
const ROLES = ['owner', 'operator', 'runtime'];

function urlFor(adminUrl, database, user, password) {
  const u = new URL(adminUrl);
  u.pathname = `/${database}`;
  if (user) {
    u.username = user;
    u.password = password;
  }
  return u.toString();
}

async function run(url, statements) {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    for (const sql of statements) await client.query(sql);
  } finally {
    await client.end();
  }
}

/** Creates the database and its roles; returns each role's name and URL. */
export async function createDatabaseWithRoles(adminUrl, name) {
  if (!E2E_DATABASE.test(name)) throw new Error('not an e2e database name');
  const names = Object.fromEntries(ROLES.map((r) => [r, `${name}_${r}`]));
  const passwords = Object.fromEntries(
    ROLES.map((r) => [r, randomBytes(18).toString('base64url')]),
  );
  await run(adminUrl, [
    ...roleSetupStatements(names),
    ...ROLES.map((r) => `ALTER ROLE "${names[r]}" PASSWORD '${passwords[r]}'`),
    `CREATE DATABASE "${name}" OWNER "${names.operator}"`,
  ]);
  await run(urlFor(adminUrl, name), databaseSetupStatements(name, names));
  return Object.fromEntries(
    ROLES.map((r) => [r, { name: names[r], url: urlFor(adminUrl, name, names[r], passwords[r]) }]),
  );
}

/** Drops the database, then its three roles, by their exact names. */
export async function dropDatabaseWithRoles(adminUrl, name) {
  if (!E2E_DATABASE.test(name)) throw new Error('not an e2e database name');
  await run(adminUrl, [
    `DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`,
    ...['runtime', 'operator', 'owner'].map((r) => `DROP ROLE IF EXISTS "${name}_${r}"`),
  ]);
}
