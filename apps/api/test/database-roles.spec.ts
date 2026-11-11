import { readdirSync, readFileSync } from 'node:fs';
import { TABLE_INVENTORY } from '../src/admin/backup-inventory.js';
import { REOPEN_FUNCTIONS_SQL } from '../src/admin/reopen-functions.js';
import { RUNTIME_FUNCTIONS, RUNTIME_GRANTS } from '../src/database/runtime-privileges.js';
import { isPrivilegeError } from '../src/maintenance/maintenance.service.js';

/**
 * Follow-up review F-25: the runtime role's list stays complete and minimal, and nothing a future
 * migration or edit adds can widen it silently. Static checks; the database checks are in
 * review/f25-roles.int-spec.ts.
 */
const migrations = new URL('../prisma/migrations/', import.meta.url);

describe('F-25: the runtime privilege list', () => {
  it('classifies exactly the tables of the backup inventory', () => {
    expect(Object.keys(RUNTIME_GRANTS).sort()).toEqual(Object.keys(TABLE_INVENTORY).sort());
  });

  it('never grants TRUNCATE, REFERENCES, TRIGGER or anything on the migration table', () => {
    for (const grant of Object.values(RUNTIME_GRANTS))
      for (const p of grant.table) expect(['SELECT', 'INSERT', 'UPDATE', 'DELETE']).toContain(p);
    expect(RUNTIME_GRANTS._prisma_migrations).toBeUndefined();
  });

  it('migrations hold no privilege, ownership or role statement', () => {
    const forbidden =
      /\b(GRANT|REVOKE|OWNER\s+TO|CREATE\s+ROLE|ALTER\s+ROLE|DROP\s+ROLE|ALTER\s+DEFAULT\s+PRIVILEGES|SECURITY\s+DEFINER|SET\s+ROLE|SET\s+SESSION\s+AUTHORIZATION|CREATE\s+(OR\s+REPLACE\s+)?FUNCTION|CREATE\s+EXTENSION)\b/i;
    const dirs = readdirSync(migrations, { withFileTypes: true }).filter((d) => d.isDirectory());
    expect(dirs.length).toBeGreaterThan(0);
    for (const dir of dirs) {
      // Statements only: comments, string literals and quoted names may say anything.
      const sql = readFileSync(new URL(`${dir.name}/migration.sql`, migrations), 'utf8')
        .replace(/--[^\n]*/g, '')
        .replace(/'(?:[^']|'')*'/g, "''")
        .replace(/"(?:[^"]|"")*"/g, '""');
      expect(forbidden.exec(sql)?.[0], dir.name).toBeUndefined();
    }
  });
});

describe('F-25: the reopening functions', () => {
  it('are exactly the functions the runtime role may execute', () => {
    const names = REOPEN_FUNCTIONS_SQL.map(
      (sql) => /FUNCTION (ruvee_control\.\w+)\(/.exec(sql)?.[1],
    );
    expect(names).toEqual(RUNTIME_FUNCTIONS.map((f) => f.slice(0, f.indexOf('('))));
  });

  it('run with a fixed search_path and name every table with its schema', () => {
    for (const sql of REOPEN_FUNCTIONS_SQL) {
      expect(sql).toMatch(/SECURITY DEFINER SET search_path = pg_catalog, pg_temp/);
      for (const [, name] of sql.matchAll(/\b(?:FROM|JOIN|UPDATE)\s+([a-z_.]+)/g))
        expect(name).toMatch(/^(ruvee_control|public)\./);
      // A function or variable the caller could shadow: every call is pg_catalog's or plpgsql.
      expect(sql).not.toMatch(/(?<![.\w])now\(\)/);
    }
  });
});

describe('F-25: administrative commands never use the API runtime URL', () => {
  it('ruvee-admin reads the operator URLs, never DATABASE_URL', () => {
    const cli = readFileSync(new URL('../src/admin/cli.ts', import.meta.url), 'utf8');
    expect(cli).not.toMatch(/process\.env\.DATABASE_URL/);
    expect(cli).toMatch(/process\.env\.RUVEE_ADMIN_DATABASE_URL/);
    expect(cli).toMatch(/process\.env\.RESTORE_DATABASE_URL/);
  });
});

describe('F-25: the maintenance gate recognises a missing privilege', () => {
  it('finds PostgreSQL 42501 and 42883 through nested driver errors, and nothing else', () => {
    expect(isPrivilegeError({ cause: { code: '42501' } })).toBe(true);
    expect(
      isPrivilegeError({ meta: { driverAdapterError: { cause: { originalCode: '42883' } } } }),
    ).toBe(true);
    expect(isPrivilegeError(new Error('connection refused'))).toBe(false);
    expect(isPrivilegeError({ code: 'P1001' })).toBe(false);
    expect(isPrivilegeError({ cause: { code: '08006' } })).toBe(false);
  });
});
