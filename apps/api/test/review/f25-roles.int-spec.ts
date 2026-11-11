import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { copyFileSync, chmodSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';
import {
  applyRuntimeGrants,
  assertOperator,
  existingDatabaseStatements,
  RoleError,
} from '../../src/admin/database-roles.js';
import { initInstallation } from '../../src/admin/installation.js';
import { pgToolsFromEnv } from '../../src/admin/pg-tools.js';
import {
  completeRestore,
  createBackup,
  issueReopenCode,
  knownMigrations,
  restoreBackup,
  type BackupResult,
} from '../../src/admin/server-restore.js';
import { privilegeProblems } from '../../src/database/runtime-privileges.js';
import { registerAccount, startHarness, type Harness } from '../support/api-harness.js';
import { testBackupKey, type TestBackupKey } from '../support/backup-keys.js';
import { reopenWithKit } from '../support/reopen-client.js';
import { syntheticAccount, type SyntheticAccount } from '../support/synthetic-client.js';
import {
  createTempDatabase,
  initFresh,
  migrate,
  query,
  type TempDatabase,
} from '../support/temp-database.js';

/**
 * Follow-up review F-25 (regression): the API runs as a runtime role that owns nothing and holds
 * only its listed privileges; restore state belongs to the operator and changes only through the
 * reopening functions; administrative steps refuse a superuser and the runtime role. Every
 * database here has its own owner, operator and runtime roles (temp-database.ts), made with the
 * guide's statements; the superuser URL (`db.url`) is only the test's view, to set up a state
 * and to look. Synthetic data only.
 */

const MIGRATIONS = knownMigrations(new URL('../../prisma/migrations', import.meta.url).pathname);
const tools = pgToolsFromEnv();
const config = {
  publicOrigin: 'http://127.0.0.1:3100',
  sessionCookieSecure: 'true' as const,
  extensionOrigins: '',
};
const SERVER_URL = process.env.DATABASE_URL ?? '';

const view = (url: string) => (sql: string, params: unknown[]) =>
  query<Record<string, unknown>>(url, sql, params);

async function connect(url: string): Promise<pg.Client> {
  const c = new pg.Client({ connectionString: url });
  await c.connect();
  return c;
}

/** The SQLSTATE a statement fails with as this connection's role, or 'ok'. */
async function sqlState(c: pg.Client, sql: string, params: unknown[] = []): Promise<string> {
  await c.query('SAVEPOINT attempt');
  try {
    await c.query(sql, params);
    await c.query('RELEASE SAVEPOINT attempt');
    return 'ok';
  } catch (error) {
    await c.query('ROLLBACK TO SAVEPOINT attempt');
    return (error as { code?: string }).code ?? 'unknown';
  }
}

const guardOf = async (db: TempDatabase) =>
  (await query<{ state: string }>(db.url, 'SELECT state FROM ruvee_control.restore_guard'))[0]
    ?.state;
const codesOf = (db: TempDatabase) =>
  query<{ failed: number; revoked: boolean; consumed: boolean }>(
    db.url,
    `SELECT failed_attempts AS failed, revoked_at IS NOT NULL AS revoked,
       consumed_at IS NOT NULL AS consumed
     FROM ruvee_control.reopen_codes ORDER BY created_at`,
  );
const aclsOf = (db: TempDatabase) =>
  query<{ acl: string }>(
    db.url,
    `SELECT coalesce(c.relacl::text, '') || '|' ||
       coalesce((SELECT string_agg(a.attname || '=' || a.attacl::text, ',' ORDER BY a.attnum)
                 FROM pg_attribute a WHERE a.attrelid = c.oid AND a.attacl IS NOT NULL), '') AS acl
     FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname IN ('public', 'ruvee_control') AND c.relkind = 'r' ORDER BY c.relname`,
  );

async function grantAsOperator(db: TempDatabase): Promise<void> {
  const c = await connect(db.operator.url);
  try {
    await c.query('BEGIN');
    await applyRuntimeGrants(c, db.runtime.name);
    await c.query('COMMIT');
  } finally {
    await c.end();
  }
}

/** A session row as the runtime role may write one (it creates sessions; that is its job). */
async function insertSession(
  c: pg.Client,
  accountId: string,
  deviceId: string,
  kind: 'reopen' | 'cookie',
  revoked = false,
): Promise<string> {
  const id = randomUUID();
  await c.query(
    `INSERT INTO sessions (id, account_id, device_id, kind, secret_hash, auth_at,
       idle_expires_at, absolute_expires_at, revoked_at, revoke_reason)
     VALUES ($1, $2, $3, $4, $5, now(), now() + interval '30 minutes',
       now() + interval '30 minutes', $6, $7)`,
    [
      id,
      accountId,
      deviceId,
      kind,
      randomBytes(32),
      revoked ? new Date() : null,
      revoked ? 'logout' : null,
    ],
  );
  return id;
}

describe('REVIEW F-25 (regression): least-privilege database roles', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let key: TestBackupKey;
  let outDir: string;
  let backup: BackupResult;
  /** A restored database in `reopening`, restored and reviewed as the operator. */
  let r: { db: TempDatabase; restoreId: string; code: string };
  const extra: TempDatabase[] = [];

  async function newDatabase(fresh: boolean): Promise<TempDatabase> {
    process.env.DATABASE_URL = SERVER_URL;
    const db = await createTempDatabase();
    extra.push(db);
    if (fresh) {
      migrate(db.owner.url);
      await initFresh(db);
    }
    return db;
  }

  beforeAll(async () => {
    process.env.DATABASE_URL = SERVER_URL;
    vi.resetModules();
    h = await startHarness();
    account = await syntheticAccount('synthetic-f25-owner');
    await registerAccount(h, account);
    key = await testBackupKey();
    outDir = mkdtempSync(join(tmpdir(), 'ruvee-review-f25-'));
    backup = await createBackup({
      databaseUrl: h.db.operator.url,
      outDir,
      tools,
      recipient: key.recipient,
      syntheticTestOnly: true,
      config,
    });
    process.env.DATABASE_URL = SERVER_URL;
    const db = await createTempDatabase();
    const restored = await restoreBackup({
      manifestPath: backup.manifestPath,
      identityPath: key.identityPath,
      trustedDigest: backup.digest,
      targetDatabaseUrl: db.operator.url,
      runtimeRole: db.runtime.name,
      tools,
      migrate,
      knownMigrations: MIGRATIONS,
    });
    if (!('removed' in restored)) throw new Error('restore stopped');
    const done = await completeRestore(db.operator.url, {
      restoreId: restored.restoreId,
      devicesReviewed: true,
      acceptRestoredCredentials: true,
    });
    if (done.state !== 'reopening') throw new Error('expected reopening');
    r = { db, restoreId: restored.restoreId, code: done.reopen.code };
  }, 180_000);

  afterAll(async () => {
    process.env.DATABASE_URL = SERVER_URL;
    await (h as Harness | undefined)?.close();
    await (r as typeof r | undefined)?.db.drop();
    for (const db of extra) await db.drop();
    if (outDir) rmSync(outDir, { recursive: true, force: true });
    (key as TestBackupKey | undefined)?.drop();
  }, 60_000);

  it('the runtime role holds exactly its list and owns nothing, fresh and restored', async () => {
    expect(await privilegeProblems(view(h.db.url), h.db.runtime.name)).toEqual([]);
    expect(await privilegeProblems(view(r.db.url), r.db.runtime.name)).toEqual([]);
    for (const db of [h.db, r.db]) {
      const [attrs] = await query<Record<string, boolean>>(
        db.url,
        `SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
         FROM pg_roles WHERE rolname = $1`,
        [db.runtime.name],
      );
      expect(Object.values(attrs ?? { missing: true }).every((v) => !v)).toBe(true);
    }
    // The schema owner owns `public` and all of it; the operator owns the control schema.
    const owners = await query<{ name: string; owner: string }>(
      r.db.url,
      `SELECT n.nspname AS name, o.rolname AS owner FROM pg_namespace n
       JOIN pg_roles o ON o.oid = n.nspowner WHERE n.nspname IN ('public', 'ruvee_control')
       ORDER BY 1`,
    );
    expect(owners).toEqual([
      { name: 'public', owner: r.db.owner.name },
      { name: 'ruvee_control', owner: r.db.operator.name },
    ]);
    const strays = await query<{ n: string }>(
      r.db.url,
      `SELECT count(*) AS n FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
       WHERE n.nspname = 'public' AND c.relowner <> $1::regrole`,
      [r.db.owner.name],
    );
    expect(strays[0]?.n).toBe('0');
    // The reopening functions: the operator's, definer rights, fixed search_path, no PUBLIC.
    const fns = await query<{
      owner: string;
      definer: boolean;
      config: string[] | null;
      public: boolean;
      runtime: boolean;
    }>(
      r.db.url,
      `SELECT o.rolname AS owner, p.prosecdef AS definer, p.proconfig AS config,
         has_function_privilege('public', p.oid, 'EXECUTE') AS public,
         has_function_privilege($1, p.oid, 'EXECUTE') AS runtime
       FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
       JOIN pg_roles o ON o.oid = p.proowner WHERE n.nspname = 'ruvee_control'`,
      [r.db.runtime.name],
    );
    expect(fns).toHaveLength(5);
    for (const f of fns)
      expect(f).toEqual({
        owner: r.db.operator.name,
        definer: true,
        config: ['search_path=pg_catalog, pg_temp'],
        public: false,
        runtime: true,
      });
  });

  it('runtime credentials cannot open maintenance, change, replace or own control objects, or gain roles', async () => {
    const aclsBefore = await aclsOf(r.db);
    const c = await connect(r.db.runtime.url);
    try {
      await c.query('BEGIN');
      const fn = 'ruvee_control.reopen_complete(uuid)';
      for (const sql of [
        `UPDATE ruvee_control.restore_guard SET state = 'open'`,
        `INSERT INTO ruvee_control.restore_guard (id, state) VALUES (2, 'open')`,
        'DELETE FROM ruvee_control.restore_guard',
        'SELECT code_hash FROM ruvee_control.reopen_codes',
        'UPDATE ruvee_control.reopen_codes SET revoked_at = NULL, failed_attempts = 0',
        'SELECT restore_id FROM ruvee_control.restore_guard',
        'DROP TABLE ruvee_control.restore_guard',
        'TRUNCATE ruvee_control.reopen_codes',
        `ALTER TABLE ruvee_control.restore_guard OWNER TO "${r.db.runtime.name}"`,
        'ALTER TABLE ruvee_control.restore_guard DISABLE ROW LEVEL SECURITY',
        'DROP SCHEMA ruvee_control CASCADE',
        'CREATE TABLE ruvee_control.f25 (id int)',
        `CREATE OR REPLACE FUNCTION ${fn.replace('(uuid)', '(p_session_id uuid)')} RETURNS uuid
           LANGUAGE sql AS 'SELECT NULL::uuid'`,
        `ALTER FUNCTION ${fn} OWNER TO "${r.db.runtime.name}"`,
        `ALTER FUNCTION ${fn} SECURITY INVOKER`,
        `DROP FUNCTION ${fn}`,
        'CREATE TABLE public.f25 (id int)',
        'CREATE SCHEMA f25',
        'CREATE TEMP TABLE f25 (id int)',
        'DROP TABLE public.accounts',
        'ALTER TABLE public.sessions ADD COLUMN f25 int',
        'TRUNCATE public.security_events',
        'DELETE FROM public.accounts',
        'DELETE FROM public.vault_commits',
        'CREATE ROLE f25_role',
        `GRANT "${r.db.operator.name}" TO "${r.db.runtime.name}"`,
        `GRANT "${r.db.owner.name}" TO "${r.db.runtime.name}"`,
        `SET ROLE "${r.db.operator.name}"`,
        `SET ROLE "${r.db.owner.name}"`,
        `ALTER ROLE "${r.db.runtime.name}" CREATEROLE`,
        `ALTER DATABASE "${r.db.name}" OWNER TO "${r.db.runtime.name}"`,
        `SET session_replication_role = replica`,
        `COPY (SELECT 1) TO PROGRAM 'true'`,
      ])
        expect(await sqlState(c, sql), sql).toBe('42501');
      // GRANT without a grant option is a warning that grants nothing: checked by its effect.
      for (const sql of [
        'GRANT ALL ON ruvee_control.restore_guard TO PUBLIC',
        `GRANT SELECT ON public.accounts TO "${r.db.owner.name}"`,
        'GRANT ALL ON ALL TABLES IN SCHEMA public TO PUBLIC',
      ])
        expect(['ok', '42501']).toContain(await sqlState(c, sql));
      await c.query('COMMIT');
    } finally {
      await c.end();
    }
    expect(await aclsOf(r.db)).toEqual(aclsBefore);
    expect(await guardOf(r.db)).toBe('reopening');
    // A fresh installation's row is as closed to it.
    const f = await connect(h.db.runtime.url);
    try {
      await f.query('BEGIN');
      for (const sql of [
        `UPDATE ruvee_control.installation SET origin = 'fresh'`,
        'DELETE FROM ruvee_control.installation',
        'DROP TABLE ruvee_control.installation',
        'CREATE TABLE ruvee_control.restore_guard (id int, state text)',
      ])
        expect(await sqlState(f, sql), sql).toBe('42501');
      await f.query('COMMIT');
    } finally {
      await f.end();
    }
  });

  it('the reopening functions refuse every transition the persisted state does not allow', async () => {
    const [device] = await query<{ id: string; account_id: string }>(
      r.db.url,
      `SELECT id, account_id FROM devices WHERE status = 'active' LIMIT 1`,
    );
    if (!device) throw new Error('no device in the snapshot');
    const codesBefore = await codesOf(r.db);
    const c = await connect(r.db.runtime.url);
    try {
      const find = async (hash: Buffer | null) =>
        (
          await c.query<{ code_id: string }>(
            'SELECT code_id FROM ruvee_control.reopen_code_find($1)',
            [hash],
          )
        ).rows;
      const consume = async (code: string, session: string, via: string | null) =>
        (
          await c.query<{ ok: boolean }>(
            'SELECT ruvee_control.reopen_code_consume($1, $2, $3) AS ok',
            [code, session, via],
          )
        ).rows[0]?.ok;
      const complete = async (session: string) =>
        (
          await c.query<{ id: string | null }>('SELECT ruvee_control.reopen_complete($1) AS id', [
            session,
          ])
        ).rows[0]?.id;
      // Without the code the runtime role cannot learn a code id: no hash matches.
      expect(await find(randomBytes(32))).toEqual([]);
      expect(await find(null)).toEqual([]);
      expect(await find(randomBytes(31))).toEqual([]);
      expect(await consume(randomUUID(), randomUUID(), 'password')).toBe(false);
      await c.query('SELECT ruvee_control.reopen_code_failed($1)', [randomUUID()]);
      expect(
        (
          await c.query('SELECT ruvee_control.reopen_session_via($1, $2) AS via', [
            randomUUID(),
            device.account_id,
          ])
        ).rows[0],
      ).toEqual({ via: null });
      expect(await complete(randomUUID())).toBeNull();

      // With the real code (the test reads its hash), every precondition is still checked.
      const hash = createHash('sha256')
        .update(Buffer.from(r.code.slice(4), 'base64url'))
        .digest();
      const [code] = await find(hash);
      if (!code) throw new Error('the usable code was not found');
      const live = await insertSession(c, device.account_id, device.id, 'reopen');
      const revoked = await insertSession(c, device.account_id, device.id, 'reopen', true);
      const cookie = await insertSession(c, device.account_id, device.id, 'cookie');
      expect(await consume(code.code_id, randomUUID(), 'password')).toBe(false);
      expect(await consume(code.code_id, revoked, 'password')).toBe(false);
      expect(await consume(code.code_id, cookie, 'password')).toBe(false);
      expect(await consume(code.code_id, live, 'admin')).toBe(false);
      expect(await consume(code.code_id, live, null)).toBe(false);
      // A live reopen session no code is linked to cannot complete anything.
      expect(await complete(live)).toBeNull();
      expect(await complete(cookie)).toBeNull();
      expect(await codesOf(r.db)).toEqual(codesBefore);
      expect(await guardOf(r.db)).toBe('reopening');

      // Only from `reopening`: a guard in review refuses consumption and completion.
      await query(r.db.url, `UPDATE ruvee_control.restore_guard SET state = 'review'`);
      expect(await consume(code.code_id, live, 'recovery')).toBe(false);
      await query(r.db.url, `UPDATE ruvee_control.restore_guard SET state = 'reopening'`);

      // The permitted transition is atomic with the caller's transaction: rolled back, nothing.
      await c.query('BEGIN');
      expect(await consume(code.code_id, live, 'recovery')).toBe(true);
      expect(await complete(live)).toBe(r.restoreId);
      expect((await c.query('SELECT state FROM ruvee_control.restore_guard')).rows).toEqual([
        { state: 'open' },
      ]);
      await c.query('ROLLBACK');
      expect(await guardOf(r.db)).toBe('reopening');
      expect(await codesOf(r.db)).toEqual(codesBefore);

      // Consumed, then the guard leaves `reopening` before completion: refused.
      expect(await consume(code.code_id, live, 'recovery')).toBe(true);
      expect(await consume(code.code_id, live, 'recovery')).toBe(false);
      await query(r.db.url, `UPDATE ruvee_control.restore_guard SET state = 'review'`);
      expect(await complete(live)).toBeNull();
      await query(r.db.url, `UPDATE ruvee_control.restore_guard SET state = 'reopening'`);
      // A host-issued new code revokes the consumed one: the session can no longer complete.
      r.code = (await issueReopenCode(r.db.operator.url, { restoreId: r.restoreId })).code;
      expect(await complete(live)).toBeNull();
      expect(await guardOf(r.db)).toBe('reopening');
    } finally {
      await c.end();
    }
  });

  it('missing permissions fail closed: no gate grant serves maintenance, no function grant opens nothing', async () => {
    const d = await newDatabase(true);
    await query(d.url, `REVOKE ALL ON ruvee_control.installation FROM "${d.runtime.name}"`);
    vi.resetModules();
    const closed = await startHarness({ database: d });
    try {
      const res = await closed.get('/api/v1/account/keys');
      expect([res.status, (res.body as { error?: string }).error]).toEqual([503, 'maintenance']);
      expect((await closed.get('/health/live')).status).toBe(200);
    } finally {
      await closed.app.close();
    }
    await grantAsOperator(d);
    vi.resetModules();
    const reopened = await startHarness({ database: d });
    try {
      expect((await reopened.get('/api/v1/account/keys')).status).toBe(401);
    } finally {
      await reopened.app.close();
    }

    // The restored database without EXECUTE on the reopening functions: nothing opens.
    await query(
      r.db.url,
      `REVOKE ALL ON ALL FUNCTIONS IN SCHEMA ruvee_control FROM "${r.db.runtime.name}"`,
    );
    vi.resetModules();
    const restored = await startHarness({ database: r.db });
    try {
      const res = await reopenWithKit(restored, account, r.code);
      expect(res.status).toBeGreaterThanOrEqual(401);
      expect(await guardOf(r.db)).toBe('reopening');
      expect((await codesOf(r.db)).filter((x) => x.consumed && !x.revoked)).toEqual([]);
      const [reopens] = await query<{ n: string }>(
        r.db.url,
        `SELECT count(*) AS n FROM sessions WHERE kind = 'reopen' AND revoked_at IS NULL`,
      );
      // The host's new code ended every earlier reopen session; this attempt made none.
      expect(reopens?.n).toBe('0');
      // Granted again by the operator, the same path works as the runtime role.
      await grantAsOperator(r.db);
      expect((await reopenWithKit(restored, account, r.code)).status).toBe(200);
    } finally {
      await restored.app.close();
    }
  });

  it('administrative steps refuse a superuser and the runtime role; backup and migration need theirs', async () => {
    const e = await newDatabase(false);
    for (const [url, message] of [
      [e.url, /not a superuser/],
      [e.runtime.url, /not the API runtime role/],
    ] as const) {
      const c = await connect(url);
      try {
        await expect(initInstallation(c, e.runtime.name)).rejects.toThrow(message);
        await expect(assertOperator(c, e.runtime.name)).rejects.toBeInstanceOf(RoleError);
      } finally {
        await c.end();
      }
    }
    const asOperator = await connect(e.operator.url);
    try {
      // The operator itself, or the schema owner, can never be named as the runtime role.
      await expect(initInstallation(asOperator, e.operator.name)).rejects.toThrow();
      await expect(initInstallation(asOperator, e.owner.name)).rejects.toThrow();
    } finally {
      await asOperator.end();
    }
    for (const target of [e.url, e.runtime.url])
      await expect(
        restoreBackup({
          manifestPath: backup.manifestPath,
          identityPath: key.identityPath,
          trustedDigest: backup.digest,
          targetDatabaseUrl: target,
          runtimeRole: e.runtime.name,
          tools,
          migrate,
          knownMigrations: MIGRATIONS,
        }),
      ).rejects.toMatchObject({ stage: 'prepare' });
    expect(await guardOf(e).catch(() => 'none')).toBe('none');
    // Migrations need the schema owner: the runtime role cannot create anything.
    expect(() => {
      migrate(e.runtime.url);
    }).toThrow(/migrate deploy failed/);
    // A backup needs the operator: the runtime role cannot read the migration table.
    const empty = mkdtempSync(join(tmpdir(), 'ruvee-review-f25-runtime-'));
    try {
      await expect(
        createBackup({
          databaseUrl: h.db.runtime.url,
          outDir: empty,
          tools,
          recipient: key.recipient,
          syntheticTestOnly: true,
          config,
        }),
      ).rejects.toThrow();
      expect(readdirSync(empty)).toEqual([]);
    } finally {
      rmSync(empty, { recursive: true, force: true });
    }
  });

  it('a migration cannot widen the runtime role silently: an extra grant is found, closes production and is undone', async () => {
    const f = await newDatabase(true);
    // A new table gets nothing, and grant-runtime refuses until it is classified.
    await query(f.owner.url, 'CREATE TABLE public.f25_future (id int)');
    expect(await privilegeProblems(view(f.url), f.runtime.name)).toEqual([]);
    await expect(grantAsOperator(f)).rejects.toThrow(
      /without a runtime classification.*: f25_future/,
    );
    await query(f.owner.url, 'DROP TABLE public.f25_future');
    // A migration (as the owner) that grants more than the list.
    await query(f.owner.url, `GRANT ALL ON public.accounts TO "${f.runtime.name}"`);
    await query(f.owner.url, `GRANT CREATE ON SCHEMA public TO "${f.runtime.name}"`);
    const problems = await privilegeProblems(view(f.url), f.runtime.name);
    expect(problems).toEqual(
      expect.arrayContaining([
        'DELETE on public.accounts',
        'TRUNCATE on public.accounts',
        'UPDATE on public.accounts',
        'CREATE on schema public',
      ]),
    );
    // In production the API serves nothing as such a role. (Production also wants the OPAQUE
    // setup file private: a 0600 copy of the test fixture.)
    const env = process.env.NODE_ENV;
    const setupFile = process.env.OPAQUE_SERVER_SETUP_FILE ?? '';
    const privateDir = mkdtempSync(join(tmpdir(), 'ruvee-review-f25-prod-'));
    const privateSetup = join(privateDir, 'opaque-server-setup');
    copyFileSync(setupFile, privateSetup);
    chmodSync(privateSetup, 0o600);
    process.env.NODE_ENV = 'production';
    process.env.OPAQUE_SERVER_SETUP_FILE = privateSetup;
    try {
      vi.resetModules();
      const prod = await startHarness({ database: f });
      try {
        const res = await prod.get('/api/v1/account/keys');
        expect([res.status, (res.body as { error?: string }).error]).toEqual([
          503,
          'server_unavailable',
        ]);
      } finally {
        await prod.app.close();
      }
      // grant-runtime puts the list back exactly; then it serves.
      await grantAsOperator(f);
      expect(await privilegeProblems(view(f.url), f.runtime.name)).toEqual([]);
      vi.resetModules();
      const fixed = await startHarness({ database: f });
      try {
        expect((await fixed.get('/api/v1/account/keys')).status).toBe(401);
      } finally {
        await fixed.app.close();
      }
    } finally {
      process.env.NODE_ENV = env;
      process.env.OPAQUE_SERVER_SETUP_FILE = setupFile;
      rmSync(privateDir, { recursive: true, force: true });
    }
  });

  it('in production, privileges not granted yet close nothing for good: before init it is maintenance, after init it serves', async () => {
    const d = await newDatabase(false);
    migrate(d.owner.url);
    const env = process.env.NODE_ENV;
    const setupFile = process.env.OPAQUE_SERVER_SETUP_FILE ?? '';
    const privateDir = mkdtempSync(join(tmpdir(), 'ruvee-review-f25-prod-'));
    const privateSetup = join(privateDir, 'opaque-server-setup');
    copyFileSync(setupFile, privateSetup);
    chmodSync(privateSetup, 0o600);
    process.env.NODE_ENV = 'production';
    process.env.OPAQUE_SERVER_SETUP_FILE = privateSetup;
    try {
      vi.resetModules();
      const prod = await startHarness({ database: d });
      try {
        const before = await prod.get('/api/v1/account/keys');
        expect([before.status, (before.body as { error?: string }).error]).toEqual([
          503,
          'maintenance',
        ]);
        // `init` while the API runs: the same process opens, with no restart.
        await initFresh(d);
        expect((await prod.get('/api/v1/account/keys')).status).toBe(401);
      } finally {
        await prod.app.close();
      }
    } finally {
      process.env.NODE_ENV = env;
      process.env.OPAQUE_SERVER_SETUP_FILE = setupFile;
      rmSync(privateDir, { recursive: true, force: true });
    }
  });

  it("the guide's move of a database set up before F-25 ends with exactly the list, and the API serves it", async () => {
    const g = await newDatabase(false);
    // The state before F-25: everything owned by the one admin role the API connected as (here
    // the test's superuser), PUBLIC with its default access, and `init` as it was.
    await query(g.url, `ALTER DATABASE "${g.name}" OWNER TO CURRENT_USER`);
    await query(g.url, 'ALTER SCHEMA public OWNER TO pg_database_owner');
    await query(g.url, `GRANT CONNECT, TEMPORARY ON DATABASE "${g.name}" TO PUBLIC`);
    await query(g.url, 'GRANT USAGE ON SCHEMA public TO PUBLIC');
    migrate(g.url);
    await query(
      g.url,
      `CREATE SCHEMA ruvee_control;
       REVOKE ALL ON SCHEMA ruvee_control FROM PUBLIC;
       CREATE TABLE ruvee_control.installation (id smallint PRIMARY KEY CHECK (id = 1),
         origin text NOT NULL CHECK (origin = 'fresh'),
         initialized_at timestamptz NOT NULL DEFAULT now());
       INSERT INTO ruvee_control.installation (id, origin) VALUES (1, 'fresh');
       INSERT INTO bootstrap_tokens (id, token_hash, expires_at)
         VALUES (gen_random_uuid(), sha256('f25'::bytea), now() + interval '1 minute')`,
    );
    const rows = async () =>
      (await query<{ n: string }>(g.url, 'SELECT count(*) AS n FROM bootstrap_tokens'))[0]?.n;
    expect(await rows()).toBe('1');
    // The guide: the cluster administrator's statements, then grant-runtime as the operator.
    const names = { owner: g.owner.name, operator: g.operator.name, runtime: g.runtime.name };
    for (const sql of existingDatabaseStatements(g.name, names)) await query(g.url, sql);
    await grantAsOperator(g);
    expect(await privilegeProblems(view(g.url), g.runtime.name)).toEqual([]);
    const strays = await query<{ name: string }>(
      g.url,
      `SELECT c.relname AS name FROM pg_class c
       JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles o ON o.oid = c.relowner
       WHERE n.nspname IN ('public', 'ruvee_control') AND c.relkind = 'r'
         AND o.rolname NOT IN ($1, $2)`,
      [g.owner.name, g.operator.name],
    );
    expect(strays).toEqual([]);
    expect(await rows()).toBe('1');
    // Served as the runtime role, the installation is open and registration works.
    vi.resetModules();
    const served = await startHarness({ database: g });
    try {
      expect((await served.get('/api/v1/account/keys')).status).toBe(401);
      await registerAccount(served, await syntheticAccount('synthetic-f25-moved'));
    } finally {
      await served.app.close();
    }
  }, 60_000);
});
