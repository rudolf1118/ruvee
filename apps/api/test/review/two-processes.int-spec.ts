import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { createServer } from 'node:net';
import pg from 'pg';
import request from 'supertest';
import { loginStartResponseSchema } from '@ruvee/contracts';
import { randomToken, sha256 } from '../../src/common/secrets.js';
import { createControlSchema, grantGateRead } from '../../src/admin/restore-control.js';
import { registerAccount, WRITE_HEADERS, type Harness } from '../support/api-harness.js';
import { signLogin } from '../support/device-proof.js';
import { finishLogin, startLogin, syntheticAccount } from '../support/synthetic-client.js';
import {
  createTempDatabase,
  initFresh,
  migrate,
  query,
  type TempDatabase,
} from '../support/temp-database.js';

/**
 * Follow-up review §18.5: two API processes, each `node dist/main.js` launched on its own, serve
 * one database at once. That is the accidental overlap §17.2 option B is for; the instance lock
 * would normally stop the second, so both run with RUVEE_TEST_ONLY_SKIP_INSTANCE_LOCK, which
 * env.ts refuses outside NODE_ENV=test. Both connect as the runtime role, as deployed (F-25).
 * Needs `pnpm --filter @ruvee/api build` first (turbo's test:integration depends on it).
 * Synthetic data only.
 */

const API_ROOT = new URL('../../', import.meta.url).pathname;
const SETUP_FILE = 'test/fixtures/opaque-server-setup.test-only';
const ORIGIN = 'http://127.0.0.1:3100';

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => {
        resolve(typeof address === 'object' && address ? address.port : 0);
      });
    });
  });
}

class ApiProcess {
  private child: ChildProcess | undefined;
  readonly output: string[] = [];

  private constructor(
    readonly name: string,
    readonly port: number,
    private readonly databaseUrl: string,
  ) {}

  static async start(name: string, databaseUrl: string): Promise<ApiProcess> {
    const api = new ApiProcess(name, await freePort(), databaseUrl);
    await api.launch();
    return api;
  }

  get pid(): number | undefined {
    return this.child?.pid;
  }

  async launch(): Promise<void> {
    const child = spawn(process.execPath, ['dist/main.js'], {
      cwd: API_ROOT,
      env: {
        PATH: process.env.PATH ?? '',
        NODE_ENV: 'test',
        API_HOST: '127.0.0.1',
        API_PORT: String(this.port),
        DATABASE_URL: this.databaseUrl,
        OPAQUE_SERVER_SETUP_FILE: SETUP_FILE,
        PUBLIC_ORIGIN: ORIGIN,
        LOG_LEVEL: 'warn',
        RUVEE_TEST_ONLY_SKIP_INSTANCE_LOCK: '1',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    this.child = child;
    const keep = (chunk: Buffer) => this.output.push(chunk.toString('utf8'));
    child.stdout.on('data', keep);
    child.stderr.on('data', keep);
    await this.ready();
  }

  /** Waits for /health/ready; a process that exits or never answers fails the test. */
  async ready(timeoutMs = 30_000): Promise<void> {
    const until = Date.now() + timeoutMs;
    while (Date.now() < until) {
      if (this.child?.exitCode !== null && this.child?.exitCode !== undefined)
        throw new Error(`${this.name} exited:\n${this.output.join('')}`);
      const res = await this.http()
        .get('/health/ready')
        .catch(() => undefined);
      if (res?.status === 200) return;
      await new Promise((r) => setTimeout(r, 100));
    }
    throw new Error(`${this.name} not ready:\n${this.output.join('')}`);
  }

  async stop(): Promise<void> {
    const child = this.child;
    this.child = undefined;
    if (child?.exitCode !== null) return;
    const exited = new Promise<boolean>((resolve) =>
      child.once('exit', () => {
        resolve(true);
      }),
    );
    child.kill('SIGTERM');
    const done = await Promise.race([
      exited,
      new Promise<boolean>((r) =>
        setTimeout(() => {
          r(false);
        }, 10_000),
      ),
    ]);
    if (!done) child.kill('SIGKILL');
  }

  http() {
    return request(`http://127.0.0.1:${String(this.port)}`);
  }

  post(path: string, body: unknown, cookie?: string) {
    const req = this.http()
      .post(path)
      .set(WRITE_HEADERS)
      .send(body as object);
    return cookie ? req.set('Cookie', cookie) : req;
  }

  get(path: string, cookie?: string) {
    const req = this.http().get(path);
    return cookie ? req.set('Cookie', cookie) : req;
  }
}

describe('REVIEW §18.5: two independently launched API processes on one database', () => {
  let db: TempDatabase;
  let a: ApiProcess;
  let b: ApiProcess;
  let account: Awaited<ReturnType<typeof syntheticAccount>>;

  const clearWindows = () => query(db.url, 'DELETE FROM rate_windows');
  const sessions = async () =>
    (await query<{ n: number }>(db.url, 'SELECT count(*)::int AS n FROM sessions'))[0]?.n ?? 0;

  async function start(p: ApiProcess) {
    const client = startLogin();
    const res = await p
      .post('/api/v1/auth/login/start', {
        username: account.username,
        startLoginRequest: client.startLoginRequest,
        platform: 'web',
        deviceId: account.deviceId,
      })
      .expect(200);
    const started = loginStartResponseSchema.parse(res.body);
    const finished = finishLogin(client.clientLoginState, started.loginResponse);
    if (!finished) throw new Error('OPAQUE refused the password');
    return {
      loginId: started.loginId,
      finishLoginRequest: finished.finishLoginRequest,
      deviceProof: signLogin(account, started, finished.finishLoginRequest),
    };
  }

  const loginStart = (p: ApiProcess) =>
    p.post('/api/v1/auth/login/start', {
      username: account.username,
      startLoginRequest: startLogin().startLoginRequest,
      platform: 'web',
      deviceId: account.deviceId,
    });

  beforeAll(async () => {
    db = await createTempDatabase();
    migrate(db.owner.url);
    await initFresh(db);
    [a, b] = await Promise.all([
      ApiProcess.start('A', db.runtime.url),
      ApiProcess.start('B', db.runtime.url),
    ]);
    account = await syntheticAccount('synthetic-two-processes');
    const remote = {
      post: (path: string, body: unknown) => a.post(path, body),
      async bootstrapToken() {
        const token = randomToken();
        await query(
          db.url,
          `INSERT INTO bootstrap_tokens (id, token_hash, expires_at) VALUES ($1, $2, now() + interval '60 minutes')`,
          [randomUUID(), Buffer.from(sha256(Buffer.from(token, 'base64url')))],
        );
        return token;
      },
    };
    await registerAccount(remote as unknown as Harness, account);
  }, 120_000);

  afterAll(async () => {
    for (const p of [a as ApiProcess | undefined, b as ApiProcess | undefined]) await p?.stop();
    await (db as TempDatabase | undefined)?.drop();
  });

  it('runs as two OS processes, each with its own pid and port', () => {
    expect(a.pid).toBeDefined();
    expect(b.pid).toBeDefined();
    expect(a.pid).not.toBe(b.pid);
    expect(a.pid).not.toBe(process.pid);
    expect(a.port).not.toBe(b.port);
  });

  it('the per-address window is one budget across both processes, also under concurrency', async () => {
    await clearWindows();
    const statuses = (
      await Promise.all(Array.from({ length: 30 }, (_, i) => loginStart(i % 2 === 0 ? a : b)))
    ).map((r) => r.status);
    expect(statuses.filter((s) => s === 200)).toHaveLength(20);
    expect(statuses.filter((s) => s === 429)).toHaveLength(10);
  }, 60_000);

  it('the per-session window is one budget across both processes', async () => {
    await clearWindows();
    const login = await start(a);
    const done = await b.post('/api/v1/auth/login/finish', login).expect(200);
    const header = done.headers['set-cookie'] as unknown as string[];
    const cookie = header.find((c) => c.startsWith('__Host-ruvee_session='))?.split(';')[0] ?? '';
    const statuses: number[] = [];
    for (let batch = 0; batch < 8; batch++)
      statuses.push(
        ...(
          await Promise.all(
            Array.from({ length: 40 }, (_, i) =>
              (i % 2 === 0 ? a : b).get('/api/v1/account', cookie),
            ),
          )
        ).map((r) => r.status),
      );
    expect(statuses.filter((s) => s === 200)).toHaveLength(300);
    expect(statuses.filter((s) => s === 429)).toHaveLength(20);
  }, 60_000);

  it('a login started on A finishes on B, once; a replay fails on both', async () => {
    await clearWindows();
    const login = await start(a);
    const done = await b.post('/api/v1/auth/login/finish', login).expect(200);
    expect(done.body).toMatchObject({ proven: true });
    for (const p of [a, b]) {
      const again = await p.post('/api/v1/auth/login/finish', login);
      expect(again.status).toBe(401);
      expect(again.body).toMatchObject({ error: 'login_failed' });
    }
  }, 30_000);

  it('concurrent finishes across both processes create at most one session', async () => {
    for (let round = 0; round < 3; round++) {
      await clearWindows();
      const login = await start(round % 2 === 0 ? a : b);
      const before = await sessions();
      const results = await Promise.all(
        Array.from({ length: 8 }, (_, i) =>
          (i % 2 === 0 ? a : b).post('/api/v1/auth/login/finish', login),
        ),
      );
      expect(results.map((r) => r.status).sort()).toEqual([200, 401, 401, 401, 401, 401, 401, 401]);
      expect(await sessions()).toBe(before + 1);
    }
  }, 60_000);

  it('restarting a process does not reset the windows it counted', async () => {
    await clearWindows();
    for (let i = 0; i < 20; i++) expect((await loginStart(i % 2 === 0 ? a : b)).status).toBe(200);
    const pidBefore = a.pid;
    await a.stop();
    await a.launch();
    expect(a.pid).not.toBe(pidBefore);
    expect((await loginStart(a)).status).toBe(429);
    expect((await loginStart(b)).status).toBe(429);
  }, 60_000);

  it('a database failure refuses on both processes; nothing is admitted without the windows', async () => {
    await clearWindows();
    const login = await start(a);
    const done = await b.post('/api/v1/auth/login/finish', login).expect(200);
    const cookie =
      (done.headers['set-cookie'] as unknown as string[])
        .find((c) => c.startsWith('__Host-ruvee_session='))
        ?.split(';')[0] ?? '';
    const runtime = db.runtime.name;
    const pending = async () =>
      (await query<{ n: number }>(db.url, 'SELECT count(*)::int AS n FROM login_states'))[0]?.n;
    const pendingBefore = await pending();
    await query(db.url, `REVOKE ALL ON rate_windows FROM "${runtime}"`);
    try {
      for (const p of [a, b]) {
        const read = await p.get('/api/v1/account', cookie);
        expect(read.status).toBe(500);
        expect(read.body).toMatchObject({ error: 'internal_error' });
        expect((await loginStart(p)).status).toBe(500);
      }
      expect(await pending()).toBe(pendingBefore);
    } finally {
      await query(db.url, `GRANT SELECT, INSERT, UPDATE, DELETE ON rate_windows TO "${runtime}"`);
    }
    expect((await a.get('/api/v1/account', cookie)).status).toBe(200);
  }, 30_000);

  async function asAdmin<T>(work: (c: pg.Client) => Promise<T>): Promise<T> {
    const c = new pg.Client({ connectionString: db.url });
    await c.connect();
    try {
      return await work(c);
    } finally {
      await c.end();
    }
  }

  describe('maintenance and reopening, enforced by both processes', () => {
    const setGuard = (state: string) =>
      query(db.url, `UPDATE ruvee_control.restore_guard SET state = $1 WHERE id = 1`, [state]);

    beforeAll(async () => {
      // A guard as a restore's PREPARE writes it (server-restore.ts); it takes precedence over
      // the installation row, so this database now answers as a restore in progress.
      await asAdmin(async (c) => {
        await c.query(`CREATE TABLE ruvee_control.restore_guard (
          id smallint PRIMARY KEY CHECK (id = 1),
          state text NOT NULL CHECK (state IN ('restoring', 'review', 'reopening', 'open')))`);
        await c.query(`INSERT INTO ruvee_control.restore_guard (id, state) VALUES (1, 'open')`);
        await grantGateRead(c, db.runtime.name);
      });
    });

    afterAll(async () => {
      await query(db.url, 'DROP TABLE ruvee_control.restore_guard');
    });

    it('open → review: both refuse at once, including a process that already served open', async () => {
      await clearWindows();
      for (const p of [a, b]) expect((await loginStart(p)).status).toBe(200);
      await setGuard('review');
      for (const p of [a, b]) {
        const res = await loginStart(p);
        expect(res.status).toBe(503);
        expect(res.body).toMatchObject({ error: 'maintenance' });
      }
    });

    it('reopening: both serve only the reopening routes', async () => {
      await setGuard('reopening');
      for (const p of [a, b]) {
        const ordinary = await loginStart(p);
        expect(ordinary.status).toBe(503);
        expect(ordinary.body).toMatchObject({ error: 'reopening' });
        // Past the gate: the body is refused by validation, which runs after it.
        const reopen = await p.post('/api/v1/reopen/login/start', {});
        expect(reopen.status).toBe(400);
      }
    });

    it('reopening → open: both serve again', async () => {
      await clearWindows();
      await setGuard('open');
      for (const p of [a, b]) expect((await loginStart(p)).status).toBe(200);
    });
  });

  // Last: it replaces the database the other tests use.
  it('a same-named database replaced by a restore in review is refused by a process that saw it open', async () => {
    await clearWindows();
    expect((await loginStart(a)).status).toBe(200);
    // The operator drops the served database and creates a restore target under the same name
    // (not the documented procedure, which uses a new name; possible all the same). A's pool
    // reconnects to the new database by name.
    const admin = new pg.Client({ connectionString: db.url.replace(`/${db.name}`, '/postgres') });
    await admin.connect();
    try {
      await admin.query(`DROP DATABASE "${db.name}" WITH (FORCE)`);
      await admin.query(`CREATE DATABASE "${db.name}" OWNER "${db.operator.name}"`);
    } finally {
      await admin.end();
    }
    const { applyRuntimeGrants, databaseSetupStatements } =
      await import('../../src/admin/database-roles.js');
    await asAdmin(async (c) => {
      for (const sql of databaseSetupStatements(db.name, {
        owner: db.owner.name,
        operator: db.operator.name,
        runtime: db.runtime.name,
      }))
        await c.query(sql);
      await createControlSchema(c);
      await c.query(`CREATE TABLE ruvee_control.restore_guard (
        id smallint PRIMARY KEY CHECK (id = 1),
        state text NOT NULL CHECK (state IN ('restoring', 'review', 'reopening', 'open')))`);
      await c.query(`INSERT INTO ruvee_control.restore_guard (id, state) VALUES (1, 'restoring')`);
      await grantGateRead(c, db.runtime.name);
    });
    // As after LOAD, MIGRATE and APPLY POLICY: the schema, the runtime role's full list, and the
    // guard in `review`. A process that served the old database must not serve this one.
    migrate(db.owner.url);
    await asAdmin(async (c) => {
      await applyRuntimeGrants(c, db.runtime.name);
      await c.query(`UPDATE ruvee_control.restore_guard SET state = 'review' WHERE id = 1`);
    });
    // The first statement on a connection the drop terminated may fail; health says when the
    // pool is back. Readiness is not gated by maintenance.
    await a.ready();
    await b.ready();
    for (const p of [a, b]) {
      const res = await loginStart(p);
      expect(res.status).toBe(503);
      expect(res.body).toMatchObject({ error: 'maintenance' });
    }
  }, 60_000);
});
