import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ConfigService } from '@nestjs/config';
import * as opaque from '@serenity-kit/opaque';
import pg from 'pg';
import { loginStartResponseSchema } from '@ruvee/contracts';
import type { Env } from '../../src/config/env.js';
import {
  LOGIN_STATE_TTL_MS,
  LoginStateStore,
  MAX_PENDING,
} from '../../src/auth/login-state.store.js';
import { OpaqueServerService } from '../../src/auth/opaque-server.service.js';
import {
  loginSubject,
  ThrottleService,
  WINDOWS_PER_SCOPE,
} from '../../src/auth/throttle.service.js';
import { DATABASE_POOL_MAX, PrismaService } from '../../src/database/prisma.service.js';
import { registerAccount, startHarness, type Harness } from '../support/api-harness.js';
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
 * Follow-up review §17.2 option B: the per-address, wrong-code and per-session windows and the
 * pending logins are shared in the database, so two API processes that overlap by accident (the
 * instance lock lost, a stalled event loop) still share one budget and one single-use login
 * state. Each "process" here is its own Prisma client and services in this Node.js process,
 * connected as the runtime role exactly as deployed (F-25), never as an administrator; two
 * separate OS processes are in two-processes.int-spec.ts. Synthetic data only.
 */

const sha256 = (data: string | Uint8Array) => createHash('sha256').update(data).digest();

function settledCounts(results: PromiseSettledResult<unknown>[]) {
  const refused = results.filter(
    (r) => r.status === 'rejected' && (r.reason as { code?: string }).code === 'rate_limited',
  ).length;
  const other = results.filter(
    (r) => r.status === 'rejected' && (r.reason as { code?: string }).code !== 'rate_limited',
  );
  if (other.length > 0) throw (other[0] as PromiseRejectedResult).reason;
  return { admitted: results.filter((r) => r.status === 'fulfilled').length, refused };
}

function config(values: Partial<Record<keyof Env, unknown>>): ConfigService<Env, true> {
  return { get: (key: keyof Env) => values[key] } as unknown as ConfigService<Env, true>;
}

interface Process {
  readonly prisma: PrismaService;
  readonly throttle: ThrottleService;
  readonly logins: LoginStateStore;
}

async function apiProcess(url: string, setupFile: string): Promise<Process> {
  const prisma = new PrismaService(config({ DATABASE_URL: url, READINESS_DB_TIMEOUT_MS: 5_000 }));
  const server = new OpaqueServerService(
    config({ OPAQUE_SERVER_SETUP_FILE: setupFile, NODE_ENV: 'test' }),
  );
  await server.onModuleInit();
  const logins = new LoginStateStore(prisma, server);
  await logins.onModuleInit();
  return { prisma, throttle: new ThrottleService(prisma), logins };
}

const SETUP_FILE = 'test/fixtures/opaque-server-setup.test-only';

describe('REVIEW §17.2 option B: limits and login states shared across API processes', () => {
  let db: TempDatabase;
  let a: Process;
  let b: Process;
  let accountId: string;

  beforeAll(async () => {
    db = await createTempDatabase();
    migrate(db.owner.url);
    await initFresh(db);
    a = await apiProcess(db.runtime.url, SETUP_FILE);
    b = await apiProcess(db.runtime.url, SETUP_FILE);
    accountId = '11111111-1111-4111-8111-111111111111';
    await query(
      db.url,
      `INSERT INTO accounts (id, username_normalized) VALUES ($1, 'synthetic-17-2')`,
      [accountId],
    );
  }, 60_000);

  afterAll(async () => {
    for (const p of [a, b] as (Process | undefined)[]) await p?.prisma.$disconnect();
    await (db as TempDatabase | undefined)?.drop();
  });

  beforeEach(async () => {
    await query(db.url, 'DELETE FROM rate_windows');
    await query(db.url, 'DELETE FROM login_states');
  });

  describe('request windows', () => {
    it('per address: one budget of 20 across processes, reserved atomically, /64 for IPv6', async () => {
      const at = new Date('2026-10-29T12:00:00.000Z');
      const results = await Promise.allSettled(
        Array.from({ length: 60 }, (_, i) =>
          (i % 2 === 0 ? a : b).throttle.assertIpAllowed(
            `2001:db8:1:2::${(i + 1).toString(16)}`,
            at,
          ),
        ),
      );
      expect(settledCounts(results)).toEqual({ admitted: 20, refused: 40 });
      // Another /64 and an IPv4 address have their own windows.
      await a.throttle.assertIpAllowed('2001:db8:1:3::1', at);
      await b.throttle.assertIpAllowed('198.51.100.7', at);
      // A refusal carries the time left in the window.
      await expect(b.throttle.assertIpAllowed('2001:db8:1:2::ffff', at)).rejects.toMatchObject({
        code: 'rate_limited',
      });
      // The window ends after a minute, for both processes.
      await a.throttle.assertIpAllowed('2001:db8:1:2::1', new Date(at.getTime() + 60_000));
    });

    it('per session: one budget of 300 across processes', async () => {
      const at = new Date('2026-10-29T12:00:00.000Z');
      const session = '22222222-2222-4222-8222-222222222222';
      const results = await Promise.allSettled(
        Array.from({ length: 320 }, (_, i) =>
          (i % 2 === 0 ? a : b).throttle.assertSessionAllowed(session, at),
        ),
      );
      expect(settledCounts(results)).toEqual({ admitted: 300, refused: 20 });
      await a.throttle.assertSessionAllowed('33333333-3333-4333-8333-333333333333', at);
    });

    it('wrong reopening codes: 10 per address across processes; the usable code gives its guess back', async () => {
      const at = new Date('2026-10-29T12:00:00.000Z');
      const results = await Promise.allSettled(
        Array.from({ length: 15 }, (_, i) =>
          (i % 2 === 0 ? a : b).throttle.reserveReopenCodeGuess('203.0.113.9', at),
        ),
      );
      expect(settledCounts(results)).toEqual({ admitted: 10, refused: 5 });
      // Another address is unaffected; its usable code gives its reservation back each time,
      // so a right code never uses up the address's guesses.
      for (let i = 0; i < 25; i++) {
        const guess = await (i % 2 === 0 ? a : b).throttle.reserveReopenCodeGuess(
          '203.0.113.10',
          at,
        );
        await (i % 2 === 0 ? b : a).throttle.releaseReopenCodeGuess(guess);
      }
      const [row] = await query<{ hits: number }>(
        db.url,
        `SELECT hits FROM rate_windows WHERE scope = 'wrong_code' AND key_hash = $1`,
        [sha256('wrong_code\u0000203.0.113.10')],
      );
      expect(row?.hits).toBe(0);
      // A release from an earlier window never takes from the next one.
      const old = await a.throttle.reserveReopenCodeGuess('203.0.113.11', at);
      const later = new Date(at.getTime() + 15 * 60_000);
      await a.throttle.reserveReopenCodeGuess('203.0.113.11', later);
      await a.throttle.releaseReopenCodeGuess(old);
      const [after] = await query<{ hits: number }>(
        db.url,
        `SELECT hits FROM rate_windows WHERE scope = 'wrong_code' AND key_hash = $1`,
        [sha256('wrong_code\u0000203.0.113.11')],
      );
      expect(after?.hits).toBe(1);
    });

    it('at the bound, live windows are kept and new keys share one overflow window; expired ones make room', async () => {
      const at = new Date('2026-10-29T12:00:00.000Z');
      // One address used up its 20 before the table fills.
      for (let i = 0; i < 20; i++) await a.throttle.assertIpAllowed('198.51.100.20', at);
      await expect(a.throttle.assertIpAllowed('198.51.100.20', at)).rejects.toMatchObject({
        code: 'rate_limited',
      });
      // A flood of other addresses fills the table with live windows.
      await query(
        db.url,
        `INSERT INTO rate_windows (scope, key_hash, window_start, hits)
         SELECT 'address', sha256(('flood-' || i)::bytea), $1, 1
         FROM generate_series(1, $2::int - 1) AS i`,
        [at, WINDOWS_PER_SCOPE],
      );
      const count = async () =>
        (
          await query<{ n: number }>(
            db.url,
            `SELECT count(*)::int AS n FROM rate_windows WHERE scope = 'address'`,
          )
        )[0]?.n;
      expect(await count()).toBe(WINDOWS_PER_SCOPE);
      // The refused address stays refused (follow-up review F-8)...
      await expect(b.throttle.assertIpAllowed('198.51.100.20', at)).rejects.toMatchObject({
        code: 'rate_limited',
      });
      // ...and new addresses share one window of 20, across both processes.
      const results = await Promise.allSettled(
        Array.from({ length: 30 }, (_, i) =>
          (i % 2 === 0 ? a : b).throttle.assertIpAllowed(`192.0.2.${String(i + 1)}`, at),
        ),
      );
      expect(settledCounts(results)).toEqual({ admitted: 20, refused: 10 });
      expect(await count()).toBe(WINDOWS_PER_SCOPE + 1);
      // Once the flood's windows have ended they are removed, and a new address gets its own.
      const later = new Date(at.getTime() + 60_000);
      await a.throttle.assertIpAllowed('192.0.2.200', later);
      expect(await count()).toBeLessThan(WINDOWS_PER_SCOPE + 1);
      const [own] = await query<{ hits: number }>(
        db.url,
        `SELECT hits FROM rate_windows WHERE scope = 'address' AND key_hash = $1`,
        [sha256('address\u0000192.0.2.200')],
      );
      expect(own?.hits).toBe(1);
    });

    const liveWindows = async (at: Date) =>
      (
        await query<{ n: number }>(
          db.url,
          `SELECT count(*)::int AS n FROM rate_windows
           WHERE scope = 'address' AND window_start > $1::timestamptz - interval '60 seconds'`,
          [at],
        )
      )[0]?.n ?? 0;
    const fillWindows = (at: Date, n: number, prefix = 'flood-') =>
      query(
        db.url,
        `INSERT INTO rate_windows (scope, key_hash, window_start, hits)
         SELECT 'address', sha256(($3 || i)::bytea), $1, 1 FROM generate_series(1, $2::int) AS i`,
        [at, n, prefix],
      );

    it('racing new keys pass the bound by less than the statements that can run at once (two pools)', async () => {
      const at = new Date('2026-10-29T12:00:00.000Z');
      await fillWindows(at, WINDOWS_PER_SCOPE - 1);
      const results = await Promise.allSettled(
        Array.from({ length: 80 }, (_, i) =>
          (i % 2 === 0 ? a : b).throttle.assertIpAllowed(`203.0.113.${String(i + 1)}`, at),
        ),
      );
      const { admitted } = settledCounts(results);
      const [own] = await query<{ n: number }>(
        db.url,
        `SELECT count(*)::int AS n FROM rate_windows
         WHERE scope = 'address' AND key_hash = ANY($1::bytea[])`,
        [Array.from({ length: 80 }, (_, i) => sha256(`address\u0000203.0.113.${String(i + 1)}`))],
      );
      const [overflow] = await query<{ hits: number }>(
        db.url,
        `SELECT hits FROM rate_windows WHERE scope = 'address' AND key_hash = $1`,
        [sha256('address\u0000\u0000overflow')],
      );
      const ownWindows = own?.n ?? 0;
      // At least the one free place was taken; at most one per statement running at once in
      // either process's pool (DATABASE_POOL_MAX each), so the bound moves by less than 2 × 10.
      expect(ownWindows).toBeGreaterThanOrEqual(1);
      expect(ownWindows).toBeLessThanOrEqual(2 * DATABASE_POOL_MAX);
      expect(await liveWindows(at)).toBeLessThanOrEqual(
        WINDOWS_PER_SCOPE - 1 + 2 * DATABASE_POOL_MAX + 1,
      );
      // Every other key went to the overflow window, which admitted at most its 20.
      expect(overflow?.hits).toBe(21);
      expect(admitted).toBe(ownWindows + 20);
    });

    it('expiry boundaries: a window counts until its last millisecond and ends exactly at its length', async () => {
      const at = new Date('2026-10-29T12:00:00.000Z');
      for (let i = 0; i < 20; i++) await a.throttle.assertIpAllowed('198.51.100.40', at);
      const last = new Date(at.getTime() + 60_000 - 1);
      await expect(b.throttle.assertIpAllowed('198.51.100.40', last)).rejects.toMatchObject({
        code: 'rate_limited',
      });
      const end = new Date(at.getTime() + 60_000);
      await b.throttle.assertIpAllowed('198.51.100.40', end);
      const [row] = await query<{ hits: number; window_start: Date }>(
        db.url,
        `SELECT hits, window_start FROM rate_windows WHERE scope = 'address' AND key_hash = $1`,
        [sha256('address\u0000198.51.100.40')],
      );
      expect(row).toEqual({ hits: 1, window_start: end });
      // Pruning uses the same boundary: a window in its last millisecond is live and kept.
      await query(db.url, `DELETE FROM rate_windows`);
      await fillWindows(at, 3, 'edge-');
      await a.throttle.assertIpAllowed('198.51.100.41', last);
      expect(await liveWindows(last)).toBe(4);
      await a.throttle.assertIpAllowed('198.51.100.42', end);
      const [left] = await query<{ n: number }>(
        db.url,
        `SELECT count(*)::int AS n FROM rate_windows WHERE scope = 'address'`,
      );
      expect(left?.n).toBe(2);
    });

    it('pruning racing with live use never removes a live window or resets its count', async () => {
      const at = new Date('2026-10-29T12:00:00.000Z');
      const later = new Date(at.getTime() + 60_000);
      // 400 ended windows, keyed as the limiter keys an address (SHA-256 of scope, NUL, key).
      // Any new key may prune them.
      await query(
        db.url,
        `INSERT INTO rate_windows (scope, key_hash, window_start, hits)
         SELECT 'address', sha256(convert_to('address', 'UTF8') || '\\x00'::bytea || convert_to('old-' || i, 'UTF8')), $1, 20
         FROM generate_series(1, 400) AS i`,
        [at],
      );
      // 40 of those addresses come back at once and use up their new window, while 120 new
      // addresses (each pruning up to 500 ended windows) run at the same time on both processes.
      const revived = Array.from({ length: 40 }, (_, i) => `old-${String(i + 1)}`);
      const work: Promise<unknown>[] = [];
      for (let round = 0; round < 20; round++)
        for (const [i, address] of revived.entries())
          work.push((i % 2 === 0 ? a : b).throttle.assertIpAllowed(address, later));
      for (let i = 0; i < 120; i++)
        work.push(
          (i % 2 === 0 ? b : a).throttle.assertIpAllowed(`198.18.0.${String(i + 1)}`, later),
        );
      settledCounts(await Promise.allSettled(work));
      // Each revived address has used exactly its 20: the 21st is refused on either process.
      for (const [i, address] of revived.entries())
        await expect(
          (i % 2 === 0 ? b : a).throttle.assertIpAllowed(address, later),
        ).rejects.toMatchObject({ code: 'rate_limited' });
      const rows = await query<{ hits: number }>(
        db.url,
        `SELECT hits FROM rate_windows WHERE scope = 'address' AND key_hash = ANY($1::bytea[])`,
        [revived.map((r) => sha256(`address\u0000${r}`))],
      );
      expect(rows).toHaveLength(40);
      expect(rows.every((r) => r.hits === 21)).toBe(true);
      // The pruning did run during the race: every ended window that did not come back is gone.
      const [ended] = await query<{ n: number }>(
        db.url,
        `SELECT count(*)::int AS n FROM rate_windows WHERE scope = 'address' AND window_start = $1`,
        [at],
      );
      expect(ended?.n).toBe(0);
    }, 60_000);

    it('a prune that meets a window renewed under it re-checks the expiry and keeps it (deterministic)', async () => {
      const at = new Date('2026-10-29T12:00:00.000Z');
      const later = new Date(at.getTime() + 60_000);
      const key = sha256('address\u0000198.51.100.50');
      await query(
        db.url,
        `INSERT INTO rate_windows (scope, key_hash, window_start, hits) VALUES ('address', $1, $2, 20)`,
        [key, at],
      );
      // The renewal (what a request for that address does once its window ended) holds the row.
      const renewal = new pg.Client({ connectionString: db.url });
      await renewal.connect();
      try {
        await renewal.query('BEGIN');
        await renewal.query(
          `UPDATE rate_windows SET window_start = $2, hits = 20 WHERE scope = 'address' AND key_hash = $1`,
          [key, later],
        );
        // A new address prunes: its snapshot still sees the old, ended window, so it waits on it.
        const pruning = a.throttle.assertIpAllowed('198.51.100.51', later);
        for (let i = 0; i < 100; i++) {
          const [waiting] = await query<{ n: number }>(
            db.url,
            `SELECT count(*)::int AS n FROM pg_stat_activity
             WHERE datname = current_database() AND wait_event_type = 'Lock' AND query LIKE '%DELETE FROM rate_windows%'`,
          );
          if ((waiting?.n ?? 0) > 0) break;
          await new Promise((r) => setTimeout(r, 20));
        }
        await renewal.query('COMMIT');
        await pruning;
      } finally {
        await renewal.end();
      }
      const [row] = await query<{ hits: number; window_start: Date }>(
        db.url,
        `SELECT hits, window_start FROM rate_windows WHERE scope = 'address' AND key_hash = $1`,
        [key],
      );
      expect(row).toEqual({ hits: 20, window_start: later });
      await expect(b.throttle.assertIpAllowed('198.51.100.50', later)).rejects.toMatchObject({
        code: 'rate_limited',
      });
    });

    it('fails closed: a database error refuses the request, it never admits it', async () => {
      await query(db.url, `REVOKE UPDATE ON rate_windows FROM "${db.runtime.name}"`);
      try {
        await expect(a.throttle.assertIpAllowed('198.51.100.30')).rejects.toThrow(
          /permission denied/,
        );
        await expect(
          a.throttle.assertSessionAllowed('44444444-4444-4444-8444-444444444444'),
        ).rejects.toThrow(/permission denied/);
      } finally {
        await query(db.url, `GRANT UPDATE ON rate_windows TO "${db.runtime.name}"`);
      }
      const unreachable = new PrismaService(
        config({
          DATABASE_URL: 'postgresql://nobody:nothing@127.0.0.1:9/none',
          READINESS_DB_TIMEOUT_MS: 1_000,
        }),
      );
      try {
        await expect(
          new ThrottleService(unreachable).assertIpAllowed('198.51.100.31'),
        ).rejects.toThrow();
      } finally {
        await unreachable.$disconnect();
      }
    });
  });

  describe('pending login states', () => {
    const base = {
      loginSubject: loginSubject('synthetic-17-2'),
      deviceId: '55555555-5555-4555-8555-555555555555',
      platform: 'web' as const,
    };

    it('a state put by one process is consumed once by the other, with its binding intact', async () => {
      const put = await a.logins.put({ ...base, serverLoginState: 'state-a', accountId });
      const got = await b.logins.consume(put.loginId);
      expect(got).toMatchObject({
        serverLoginState: 'state-a',
        accountId,
        deviceId: base.deviceId,
        platform: 'web',
      });
      expect(Buffer.from(got?.challenge ?? [])).toEqual(Buffer.from(put.challenge));
      expect(Buffer.from(got?.loginSubject ?? [])).toEqual(Buffer.from(base.loginSubject));
      expect(got?.sessionId).toBeUndefined();
      expect(await a.logins.consume(put.loginId)).toBeUndefined();
      expect(await b.logins.consume(put.loginId)).toBeUndefined();
    });

    it('concurrent finishes on both processes: exactly one gets the state', async () => {
      for (let round = 0; round < 5; round++) {
        const put = await a.logins.put({
          ...base,
          serverLoginState: `race-${String(round)}`,
          accountId,
        });
        const got = await Promise.all(
          Array.from({ length: 10 }, (_, i) => (i % 2 === 0 ? a : b).logins.consume(put.loginId)),
        );
        expect(got.filter((g) => g !== undefined)).toHaveLength(1);
      }
    });

    it('opens only with the binding it was sealed under, under the same setup, before expiry', async () => {
      // A row whose device was changed no longer opens; the row is gone either way.
      const moved = await a.logins.put({ ...base, serverLoginState: 'moved', accountId });
      await query(db.url, `UPDATE login_states SET device_id = $1`, [
        '66666666-6666-4666-8666-666666666666',
      ]);
      expect(await b.logins.consume(moved.loginId)).toBeUndefined();
      // A sealed state copied onto another row (another login id) does not open there.
      const one = await a.logins.put({ ...base, serverLoginState: 'one', accountId });
      const two = await a.logins.put({ ...base, serverLoginState: 'two', accountId });
      await query(
        db.url,
        `UPDATE login_states SET sealed = (SELECT sealed FROM login_states WHERE id_hash = $1)
         WHERE id_hash = $2`,
        [
          sha256(Buffer.from(one.loginId, 'base64url')),
          sha256(Buffer.from(two.loginId, 'base64url')),
        ],
      );
      expect(await b.logins.consume(two.loginId)).toBeUndefined();
      expect(await b.logins.consume(one.loginId)).toMatchObject({ serverLoginState: 'one' });
      // A process with another OPAQUE setup cannot open it (and could not finish OPAQUE anyway).
      const dir = mkdtempSync(join(tmpdir(), 'ruvee-17-2-'));
      try {
        await opaque.ready;
        const other = join(dir, 'setup');
        writeFileSync(other, opaque.server.createSetup(), { mode: 0o600 });
        const c = await apiProcess(db.runtime.url, other);
        try {
          const put = await a.logins.put({ ...base, serverLoginState: 'setup', accountId });
          expect(await c.logins.consume(put.loginId)).toBeUndefined();
        } finally {
          await c.prisma.$disconnect();
        }
      } finally {
        rmSync(dir, { recursive: true, force: true });
      }
      // Expired by database time: refused and removed.
      const at = new Date('2026-10-29T12:00:00.000Z');
      const late = await a.logins.put({ ...base, serverLoginState: 'late', accountId }, at);
      expect(
        await b.logins.consume(late.loginId, new Date(at.getTime() + LOGIN_STATE_TTL_MS)),
      ).toBeUndefined();
      expect(await query(db.url, 'SELECT 1 FROM login_states')).toHaveLength(0);
    });

    it('stores no login id, no username and no readable OPAQUE state', async () => {
      const sentinel = 'OPAQUE-SERVER-STATE-SENTINEL-17-2';
      const put = await a.logins.put({
        ...base,
        loginSubject: loginSubject('synthetic-username-sentinel'),
        serverLoginState: sentinel,
        accountId: null,
      });
      const [row] = await query<{ text: string; sealed: Buffer; subject: Buffer; id: Buffer }>(
        db.url,
        `SELECT row_to_json(s)::text AS text, sealed, login_subject AS subject, id_hash AS id
         FROM login_states s`,
      );
      const id = Buffer.from(put.loginId, 'base64url');
      for (const needle of [
        put.loginId,
        id.toString('hex'),
        'synthetic-username-sentinel',
        sentinel,
      ])
        expect(row?.text).not.toContain(needle);
      expect(row?.sealed.includes(Buffer.from(sentinel))).toBe(false);
      expect(row?.sealed.includes(Buffer.from(put.challenge))).toBe(false);
      expect(row?.id).toEqual(sha256(id));
      expect(row?.subject).toEqual(sha256('login\u0000synthetic-username-sentinel'));
    });

    it(`refuses new logins at ${String(MAX_PENDING)} live states and never removes a live one`, async () => {
      await query(
        db.url,
        `INSERT INTO login_states (id_hash, purpose, login_subject, platform, sealed, created_at, expires_at)
         SELECT sha256(('pending-' || i)::bytea), 'login', sha256('s'::bytea), 'web',
                '\\x02'::bytea || sha256(('x' || i)::bytea) || sha256(('y' || i)::bytea) || sha256(('z' || i)::bytea), now(), now() + interval '60 seconds'
         FROM generate_series(1, $1::int) AS i`,
        [MAX_PENDING],
      );
      await expect(
        b.logins.put({ ...base, serverLoginState: 'full', accountId }),
      ).rejects.toMatchObject({ code: 'rate_limited' });
      const count = async () =>
        (await query<{ n: number }>(db.url, 'SELECT count(*)::int AS n FROM login_states'))[0]?.n;
      expect(await count()).toBe(MAX_PENDING);
      // Once they have expired, new logins are taken again and old rows go in bounded batches,
      // from both processes at once without errors.
      await query(
        db.url,
        `UPDATE login_states SET created_at = now() - interval '2 minutes',
                                 expires_at = now() - interval '1 minute'`,
      );
      const puts = await Promise.all(
        Array.from({ length: 10 }, (_, i) =>
          (i % 2 === 0 ? a : b).logins.put({
            ...base,
            serverLoginState: `after-${String(i)}`,
            accountId,
          }),
        ),
      );
      expect(await count()).toBeLessThan(MAX_PENDING);
      for (const put of puts) expect(await b.logins.consume(put.loginId)).toBeDefined();
    }, 60_000);

    it('racing starts at the bound pass it by less than the statements that can run at once', async () => {
      await query(
        db.url,
        `INSERT INTO login_states (id_hash, purpose, login_subject, platform, sealed, created_at, expires_at)
         SELECT sha256(('race-' || i)::bytea), 'login', sha256('s'::bytea), 'web',
                '\\x02'::bytea || sha256(('x' || i)::bytea) || sha256(('y' || i)::bytea) || sha256(('z' || i)::bytea),
                now(), now() + interval '60 seconds'
         FROM generate_series(1, $1::int) AS i`,
        [MAX_PENDING - 1],
      );
      const results = await Promise.allSettled(
        Array.from({ length: 60 }, (_, i) =>
          (i % 2 === 0 ? a : b).logins.put({
            ...base,
            serverLoginState: `edge-${String(i)}`,
            accountId,
          }),
        ),
      );
      const { admitted, refused } = settledCounts(results);
      expect(admitted).toBeGreaterThanOrEqual(1);
      expect(admitted).toBeLessThanOrEqual(2 * DATABASE_POOL_MAX);
      expect(refused).toBe(60 - admitted);
      const [n] = await query<{ n: number }>(db.url, 'SELECT count(*)::int AS n FROM login_states');
      expect(n?.n).toBe(MAX_PENDING - 1 + admitted);
    }, 60_000);

    it('expiry boundary: a state opens until its last millisecond, never at its expiry', async () => {
      const at = new Date(Date.now() + 5 * 60_000);
      const early = await a.logins.put({ ...base, serverLoginState: 'edge-early', accountId }, at);
      const last = new Date(at.getTime() + LOGIN_STATE_TTL_MS - 1);
      expect(await b.logins.consume(early.loginId, last)).toMatchObject({
        serverLoginState: 'edge-early',
      });
      const late = await a.logins.put({ ...base, serverLoginState: 'edge-late', accountId }, at);
      const expiry = new Date(at.getTime() + LOGIN_STATE_TTL_MS);
      expect(await b.logins.consume(late.loginId, expiry)).toBeUndefined();
      // A prune at that moment removes exactly the ended state, and keeps one still live.
      const live = await a.logins.put({ ...base, serverLoginState: 'edge-live', accountId }, last);
      const gone = await a.logins.put({ ...base, serverLoginState: 'edge-gone', accountId }, at);
      await b.logins.put({ ...base, serverLoginState: 'edge-pruner', accountId }, expiry);
      expect(await a.logins.consume(gone.loginId, last)).toBeUndefined();
      expect(await a.logins.consume(live.loginId, expiry)).toMatchObject({
        serverLoginState: 'edge-live',
      });
    });

    it('the runtime role may not update a state, or truncate either table', async () => {
      await a.logins.put({ ...base, serverLoginState: 'priv', accountId });
      for (const sql of [
        `UPDATE login_states SET expires_at = expires_at`,
        'TRUNCATE login_states',
        'TRUNCATE rate_windows',
        'ALTER TABLE rate_windows DROP CONSTRAINT rate_windows_hits_range',
      ])
        await expect(query(db.runtime.url, sql), sql).rejects.toThrow(
          /permission denied|must be owner/,
        );
    });
  });
});

describe('REVIEW §17.2 option B: one login across two API apps', () => {
  let one: Harness;
  let two: Harness;
  let account: Awaited<ReturnType<typeof syntheticAccount>>;

  beforeAll(async () => {
    one = await startHarness();
    account = await syntheticAccount('synthetic-17-2-http');
    await registerAccount(one, account);
    // A second API process on the same database. The instance lock keeps it from serving; the
    // overlap the lock exists to prevent is simulated by letting it serve anyway.
    vi.resetModules();
    two = await startHarness({ database: one.db });
    const { InstanceLockService } = await import('../../src/database/instance-lock.service.js');
    vi.spyOn(two.app.get(InstanceLockService), 'assertServing').mockImplementation(() => undefined);
  }, 90_000);

  afterAll(async () => {
    await (two as Harness | undefined)?.app.close();
    await (one as Harness | undefined)?.close();
  });

  async function start(h: Harness) {
    const client = startLogin();
    const res = await h
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
    return { started, finishLoginRequest: finished.finishLoginRequest };
  }

  const sessions = async () =>
    (await query<{ n: number }>(one.db.url, `SELECT count(*)::int AS n FROM sessions`))[0]?.n ?? 0;

  it('a proven login started on one app finishes on the other, once (D-31)', async () => {
    await one.app.get(ThrottleService).clearIpWindows();
    const { started, finishLoginRequest } = await start(one);
    const body = {
      loginId: started.loginId,
      finishLoginRequest,
      deviceProof: signLogin(account, started, finishLoginRequest),
    };
    const done = await two.post('/api/v1/auth/login/finish', body).expect(200);
    expect(done.body).toMatchObject({ proven: true, device: { status: 'active' } });
    // Replayed on either app: the state was consumed.
    for (const h of [one, two]) {
      const again = await h.post('/api/v1/auth/login/finish', body);
      expect(again.status).toBe(401);
      expect(again.body).toMatchObject({ error: 'login_failed' });
    }
  }, 30_000);

  it('without a device proof the other app gives a pre-proof session, as one app would (D-31 §5)', async () => {
    const { started, finishLoginRequest } = await start(two);
    const done = await one
      .post('/api/v1/auth/login/finish', { loginId: started.loginId, finishLoginRequest })
      .expect(200);
    expect(done.body).toMatchObject({ proven: false });
  }, 30_000);

  it('the same finish sent to both apps at once creates exactly one session', async () => {
    for (let round = 0; round < 3; round++) {
      // Each round sends seven requests from one address; the shared window allows twenty.
      await one.app.get(ThrottleService).clearIpWindows();
      const { started, finishLoginRequest } = await start(round % 2 === 0 ? one : two);
      const body = {
        loginId: started.loginId,
        finishLoginRequest,
        deviceProof: signLogin(account, started, finishLoginRequest),
      };
      const before = await sessions();
      const results = await Promise.all(
        Array.from({ length: 6 }, (_, i) =>
          (i % 2 === 0 ? one : two).post('/api/v1/auth/login/finish', body),
        ),
      );
      expect(results.filter((r) => r.status === 200)).toHaveLength(1);
      expect(results.map((r) => r.status).sort()).toEqual([200, 401, 401, 401, 401, 401]);
      expect(await sessions()).toBe(before + 1);
    }
  }, 60_000);

  it('without the grants on the new tables (grant-runtime skipped), it refuses; nothing is skipped', async () => {
    const runtime = one.db.runtime.name;
    await query(one.db.url, `REVOKE ALL ON rate_windows, login_states FROM "${runtime}"`);
    try {
      const start = await one.post('/api/v1/auth/login/start', {
        username: account.username,
        startLoginRequest: startLogin().startLoginRequest,
        platform: 'web',
        deviceId: account.deviceId,
      });
      expect(start.status).toBe(500);
      expect(start.body).toMatchObject({ error: 'internal_error' });
    } finally {
      await query(
        one.db.url,
        `GRANT SELECT, INSERT, UPDATE, DELETE ON rate_windows TO "${runtime}";
         GRANT SELECT, INSERT, DELETE ON login_states TO "${runtime}"`,
      );
    }
    expect(await query(one.db.url, 'SELECT 1 FROM login_states')).toHaveLength(0);
  });

  it('the per-address window is one budget for both apps', async () => {
    await one.app.get(ThrottleService).clearIpWindows();
    const statuses: number[] = [];
    for (let i = 0; i < 24; i++) {
      const res = await (i % 2 === 0 ? one : two).post('/api/v1/auth/login/start', {
        username: account.username,
        startLoginRequest: startLogin().startLoginRequest,
        platform: 'web',
        deviceId: account.deviceId,
      });
      statuses.push(res.status);
    }
    expect(statuses.filter((s) => s === 200)).toHaveLength(20);
    expect(statuses.slice(20)).toEqual([429, 429, 429, 429]);
  }, 30_000);
});
