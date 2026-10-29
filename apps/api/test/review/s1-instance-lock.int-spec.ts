import { createServer, connect, type Server, type Socket } from 'node:net';
import type { ConfigService } from '@nestjs/config';
import type { Env } from '../../src/config/env.js';
import { loginSubject, ThrottleService } from '../../src/auth/throttle.service.js';
import {
  INSTANCE_LOCK_KEY,
  InstanceLockService,
} from '../../src/database/instance-lock.service.js';
import { PrismaService } from '../../src/database/prisma.service.js';
import { createTempDatabase, migrate, query, type TempDatabase } from '../support/temp-database.js';

/**
 * Follow-up review S-1: the instance lock lives on one connection. If that connection is lost
 * without the client hearing of it (a silent network drop; the server ends the backend and so
 * frees the lock), the process must stop serving instead of believing it still holds the lock
 * while a second process takes it. A TCP relay stands in for the network and drops traffic
 * silently. Synthetic, empty database only.
 */

/** Relays TCP to the database; `blackhole()` stops forwarding and never closes the client side. */
async function relay(
  target: URL,
): Promise<{ url: URL; blackhole(): void; close(): Promise<void> }> {
  const sockets = new Set<Socket>();
  let dropped = false;
  const server: Server = createServer((client) => {
    const upstream = connect(Number(target.port || 5432), target.hostname);
    sockets.add(client).add(upstream);
    client.on('data', (chunk) => {
      if (!dropped) upstream.write(chunk);
    });
    upstream.on('data', (chunk) => {
      if (!dropped) client.write(chunk);
    });
    // While dropped, neither side's closing reaches the other: as on a broken network path.
    upstream.on('close', () => {
      if (!dropped) client.destroy();
    });
    client.on('close', () => {
      if (!dropped) upstream.destroy();
    });
    client.on('error', () => undefined);
    upstream.on('error', () => undefined);
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no relay address');
  const url = new URL(target.toString());
  url.hostname = '127.0.0.1';
  url.port = String(address.port);
  return {
    url,
    blackhole() {
      dropped = true;
    },
    async close() {
      for (const s of sockets) s.destroy();
      await new Promise<void>((resolve) =>
        server.close(() => {
          resolve();
        }),
      );
    },
  };
}

/** The check's own bounds: it must notice within one interval plus one query timeout. */
const CHECK_MS = 500;
const TIMEOUT_MS = 3_000;
/** The lock service retries a failed start every 5 s. */
const RETRY_BOUND_MS = 5_000 + TIMEOUT_MS;

describe('S-1: a silently lost instance-lock connection (real database)', () => {
  let db: TempDatabase;

  beforeAll(async () => {
    db = await createTempDatabase();
  }, 60_000);

  afterAll(async () => {
    await db.drop();
  });

  it('stops serving once the lock may have been freed, before another process can serve long', async () => {
    const path = await relay(new URL(db.url));
    const config = {
      get: (key: keyof Env) =>
        ({ DATABASE_URL: path.url.toString(), READINESS_DB_TIMEOUT_MS: TIMEOUT_MS })[key as string],
    } as unknown as ConfigService<Env, true>;
    const lock = new InstanceLockService(config);
    lock.checkIntervalMs = CHECK_MS;
    try {
      await lock.onApplicationBootstrap();
      // Connecting may need the full timeout on a busy server; the lock is taken by its retry then.
      await expect.poll(() => lock.held, { timeout: 2 * RETRY_BOUND_MS, interval: 100 }).toBe(true);
      const [holder] = await query<{ pid: number }>(
        db.url,
        // pg_locks lists every database's locks: only this test's own database (other test
        // files hold the same key on theirs).
        `SELECT pid FROM pg_locks WHERE locktype = 'advisory' AND granted
           AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
           AND ((classid::bigint << 32) | objid::bigint) = $1::bigint`,
        [INSTANCE_LOCK_KEY],
      );
      expect(holder?.pid).toBeGreaterThan(0);
      // The network path breaks silently, and the server ends the backend: the lock is free.
      path.blackhole();
      await query(db.url, 'SELECT pg_terminate_backend($1)', [holder?.pid]);
      const [other] = await query<{ ok: boolean }>(
        db.url,
        'SELECT pg_try_advisory_lock($1::bigint) AS ok',
        [INSTANCE_LOCK_KEY],
      );
      expect(other?.ok).toBe(true);
      // This process must notice within its check interval plus the query timeout.
      await expect
        .poll(() => lock.held, { timeout: CHECK_MS + TIMEOUT_MS + 1_000, interval: 100 })
        .toBe(false);
    } finally {
      await lock.onApplicationShutdown();
      await path.close();
    }
  }, 60_000);
});

/**
 * What an overlap of two API processes (the S-1 residual) does and does not split. Two services
 * with their own database clients stand in for two processes on one database.
 */
describe('S-1 residual: limits shared by two overlapping processes (real database)', () => {
  let db: TempDatabase;

  beforeAll(async () => {
    db = await createTempDatabase();
    migrate(db.url);
  }, 60_000);

  afterAll(async () => {
    await db.drop();
  });

  it('the per-account login limit and the per-address window are each one budget (§17.2)', async () => {
    const config = {
      get: (key: keyof Env) =>
        ({ DATABASE_URL: db.url, READINESS_DB_TIMEOUT_MS: 5_000 })[key as string],
    } as unknown as ConfigService<Env, true>;
    const prismas = [new PrismaService(config), new PrismaService(config)] as const;
    const [one, two] = prismas.map((p) => new ThrottleService(p));
    if (!one || !two) throw new Error('two services');
    try {
      // Twelve password checks for one username, alternating between the processes, all at
      // once. Five are evaluated in all, as with one process (review R3).
      const now = new Date();
      const results = await Promise.allSettled(
        Array.from({ length: 12 }, (_, i) =>
          (i % 2 === 0 ? one : two).reserveLoginAttempt(loginSubject('synthetic-s1-user'), now),
        ),
      );
      expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(5);
      // Before option B each process counted its own 20 attempts per address per minute. Now
      // forty at once from one address, split over both processes, admit twenty.
      const at = new Date();
      const perAddress = await Promise.allSettled(
        Array.from({ length: 40 }, (_, i) =>
          (i % 2 === 0 ? one : two).assertIpAllowed('192.0.2.7', at),
        ),
      );
      expect(perAddress.filter((r) => r.status === 'fulfilled')).toHaveLength(20);
    } finally {
      await Promise.all(prismas.map((p) => p.$disconnect()));
    }
  });
});
