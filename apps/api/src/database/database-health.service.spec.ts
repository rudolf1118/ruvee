import { ConfigService } from '@nestjs/config';
import { DatabaseHealthService } from './database-health.service.js';
import type { InstanceLockService } from './instance-lock.service.js';
import { PrismaService } from './prisma.service.js';

const serving = { held: true } as InstanceLockService;

function configWith(values: Record<string, unknown>): ConfigService<never, true> {
  return new ConfigService(values);
}

describe('DatabaseHealthService', () => {
  it('reports up when the query succeeds', async () => {
    const prisma = { $queryRaw: () => Promise.resolve([{ '?column?': 1 }]) } as never;
    const service = new DatabaseHealthService(
      prisma,
      configWith({ READINESS_DB_TIMEOUT_MS: 500 }),
      serving,
    );
    await expect(service.check()).resolves.toBe('up');
  });

  it('reports down when the query hangs past the timeout', async () => {
    const prisma = { $queryRaw: () => new Promise(() => undefined) } as never;
    const service = new DatabaseHealthService(
      prisma,
      configWith({ READINESS_DB_TIMEOUT_MS: 100 }),
      serving,
    );
    const started = Date.now();
    await expect(service.check()).resolves.toBe('down');
    expect(Date.now() - started).toBeLessThan(1000);
  });

  it('reports down in a process that does not hold the instance lock', async () => {
    const prisma = { $queryRaw: () => Promise.resolve([{ '?column?': 1 }]) } as never;
    const service = new DatabaseHealthService(
      prisma,
      configWith({ READINESS_DB_TIMEOUT_MS: 500 }),
      { held: false } as InstanceLockService,
    );
    await expect(service.check()).resolves.toBe('down');
  });

  it('reports down when a real client cannot reach the server', async () => {
    const config = configWith({
      // Nothing listens on the discard port on loopback, so the connection is refused.
      DATABASE_URL: 'postgresql://ruvee:unused@127.0.0.1:9/ruvee',
      READINESS_DB_TIMEOUT_MS: 1000,
    });
    const prisma = new PrismaService(config);
    try {
      await expect(new DatabaseHealthService(prisma, config, serving).check()).resolves.toBe(
        'down',
      );
    } finally {
      await prisma.$disconnect();
    }
  });
});
