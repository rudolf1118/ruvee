import { Injectable, type OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaPg } from '@prisma/adapter-pg';
import type { Env } from '../config/env.js';
import { PrismaClient } from '../generated/prisma/client.js';

/**
 * Connections per API process (pg's own default, stated so the bound is ours). It also bounds
 * how many statements of one process run at once, and so how far the soft row bounds of
 * rate_windows and login_states can be passed (follow-up review §18.2).
 */
export const DATABASE_POOL_MAX = 10;

/**
 * Prisma client for the API. Connections are opened lazily by the pool, so the
 * process can start and report liveness while the database is unreachable.
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleDestroy {
  constructor(config: ConfigService<Env, true>) {
    super({
      adapter: new PrismaPg({
        connectionString: config.get('DATABASE_URL', { infer: true }),
        connectionTimeoutMillis: config.get('READINESS_DB_TIMEOUT_MS', { infer: true }),
        max: DATABASE_POOL_MAX,
      }),
    });
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }
}
