import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import type { Env } from '../config/env.js';
import { InstanceLockService } from './instance-lock.service.js';
import { PrismaService } from './prisma.service.js';

export type DependencyStatus = 'up' | 'down';

@Injectable()
export class DatabaseHealthService {
  private readonly logger = new Logger(DatabaseHealthService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService<Env, true>,
    private readonly instance: InstanceLockService,
  ) {}

  /**
   * Runs a trivial query, bounded by READINESS_DB_TIMEOUT_MS. A process that does not hold the
   * instance lock is not ready either: it serves nothing (InstanceLockService).
   */
  async check(): Promise<DependencyStatus> {
    if (!this.instance.held) return 'down';
    const timeoutMs = this.config.get('READINESS_DB_TIMEOUT_MS', { infer: true });
    let timer: NodeJS.Timeout | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => {
        reject(new Error(`Database check timed out after ${timeoutMs} ms`));
      }, timeoutMs);
    });
    try {
      await Promise.race([this.prisma.$queryRaw`SELECT 1`, timeout]);
      return 'up';
    } catch (error) {
      // Driver errors can include connection details, so only the error class is logged.
      const kind = error instanceof Error ? error.name : 'UnknownError';
      this.logger.warn({ errorKind: kind }, 'Database readiness check failed');
      return 'down';
    } finally {
      clearTimeout(timer);
    }
  }
}
