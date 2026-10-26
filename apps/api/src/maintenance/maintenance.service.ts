import { Injectable } from '@nestjs/common';
import { ApiException } from '../common/api-exception.js';
import { PrismaService } from '../database/prisma.service.js';

export type GuardState = 'none' | 'restoring' | 'review' | 'reopening' | 'open';

/** The only routes a restored installation serves while it waits to be reopened (§3.13). */
export const REOPEN_PREFIX = '/api/v1/reopen/';

/**
 * Maintenance mode of a restored installation (backup-restore.md §3.5, §3.13). The restore tool
 * creates `ruvee_restore_guard` before it loads anything; it is outside the Prisma schema and
 * never in a backup. No table means an installation that was never restored. `restoring` and
 * `review` keep every API request closed; `reopening` serves only the reopening endpoints; only
 * the reopening's completion (or, with no account, `restore-complete`) opens it. Once open, the
 * answer is cached: a database never goes from open back to closed.
 */
@Injectable()
export class MaintenanceService {
  private open = false;

  constructor(private readonly prisma: PrismaService) {}

  /** Fails closed: until the guard has been read and says open (or is absent), nothing is open. */
  async state(): Promise<GuardState> {
    if (this.open) return 'open';
    // Two statements: PostgreSQL resolves every table a statement names, even in a CASE branch
    // that is not taken.
    const [{ present } = { present: false }] = await this.prisma.$queryRaw<{ present: boolean }[]>`
      SELECT to_regclass('public.ruvee_restore_guard') IS NOT NULL AS present`;
    const state = present
      ? (
          await this.prisma.$queryRaw<{ state: GuardState }[]>`
            SELECT state FROM ruvee_restore_guard WHERE id = 1`
        )[0]?.state
      : 'none';
    // A guard table without its row is an interrupted restore too.
    const known: GuardState = state ?? 'restoring';
    this.open = known === 'none' || known === 'open';
    return known;
  }

  async isOpen(): Promise<boolean> {
    const state = await this.state();
    return state === 'none' || state === 'open';
  }

  /** Throws the error a request on `path` gets in the current state, if any. */
  async gate(path: string): Promise<void> {
    if (!path.startsWith('/api/')) return;
    const state = await this.state();
    if (state === 'none' || state === 'open') return;
    if (state === 'reopening') {
      if (path.startsWith(REOPEN_PREFIX)) return;
      throw new ApiException('reopening');
    }
    throw new ApiException('maintenance');
  }
}
