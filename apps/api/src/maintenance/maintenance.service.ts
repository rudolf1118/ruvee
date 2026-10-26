import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service.js';

/**
 * Maintenance mode of a restored installation (backup-restore.md §3.5). The restore tool creates
 * `ruvee_restore_guard` before it loads anything; it is outside the Prisma schema and never in a
 * backup. No table means an installation that was never restored. A guard that is not `open`
 * keeps every API request closed; only `ruvee-admin restore-complete` opens it. Once open, the
 * answer is cached: a database never goes from open back to restoring.
 */
@Injectable()
export class MaintenanceService {
  private open = false;

  constructor(private readonly prisma: PrismaService) {}

  /** Fails closed: until the guard has been read and says open (or is absent), nothing is open. */
  async isOpen(): Promise<boolean> {
    if (this.open) return true;
    // Two statements: PostgreSQL resolves every table a statement names, even in a CASE branch
    // that is not taken.
    const [{ present } = { present: false }] = await this.prisma.$queryRaw<{ present: boolean }[]>`
      SELECT to_regclass('public.ruvee_restore_guard') IS NOT NULL AS present`;
    const state = present
      ? (
          await this.prisma.$queryRaw<{ state: string }[]>`
            SELECT state FROM ruvee_restore_guard WHERE id = 1`
        )[0]?.state
      : 'none';
    // A guard table without its row is an interrupted restore too.
    this.open = state === 'none' || state === 'open';
    return this.open;
  }
}
