import { Injectable } from '@nestjs/common';
import { ApiException } from '../common/api-exception.js';
import { PrismaService } from '../database/prisma.service.js';
import type { RouteClass } from '../sessions/route-class.js';

export type GuardState = 'uninitialized' | 'restoring' | 'review' | 'reopening' | 'open';

const RESTORE_STATES = new Set<GuardState>(['restoring', 'review', 'reopening', 'open']);

/**
 * Whether this database may be served (backup-restore.md §3.5, §3.13; installation.ts). Only an
 * explicit answer opens it: a fresh installation's `ruvee_control.installation` row (from
 * `ruvee-admin init`), or a restore guard in `open`. Everything else is closed: no control
 * schema (`uninitialized`), a guard table without its row or with an unknown state (an
 * interrupted restore), a schema with neither table. `reopening` serves only the reopening.
 *
 * Only `open` is cached, because a database never goes from open back to closed. Every other
 * answer is read again on the next request, so a database that becomes a restore target, or
 * moves from `restoring` to `reopening`, is seen at once (review R14).
 */
@Injectable()
export class MaintenanceService {
  private open = false;

  constructor(private readonly prisma: PrismaService) {}

  async state(): Promise<GuardState> {
    if (this.open) return 'open';
    // Two statements: PostgreSQL resolves every table a statement names, even in a CASE branch
    // that is not taken.
    const [found] = await this.prisma.$queryRaw<
      { schema: boolean; guard: boolean; installation: boolean }[]
    >`
      SELECT to_regnamespace('ruvee_control') IS NOT NULL AS schema,
             to_regclass('ruvee_control.restore_guard') IS NOT NULL AS guard,
             to_regclass('ruvee_control.installation') IS NOT NULL AS installation`;
    let state: GuardState;
    if (!found?.schema) state = 'uninitialized';
    else if (found.guard) {
      const [row] = await this.prisma.$queryRaw<{ state: string }[]>`
        SELECT state FROM ruvee_control.restore_guard WHERE id = 1`;
      state =
        row && RESTORE_STATES.has(row.state as GuardState)
          ? (row.state as GuardState)
          : 'restoring';
    } else if (found.installation) {
      const [row] = await this.prisma.$queryRaw<{ origin: string }[]>`
        SELECT origin FROM ruvee_control.installation WHERE id = 1`;
      state = row?.origin === 'fresh' ? 'open' : 'uninitialized';
    } else state = 'restoring';
    if (state === 'open') this.open = true;
    return state;
  }

  async isOpen(): Promise<boolean> {
    return (await this.state()) === 'open';
  }

  /**
   * Throws the error a request for a handler of `routeClass` gets in the current state, if any.
   * Default deny: in every state but `open`, only `health` is served, and while reopening also
   * `reopen`. The class comes from the matched handler (route-class.ts).
   */
  async gate(routeClass: RouteClass): Promise<void> {
    if (routeClass === 'health') return;
    const state = await this.state();
    if (state === 'open') return;
    if (state === 'reopening') {
      if (routeClass === 'reopen') return;
      throw new ApiException('reopening');
    }
    throw new ApiException('maintenance');
  }
}
