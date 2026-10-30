import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { ApiException } from '../common/api-exception.js';
import type { Env } from '../config/env.js';
import { PrismaService } from '../database/prisma.service.js';
import { privilegeProblems } from '../database/runtime-privileges.js';
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
 * Every answer is read again on the next request, so a database that becomes a restore target,
 * or moves from `restoring` to `reopening`, is seen at once (review R14). `open` is not cached
 * either: a database never leaves `open`, but the process names its database by URL, and a
 * database dropped and recreated under the same name as a restore target is a new database
 * (follow-up review §18.4).
 *
 * F-25: the API's role may only read the gate's columns. If it cannot (a grant missing after a
 * restore or a migration), the answer is closed, never an error that some caller might treat as
 * open. And the role itself is checked once against runtime-privileges.ts: in production a role
 * with more than its list (a superuser, the schema owner, CREATE anywhere) serves nothing.
 * Privileges it lacks are not counted there: they fail closed where they are used, and a database
 * that is not set up yet, or is being restored, is supposed to lack them.
 */
@Injectable()
export class MaintenanceService {
  private readonly logger = new Logger(MaintenanceService.name);
  private excess: string[] | undefined;
  private reportedPrivileges = false;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService<Env, true>,
  ) {}

  async state(): Promise<GuardState> {
    try {
      return await this.read();
    } catch (error) {
      if (!isPrivilegeError(error)) throw error;
      if (!this.reportedPrivileges) {
        this.reportedPrivileges = true;
        this.logger.error(
          'The API role may not read the installation state; serving nothing. Run ruvee-admin grant-runtime (docs/guides/database-roles.md).',
        );
      }
      return 'restoring';
    }
  }

  private async read(): Promise<GuardState> {
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
    return state;
  }

  /**
   * What the connected role holds beyond the runtime list, read once (a change needs a restart).
   * Logged once; in production any of it closes every route but health.
   */
  private async checkRole(): Promise<string[]> {
    if (this.excess) return this.excess;
    const [me] = await this.prisma.$queryRaw<{ name: string }[]>`SELECT current_user AS name`;
    const problems = (
      await privilegeProblems(
        (sql, params) => this.prisma.$queryRawUnsafe<Record<string, unknown>[]>(sql, ...params),
        me?.name ?? '',
      )
    ).filter((p) => !p.startsWith('missing '));
    this.excess = problems;
    if (problems.length > 0) {
      const production = this.config.get('NODE_ENV', { infer: true }) === 'production';
      const message = `The API's database role is not the runtime role (database-roles.md): ${problems.slice(0, 5).join('; ')}${problems.length > 5 ? `; and ${String(problems.length - 5)} more` : ''}`;
      if (production) this.logger.error(`${message}. Serving nothing.`);
      else this.logger.warn(message);
    }
    return problems;
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
    const problems = await this.checkRole();
    if (problems.length > 0 && this.config.get('NODE_ENV', { infer: true }) === 'production')
      throw new ApiException('server_unavailable');
    const state = await this.state();
    if (state === 'open') return;
    if (state === 'reopening') {
      if (routeClass === 'reopen') return;
      throw new ApiException('reopening');
    }
    throw new ApiException('maintenance');
  }
}

/** PostgreSQL's insufficient_privilege or undefined_function, through Prisma's error wrapping. */
export function isPrivilegeError(error: unknown, depth = 0): boolean {
  if (depth > 5 || typeof error !== 'object' || error === null) return false;
  for (const [key, value] of Object.entries(error)) {
    if ((key === 'code' || key === 'originalCode') && (value === '42501' || value === '42883'))
      return true;
    if (typeof value === 'object' && isPrivilegeError(value, depth + 1)) return true;
  }
  const cause = (error as { cause?: unknown }).cause;
  return cause !== undefined && isPrivilegeError(cause, depth + 1);
}
