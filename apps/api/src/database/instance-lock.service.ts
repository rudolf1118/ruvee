import {
  Injectable,
  Logger,
  type OnApplicationBootstrap,
  type OnApplicationShutdown,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import pg from 'pg';
import { ApiException } from '../common/api-exception.js';
import type { Env } from '../config/env.js';

/** `pg_try_advisory_lock` key of the API process: the ASCII bytes of "ruveeapi". */
export const INSTANCE_LOCK_KEY = '8247628470463590505';
const RETRY_MS = 5_000;

export const ANOTHER_INSTANCE =
  'Another Ruvee API process serves this database. V1 supports exactly one API process per ' +
  'database (login state and request limits are kept in its memory); this one serves nothing.';

/**
 * V1 runs exactly one API process per database (authentication.md §7, README): login
 * states, per-address windows and per-session limits live in that process's memory, so a second
 * process would split them. The serving process holds a session-level advisory lock on its own
 * connection; a process without it answers health checks only. Starting never waits for the
 * database (liveness stays independent of it): the lock is tried at start and then retried, and
 * taken again if its connection is lost.
 */
@Injectable()
export class InstanceLockService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger(InstanceLockService.name);
  private client: pg.Client | undefined;
  private attempting = false;
  private closing = false;
  private timer: NodeJS.Timeout | undefined;
  private reportedConflict = false;

  constructor(private readonly config: ConfigService<Env, true>) {}

  get held(): boolean {
    return this.client !== undefined;
  }

  /** Read through a method: `closing` changes while an attempt awaits the database. */
  private stopping(): boolean {
    return this.closing;
  }

  /** Every route but health: only the process holding the lock serves. */
  assertServing(): void {
    if (!this.held) throw new ApiException('server_unavailable');
  }

  async onApplicationBootstrap(): Promise<void> {
    await this.attempt();
    if (!this.held) this.retry();
  }

  async onApplicationShutdown(): Promise<void> {
    this.closing = true;
    clearInterval(this.timer);
    const client = this.client;
    this.client = undefined;
    // Ending the connection releases the lock.
    await client?.end().catch(() => undefined);
  }

  private retry(): void {
    if (this.timer || this.closing) return;
    this.timer = setInterval(() => void this.attempt(), RETRY_MS);
    this.timer.unref();
  }

  private async attempt(): Promise<void> {
    if (this.held || this.attempting || this.closing) return;
    this.attempting = true;
    const client = new pg.Client({
      connectionString: this.config.get('DATABASE_URL', { infer: true }),
      connectionTimeoutMillis: this.config.get('READINESS_DB_TIMEOUT_MS', { infer: true }),
    });
    client.on('error', () => {
      this.lost(client);
    });
    try {
      await client.connect();
      const { rows } = await client.query<{ ok: boolean }>(
        'SELECT pg_try_advisory_lock($1::bigint) AS ok',
        [INSTANCE_LOCK_KEY],
      );
      if (rows[0]?.ok !== true || this.stopping()) {
        await client.end().catch(() => undefined);
        if (!this.stopping() && !this.reportedConflict) {
          this.reportedConflict = true;
          this.logger.error(ANOTHER_INSTANCE);
        }
        return;
      }
      client.on('end', () => {
        this.lost(client);
      });
      this.client = client;
      this.reportedConflict = false;
      clearInterval(this.timer);
      this.timer = undefined;
    } catch (error) {
      // Driver errors can include connection details, so only the error class is logged.
      const kind = error instanceof Error ? error.name : 'UnknownError';
      this.logger.warn({ errorKind: kind }, 'Could not take the API instance lock yet');
      await client.end().catch(() => undefined);
    } finally {
      this.attempting = false;
    }
  }

  private lost(client: pg.Client): void {
    if (this.client !== client || this.closing) return;
    this.client = undefined;
    this.logger.error('The API instance lock was lost; serving nothing until it is taken again');
    void client.end().catch(() => undefined);
    this.retry();
  }
}
