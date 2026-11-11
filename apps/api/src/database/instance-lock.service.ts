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
  'Another Ruvee API process serves this database. Ruvee runs one API process per database; ' +
  'this one serves nothing until the other stops.';

/**
 * An operational guard against starting a second API process by accident: the serving process
 * holds a session-level advisory lock on its own connection; a process without it answers health
 * checks only. Starting never waits for the database (liveness stays independent of it): the
 * lock is tried at start and then retried, and taken again if its connection is lost.
 *
 * No security property depends on it (follow-up review §17.2, option B). The request windows,
 * pending logins and every limit are shared in the database, so two processes that overlap (a
 * lost lock connection, a stalled event loop, a partition) still share one budget and one
 * single-use login state. The holder still confirms on its connection, every `checkIntervalMs`,
 * that it holds the lock, and stops serving when the check fails or takes longer than
 * READINESS_DB_TIMEOUT_MS (follow-up review S-1); that interval bounds nothing a guarantee rests on.
 */
@Injectable()
export class InstanceLockService implements OnApplicationBootstrap, OnApplicationShutdown {
  private readonly logger = new Logger(InstanceLockService.name);
  private client: pg.Client | undefined;
  private attempting = false;
  private closing = false;
  private timer: NodeJS.Timeout | undefined;
  private reportedConflict = false;
  private checker: NodeJS.Timeout | undefined;
  private checking = false;
  /** How often the holder confirms it still holds the lock. Tests shorten it before start. */
  checkIntervalMs = 10_000;

  /** env.ts refuses the setting outside NODE_ENV=test; checked here again all the same. */
  private readonly skipped: boolean;

  constructor(private readonly config: ConfigService<Env, true>) {
    this.skipped =
      config.get('NODE_ENV', { infer: true }) === 'test' &&
      config.get('RUVEE_TEST_ONLY_SKIP_INSTANCE_LOCK', { infer: true }) === '1';
  }

  get held(): boolean {
    return this.skipped || this.client !== undefined;
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
    if (this.skipped) {
      this.logger.warn(
        'Test only: serving without the instance lock (RUVEE_TEST_ONLY_SKIP_INSTANCE_LOCK).',
      );
      return;
    }
    await this.attempt();
    if (!this.held) this.retry();
  }

  async onApplicationShutdown(): Promise<void> {
    this.closing = true;
    clearInterval(this.timer);
    clearInterval(this.checker);
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
      keepAlive: true,
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
      this.checker = setInterval(() => void this.check(client), this.checkIntervalMs);
      this.checker.unref();
    } catch (error) {
      // Driver errors can include connection details, so only the error class is logged.
      const kind = error instanceof Error ? error.name : 'UnknownError';
      this.logger.warn({ errorKind: kind }, 'Could not take the API instance lock yet');
      await client.end().catch(() => undefined);
    } finally {
      this.attempting = false;
    }
  }

  /** On the lock's own connection: is the lock still granted to this backend? */
  private async check(client: pg.Client): Promise<void> {
    if (this.client !== client || this.checking || this.closing) return;
    this.checking = true;
    let timeout: NodeJS.Timeout | undefined;
    try {
      const { rows } = await Promise.race([
        client.query<{ ok: boolean }>(
          `SELECT EXISTS (
             SELECT 1 FROM pg_locks
             WHERE locktype = 'advisory' AND granted AND pid = pg_backend_pid()
               AND ((classid::bigint << 32) | objid::bigint) = $1::bigint
           ) AS ok`,
          [INSTANCE_LOCK_KEY],
        ),
        new Promise<never>((_, reject) => {
          timeout = setTimeout(
            () => {
              reject(new Error('instance lock check timed out'));
            },
            this.config.get('READINESS_DB_TIMEOUT_MS', { infer: true }),
          );
        }),
      ]);
      if (rows[0]?.ok !== true) this.lost(client);
    } catch {
      this.lost(client);
    } finally {
      clearTimeout(timeout);
      this.checking = false;
    }
  }

  private lost(client: pg.Client): void {
    if (this.client !== client || this.closing) return;
    clearInterval(this.checker);
    this.checker = undefined;
    this.client = undefined;
    this.logger.error('The API instance lock was lost; serving nothing until it is taken again');
    void client.end().catch(() => undefined);
    this.retry();
  }
}
