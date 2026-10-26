import { Injectable } from '@nestjs/common';
import { ApiException } from '../common/api-exception.js';
import { sha256, type Bytes } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import type { ThrottleScope } from '../generated/prisma/client.js';

/**
 * authentication.md §7, as proposed. Throttling delays; it never locks an account for good. Login:
 * five free failures, then 30 s, 60 s, 120 s, … capped at 15 minutes (computed in SQL below).
 */
const LOGIN_FREE_FAILURES = 5;
const LOGIN_FIRST_DELAY_MS = 30_000;
const LOGIN_MAX_DELAY_MS = 15 * 60_000;
const BOOTSTRAP_FAILURES_PER_HOUR = 10;
const RECOVERY_STARTS_PER_HOUR = 5;
const HOUR_MS = 60 * 60_000;

const IP_WINDOW_MS = 60_000;
const IP_LIMIT = 20;
/** Bound on remembered addresses, so the limiter cannot itself exhaust memory. */
const IP_TABLE_MAX = 10_000;

function subject(scope: ThrottleScope, value: string): Bytes {
  return sha256(`${scope}\u0000${value}`);
}

@Injectable()
export class ThrottleService {
  private readonly perIp = new Map<string, { windowStart: number; count: number }>();

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Per-username login throttle. The key is a hash of the normalized username, so unknown and
   * known usernames are throttled identically and the typed name is never stored. A cheap early
   * refusal at `start`; the bound itself is `reserveLoginAttempt`.
   */
  async assertLoginAllowed(username: string, now = new Date()): Promise<void> {
    const row = await this.prisma.authThrottle.findUnique({
      where: { scope_subjectHash: { scope: 'login', subjectHash: subject('login', username) } },
    });
    if (row?.blockedUntil && row.blockedUntil > now)
      throw new ApiException(
        'rate_limited',
        undefined,
        (row.blockedUntil.getTime() - now.getTime()) / 1000,
      );
  }

  /**
   * Reserves one password check before it runs (login, step-up and reopening finishes): one
   * atomic statement counts it as a failure and sets the delay its count implies, but only if no
   * delay is in force; otherwise it refuses. However many finishes run in parallel, at most five
   * are evaluated before the delay applies (review R3). A successful check resets the count.
   */
  async reserveLoginAttempt(username: string, now = new Date()): Promise<void> {
    const hash = Buffer.from(subject('login', username));
    const reserved = await this.prisma.$queryRaw<{ failure_count: number }[]>`
      INSERT INTO auth_throttle AS t (scope, subject_hash, failure_count, window_start, blocked_until)
      VALUES ('login', ${hash}, 1, ${now}, NULL)
      ON CONFLICT (scope, subject_hash) DO UPDATE SET
        failure_count = t.failure_count + 1,
        blocked_until = CASE
          WHEN t.failure_count + 1 < ${LOGIN_FREE_FAILURES} THEN NULL
          ELSE ${now}::timestamptz + make_interval(secs => LEAST(
            ${LOGIN_FIRST_DELAY_MS}::float8 * power(2, LEAST(t.failure_count + 1 - ${LOGIN_FREE_FAILURES}, 30)),
            ${LOGIN_MAX_DELAY_MS}::float8) / 1000)
        END
      WHERE t.blocked_until IS NULL OR t.blocked_until <= ${now}
      RETURNING failure_count`;
    if (reserved.length === 1) return;
    await this.assertLoginAllowed(username, now);
    // The delay ended between the two statements: refuse this one anyway; the next may proceed.
    throw new ApiException('rate_limited', undefined, 1);
  }

  async resetLogin(username: string): Promise<void> {
    await this.prisma.authThrottle.deleteMany({
      where: { scope: 'login', subjectHash: subject('login', username) },
    });
  }

  /**
   * At most `limit` counted attempts per hour on one key, reserved atomically before the attempt
   * is checked: parallel requests cannot pass a check together and then all count (review R3).
   */
  private async reserveHourly(
    scope: 'recovery' | 'bootstrap',
    value: string,
    limit: number,
    now: Date,
  ): Promise<void> {
    const hash = Buffer.from(subject(scope, value));
    const windowOpen = new Date(now.getTime() - HOUR_MS);
    const reserved = await this.prisma.$queryRaw<{ failure_count: number }[]>`
      INSERT INTO auth_throttle AS t (scope, subject_hash, failure_count, window_start)
      VALUES (${scope}::throttle_scope, ${hash}, 1, ${now})
      ON CONFLICT (scope, subject_hash) DO UPDATE SET
        failure_count = CASE WHEN t.window_start <= ${windowOpen} THEN 1 ELSE t.failure_count + 1 END,
        window_start = CASE WHEN t.window_start <= ${windowOpen} THEN ${now} ELSE t.window_start END,
        blocked_until = NULL
      WHERE t.window_start <= ${windowOpen} OR t.failure_count < ${limit}
      RETURNING failure_count`;
    if (reserved.length === 1) return;
    const row = await this.prisma.authThrottle.findUnique({
      where: { scope_subjectHash: { scope, subjectHash: subject(scope, value) } },
    });
    const retry = row ? (row.windowStart.getTime() + HOUR_MS - now.getTime()) / 1000 : 1;
    throw new ApiException('rate_limited', undefined, Math.max(retry, 1));
  }

  /** At most 10 bootstrap attempts per hour in total (INV-20); counted before the token is checked. */
  async reserveBootstrapAttempt(now = new Date()): Promise<void> {
    await this.reserveHourly('bootstrap', '', BOOTSTRAP_FAILURES_PER_HOUR, now);
  }

  /**
   * Recovery attempts per username: 5 per hour, counted for unknown usernames too, so the limit
   * says nothing about whether an account exists (authentication.md §7).
   */
  async reserveRecoveryAttempt(username: string, now = new Date()): Promise<void> {
    await this.reserveHourly('recovery', username, RECOVERY_STARTS_PER_HOUR, now);
  }

  async resetRecovery(username: string): Promise<void> {
    await this.prisma.authThrottle.deleteMany({
      where: { scope: 'recovery', subjectHash: subject('recovery', username) },
    });
  }

  /** In-memory, per client address: 20 unauthenticated auth attempts per minute. */
  assertIpAllowed(ip: string | undefined, now = Date.now()): void {
    if (ip === undefined) return;
    const entry = this.perIp.get(ip);
    if (!entry || now - entry.windowStart >= IP_WINDOW_MS) {
      if (this.perIp.size >= IP_TABLE_MAX) this.sweep(now);
      this.perIp.set(ip, { windowStart: now, count: 1 });
      return;
    }
    entry.count++;
    if (entry.count > IP_LIMIT)
      throw new ApiException(
        'rate_limited',
        undefined,
        (entry.windowStart + IP_WINDOW_MS - now) / 1000,
      );
  }

  /** Forgets the in-memory windows (a restart does the same). Used by tests between cases. */
  clearIpWindows(): void {
    this.perIp.clear();
  }

  private sweep(now: number): void {
    for (const [ip, entry] of this.perIp)
      if (now - entry.windowStart >= IP_WINDOW_MS) this.perIp.delete(ip);
    if (this.perIp.size >= IP_TABLE_MAX) this.perIp.clear();
  }
}
