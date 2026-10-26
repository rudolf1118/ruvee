import { isIPv4, isIPv6 } from 'node:net';
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
/**
 * Wrong reopening codes per client address (review R11). A code is 256 random bits, so a wrong
 * one is never a step towards the right one; this bounds the load, and it never touches a real
 * code's own failure count.
 */
const WRONG_CODE_WINDOW_MS = 15 * 60_000;
const WRONG_CODE_LIMIT = 10;
/** authentication.md §7: every authenticated request, per session (review R16). */
const SESSION_WINDOW_MS = 60_000;
const SESSION_LIMIT = 300;
/** Bound on remembered addresses, so the limiter cannot itself exhaust memory. */
const IP_TABLE_MAX = 10_000;

/**
 * The key an address is limited under (review R17): an IPv4 address as it is, an IPv6 address by
 * its /64, the smallest block one subscriber is normally given, so rotating through the addresses
 * of one network does not give a fresh window each time.
 */
export function addressKey(ip: string): string {
  if (isIPv4(ip) || !isIPv6(ip)) return ip;
  let text = ip.toLowerCase();
  const zone = text.indexOf('%');
  if (zone >= 0) text = text.slice(0, zone);
  const v4 = /(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (v4) {
    const [a, b, c, d] = v4.slice(1).map(Number) as [number, number, number, number];
    text = `${text.slice(0, v4.index)}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const [head = '', tail] = text.split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups =
    tail === undefined
      ? left
      : [...left, ...Array<string>(8 - left.length - right.length).fill('0'), ...right];
  return `${groups
    .slice(0, 4)
    .map((g) => parseInt(g, 16).toString(16))
    .join(':')}::/64`;
}

function subject(scope: ThrottleScope, value: string): Bytes {
  return sha256(`${scope}\u0000${value}`);
}

/** Fixed windows per key, in memory (single process, so each update is atomic). */
class Windows {
  private readonly entries = new Map<string, { windowStart: number; count: number }>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  /** Counts one event; throws `rate_limited` once the limit is passed. */
  hit(key: string, now: number): void {
    const entry = this.entries.get(key);
    if (!entry || now - entry.windowStart >= this.windowMs) {
      if (this.entries.size >= IP_TABLE_MAX) this.sweep(now);
      this.entries.set(key, { windowStart: now, count: 1 });
      return;
    }
    entry.count++;
    if (entry.count > this.limit) this.refuse(entry, now);
  }

  /** Throws `rate_limited` if the limit is used up, without counting. */
  check(key: string, now: number): void {
    const entry = this.entries.get(key);
    if (entry && now - entry.windowStart < this.windowMs && entry.count >= this.limit)
      this.refuse(entry, now);
  }

  clear(): void {
    this.entries.clear();
  }

  private refuse(entry: { windowStart: number }, now: number): never {
    throw new ApiException(
      'rate_limited',
      undefined,
      (entry.windowStart + this.windowMs - now) / 1000,
    );
  }

  private sweep(now: number): void {
    for (const [key, entry] of this.entries)
      if (now - entry.windowStart >= this.windowMs) this.entries.delete(key);
    if (this.entries.size >= IP_TABLE_MAX) this.entries.clear();
  }
}

@Injectable()
export class ThrottleService {
  private readonly perIp = new Windows(IP_LIMIT, IP_WINDOW_MS);
  private readonly wrongCodes = new Windows(WRONG_CODE_LIMIT, WRONG_CODE_WINDOW_MS);
  private readonly perSession = new Windows(SESSION_LIMIT, SESSION_WINDOW_MS);

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
    this.perIp.hit(addressKey(ip), now);
  }

  /** In memory: 300 authenticated requests per minute per session (authentication.md §7). */
  assertSessionAllowed(sessionId: string, now = Date.now()): void {
    this.perSession.hit(sessionId, now);
  }

  /** Before a reopening code is looked up: an address that sent too many wrong codes waits. */
  assertReopenCodeGuessesAllowed(ip: string | undefined, now = Date.now()): void {
    if (ip === undefined) return;
    this.wrongCodes.check(addressKey(ip), now);
  }

  /** A wrong, malformed, expired or used code from this address (review R11). */
  recordWrongReopenCode(ip: string | undefined, now = Date.now()): void {
    if (ip === undefined) return;
    try {
      this.wrongCodes.hit(addressKey(ip), now);
    } catch {
      // Already over the limit: the next request is refused by the check above.
    }
  }

  /** Forgets the in-memory windows (a restart does the same). Used by tests between cases. */
  clearIpWindows(): void {
    this.perIp.clear();
    this.wrongCodes.clear();
    this.perSession.clear();
  }
}
