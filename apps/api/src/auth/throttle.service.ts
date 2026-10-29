import { isIPv4, isIPv6 } from 'node:net';
import { Injectable } from '@nestjs/common';
import { ApiException } from '../common/api-exception.js';
import { sha256, type Bytes } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import type { RateScope, ThrottleScope } from '../generated/prisma/client.js';

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

/**
 * Fixed request windows, kept in the database so that every API process shares one budget
 * (follow-up review §17.2 option B). Each is counted with one atomic statement before the work
 * it protects; a refused request is not counted twice.
 */
interface WindowRule {
  readonly scope: RateScope;
  readonly limit: number;
  readonly windowMs: number;
}
/** Unauthenticated authentication attempts per client address. */
const ADDRESS: WindowRule = { scope: 'address', limit: 20, windowMs: 60_000 };
/**
 * Wrong reopening codes per client address (review R11). A code is 256 random bits, so a wrong
 * one is never a step towards the right one; this bounds the load, and it never touches a real
 * code's own failure count.
 */
const WRONG_CODE: WindowRule = { scope: 'wrong_code', limit: 10, windowMs: 15 * 60_000 };
/** authentication.md §7: every authenticated request, per session (review R16). */
const SESSION: WindowRule = { scope: 'session', limit: 300, windowMs: 60_000 };
/** Bound on live windows per scope, so the limiter cannot itself exhaust the database. */
export const WINDOWS_PER_SCOPE = 10_000;
/** Expired windows removed per new key, at most. */
const PRUNE_BATCH = 500;
/** No address or session id contains NUL: the shared window of keys beyond the bound. */
const OVERFLOW_KEY = '\u0000overflow';

interface Counted {
  readonly keyHash: Buffer;
  readonly hits: number;
  readonly windowStart: Date;
  readonly now: Date;
}

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

/** The per-account login subject: SHA-256 of the normalized username, never the name itself. */
export function loginSubject(username: string): Bytes {
  return subject('login', username);
}

function windowKey(scope: RateScope, key: string): Buffer {
  return Buffer.from(sha256(`${scope}\u0000${key}`));
}

function refuse(rule: WindowRule, counted: Counted): never {
  const retry = (counted.windowStart.getTime() + rule.windowMs - counted.now.getTime()) / 1000;
  throw new ApiException('rate_limited', undefined, Math.max(retry, 1));
}

@Injectable()
export class ThrottleService {
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
  async reserveLoginAttempt(login: Bytes, now = new Date()): Promise<void> {
    const hash = Buffer.from(login);
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
    const row = await this.prisma.authThrottle.findUnique({
      where: { scope_subjectHash: { scope: 'login', subjectHash: login } },
    });
    if (row?.blockedUntil && row.blockedUntil > now)
      throw new ApiException(
        'rate_limited',
        undefined,
        (row.blockedUntil.getTime() - now.getTime()) / 1000,
      );
    // The delay ended between the two statements: refuse this one anyway; the next may proceed.
    throw new ApiException('rate_limited', undefined, 1);
  }

  async resetLogin(login: Bytes): Promise<void> {
    await this.prisma.authThrottle.deleteMany({ where: { scope: 'login', subjectHash: login } });
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

  /**
   * Counts one request in `rule`'s window for `key` and refuses it once the window's limit is
   * passed, in database time, so every process agrees on the window. A key that has a window is
   * one atomic UPDATE. Otherwise one statement removes up to PRUNE_BATCH expired windows of the
   * scope and inserts the key's window, or, while the scope already holds WINDOWS_PER_SCOPE live
   * windows, counts the request in one overflow window shared by every new key, under the same
   * limit. Live windows are never removed to make room (follow-up review F-8). Statements that
   * run at the same moment can each see room, so the bound may be passed by at most their number.
   * A database error refuses the request.
   */
  private async hit(rule: WindowRule, key: string, now?: Date): Promise<Counted> {
    const at = now ?? null;
    const keyHash = windowKey(rule.scope, key);
    const window = rule.windowMs;
    const [existing] = await this.prisma.$queryRaw<
      { hits: number; window_start: Date; now: Date }[]
    >`
      WITH t AS (SELECT COALESCE(${at}::timestamptz, now()) AS now)
      UPDATE rate_windows AS w SET
        hits = CASE WHEN w.window_start <= t.now - ${window} * interval '1 millisecond'
               THEN 1 ELSE LEAST(w.hits + 1, ${rule.limit + 1}) END,
        window_start = CASE WHEN w.window_start <= t.now - ${window} * interval '1 millisecond'
               THEN t.now ELSE w.window_start END
      FROM t
      WHERE w.scope = ${rule.scope}::rate_scope AND w.key_hash = ${keyHash}
      RETURNING w.hits, w.window_start, t.now`;
    let counted: Counted | undefined = existing && {
      keyHash,
      hits: existing.hits,
      windowStart: existing.window_start,
      now: existing.now,
    };
    if (!counted) {
      const overflow = windowKey(rule.scope, OVERFLOW_KEY);
      const [added] = await this.prisma.$queryRaw<
        { key_hash: Uint8Array; hits: number; window_start: Date; now: Date }[]
      >`
        WITH t AS (SELECT COALESCE(${at}::timestamptz, now()) AS now),
        pruned AS (
          DELETE FROM rate_windows
          WHERE scope = ${rule.scope}::rate_scope
            AND window_start <= (SELECT now FROM t) - ${window} * interval '1 millisecond'
            AND key_hash NOT IN (${keyHash}::bytea, ${overflow}::bytea)
            AND key_hash IN (
              SELECT key_hash FROM rate_windows
              WHERE scope = ${rule.scope}::rate_scope
                AND window_start <= (SELECT now FROM t) - ${window} * interval '1 millisecond'
              LIMIT ${PRUNE_BATCH})
          RETURNING 1),
        live AS (
          SELECT count(*) AS n FROM rate_windows
          WHERE scope = ${rule.scope}::rate_scope
            AND window_start > (SELECT now FROM t) - ${window} * interval '1 millisecond')
        INSERT INTO rate_windows AS w (scope, key_hash, window_start, hits)
        SELECT ${rule.scope}::rate_scope,
               CASE WHEN live.n < ${WINDOWS_PER_SCOPE} THEN ${keyHash}::bytea ELSE ${overflow}::bytea END,
               t.now, 1
        FROM t, live
        ON CONFLICT (scope, key_hash) DO UPDATE SET
          hits = CASE WHEN w.window_start <= EXCLUDED.window_start - ${window} * interval '1 millisecond'
                 THEN 1 ELSE LEAST(w.hits + 1, ${rule.limit + 1}) END,
          window_start = CASE WHEN w.window_start <= EXCLUDED.window_start - ${window} * interval '1 millisecond'
                 THEN EXCLUDED.window_start ELSE w.window_start END
        RETURNING w.key_hash, w.hits, w.window_start, (SELECT now FROM t) AS now`;
      if (!added) throw new Error('rate window not counted');
      counted = {
        keyHash: Buffer.from(added.key_hash),
        hits: added.hits,
        windowStart: added.window_start,
        now: added.now,
      };
    }
    if (counted.hits > rule.limit) refuse(rule, counted);
    return counted;
  }

  /** Per client address: 20 unauthenticated authentication attempts per minute. */
  async assertIpAllowed(ip: string | undefined, now?: Date): Promise<void> {
    if (ip === undefined) return;
    await this.hit(ADDRESS, addressKey(ip), now);
  }

  /** 300 authenticated requests per minute per session (authentication.md §7). */
  async assertSessionAllowed(sessionId: string, now?: Date): Promise<void> {
    await this.hit(SESSION, sessionId, now);
  }

  /**
   * Reserves one reopening-code guess for this address before the code is looked up (review
   * R11): parallel requests share the address's ten. A code that turns out to be the usable one
   * gives its reservation back with `releaseReopenCodeGuess`, so only wrong, malformed, expired
   * or used codes stay counted. An address that has used up its guesses is refused even with the
   * right code until its window ends.
   */
  async reserveReopenCodeGuess(ip: string | undefined, now?: Date): Promise<ReopenGuess> {
    if (ip === undefined) return undefined;
    const counted = await this.hit(WRONG_CODE, addressKey(ip), now);
    return { keyHash: counted.keyHash, windowStart: counted.windowStart };
  }

  /** The guess was the usable code: it is not counted against the address. */
  async releaseReopenCodeGuess(guess: ReopenGuess): Promise<void> {
    if (guess === undefined) return;
    await this.prisma.$executeRaw`
      UPDATE rate_windows SET hits = hits - 1
      WHERE scope = 'wrong_code' AND key_hash = ${guess.keyHash}
        AND window_start = ${guess.windowStart} AND hits > 0`;
  }

  /** Empties every request window (a restore does the same). Used by tests between cases. */
  async clearIpWindows(): Promise<void> {
    await this.prisma.$executeRaw`DELETE FROM rate_windows`;
  }
}

/** A reserved reopening-code guess, to give back if the code was the usable one. */
export type ReopenGuess = { readonly keyHash: Buffer; readonly windowStart: Date } | undefined;
