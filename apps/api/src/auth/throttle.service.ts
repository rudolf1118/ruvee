import { Injectable } from '@nestjs/common';
import { ApiException } from '../common/api-exception.js';
import { sha256, type Bytes } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import type { ThrottleScope } from '../generated/prisma/client.js';

/** authentication.md §7, as proposed. Throttling delays; it never locks an account for good. */
const LOGIN_FREE_FAILURES = 5;
const LOGIN_FIRST_DELAY_MS = 30_000;
const LOGIN_MAX_DELAY_MS = 15 * 60_000;
const BOOTSTRAP_FAILURES_PER_HOUR = 10;
const HOUR_MS = 60 * 60_000;

const IP_WINDOW_MS = 60_000;
const IP_LIMIT = 20;
/** Bound on remembered addresses, so the limiter cannot itself exhaust memory. */
const IP_TABLE_MAX = 10_000;

function subject(scope: ThrottleScope, value: string): Bytes {
  return sha256(`${scope}\u0000${value}`);
}

/** Exponential delay after the free failures: 30 s, 60 s, 120 s, … capped at 15 minutes. */
export function loginDelayMs(failures: number): number {
  if (failures < LOGIN_FREE_FAILURES) return 0;
  return Math.min(LOGIN_FIRST_DELAY_MS * 2 ** (failures - LOGIN_FREE_FAILURES), LOGIN_MAX_DELAY_MS);
}

@Injectable()
export class ThrottleService {
  private readonly perIp = new Map<string, { windowStart: number; count: number }>();

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Per-username login throttle. The key is a hash of the normalized username, so unknown and
   * known usernames are throttled identically and the typed name is never stored.
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

  async recordLoginFailure(username: string, now = new Date()): Promise<void> {
    const key = { scope: 'login' as const, subjectHash: subject('login', username) };
    const row = await this.prisma.authThrottle.upsert({
      where: { scope_subjectHash: key },
      create: { ...key, failureCount: 1, windowStart: now },
      update: { failureCount: { increment: 1 } },
    });
    const delay = loginDelayMs(row.failureCount);
    if (delay > 0)
      await this.prisma.authThrottle.update({
        where: { scope_subjectHash: key },
        data: { blockedUntil: new Date(now.getTime() + delay) },
      });
  }

  async resetLogin(username: string): Promise<void> {
    await this.prisma.authThrottle.deleteMany({
      where: { scope: 'login', subjectHash: subject('login', username) },
    });
  }

  /** At most 10 failed bootstrap attempts per hour in total (INV-20). */
  async assertBootstrapAllowed(now = new Date()): Promise<void> {
    const row = await this.prisma.authThrottle.findUnique({
      where: { scope_subjectHash: { scope: 'bootstrap', subjectHash: subject('bootstrap', '') } },
    });
    if (
      row &&
      now.getTime() - row.windowStart.getTime() < HOUR_MS &&
      row.failureCount >= BOOTSTRAP_FAILURES_PER_HOUR
    )
      throw new ApiException(
        'rate_limited',
        undefined,
        (row.windowStart.getTime() + HOUR_MS - now.getTime()) / 1000,
      );
  }

  async recordBootstrapFailure(now = new Date()): Promise<void> {
    const key = { scope: 'bootstrap' as const, subjectHash: subject('bootstrap', '') };
    const row = await this.prisma.authThrottle.findUnique({ where: { scope_subjectHash: key } });
    if (!row || now.getTime() - row.windowStart.getTime() >= HOUR_MS) {
      await this.prisma.authThrottle.upsert({
        where: { scope_subjectHash: key },
        create: { ...key, failureCount: 1, windowStart: now },
        update: { failureCount: 1, windowStart: now, blockedUntil: null },
      });
      return;
    }
    await this.prisma.authThrottle.update({
      where: { scope_subjectHash: key },
      data: { failureCount: { increment: 1 } },
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
