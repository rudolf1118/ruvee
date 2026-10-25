import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  RECOVERY_COOKIE_INSECURE_DEV,
  RECOVERY_COOKIE_SECURE,
  RECOVERY_SESSION_MS,
  SESSION_COOKIE_INSECURE_DEV,
  SESSION_COOKIE_SECURE,
  type TokenPair,
} from '@ruvee/contracts';
import type { Response } from 'express';
import { ApiException } from '../common/api-exception.js';
import { randomToken, sha256 } from '../common/secrets.js';
import type { Env } from '../config/env.js';
import { PrismaService } from '../database/prisma.service.js';
import type { DeviceStatus, Prisma, RevokeReason } from '../generated/prisma/client.js';

/** D-08, approved for development: web sessions 12 h idle (sliding) and 14 days absolute. */
export const SESSION_IDLE_MS = 12 * 60 * 60 * 1000;
export const SESSION_ABSOLUTE_MS = 14 * 24 * 60 * 60 * 1000;
/** D-08 for token clients: 10-minute access tokens; refresh 30 days idle, 90 days absolute. */
export const ACCESS_TOKEN_MS = 10 * 60 * 1000;
export const REFRESH_IDLE_MS = 30 * 24 * 60 * 60 * 1000;
export const REFRESH_ABSOLUTE_MS = 90 * 24 * 60 * 60 * 1000;
/** Step-up window for INV-14 endpoints. */
export const STEP_UP_MS = 5 * 60 * 1000;
/** `last_used_at`, `idle_expires_at` and `last_seen_at` are written at most this often. */
const TOUCH_INTERVAL_MS = 60 * 1000;
const TOKEN_TEXT = /^[A-Za-z0-9_-]{43}$/;

export interface AuthenticatedSession {
  readonly sessionId: string;
  readonly accountId: string;
  readonly deviceId: string;
  readonly deviceStatus: DeviceStatus;
  readonly authAt: Date;
}

@Injectable()
export class SessionService {
  readonly cookieName: string;
  /** The recovery session's own cookie, so it can never stand in for a normal session. */
  readonly recoveryCookieName: string;
  private readonly secure: boolean;

  constructor(
    private readonly prisma: PrismaService,
    config: ConfigService<Env, true>,
  ) {
    this.secure = config.get('SESSION_COOKIE_SECURE', { infer: true }) === 'true';
    this.cookieName = this.secure ? SESSION_COOKIE_SECURE : SESSION_COOKIE_INSECURE_DEV;
    this.recoveryCookieName = this.secure ? RECOVERY_COOKIE_SECURE : RECOVERY_COOKIE_INSECURE_DEV;
  }

  /** account-recovery.md §3 step 2: 15 minutes, usable only on the recovery endpoints. */
  async createRecovery(
    accountId: string,
    deviceId: string,
    tx: Prisma.TransactionClient = this.prisma,
    now = new Date(),
  ): Promise<{ token: string; absoluteExpiresAt: Date }> {
    const token = randomToken();
    const absoluteExpiresAt = new Date(now.getTime() + RECOVERY_SESSION_MS);
    await tx.session.create({
      data: {
        id: randomUUID(),
        accountId,
        deviceId,
        kind: 'recovery',
        secretHash: sha256(token),
        authAt: now,
        createdAt: now,
        lastUsedAt: now,
        idleExpiresAt: absoluteExpiresAt,
        absoluteExpiresAt,
      },
    });
    return { token, absoluteExpiresAt };
  }

  setRecoveryCookie(res: Response, token: string, absoluteExpiresAt: Date, now = new Date()): void {
    const maxAge = Math.max(0, Math.floor((absoluteExpiresAt.getTime() - now.getTime()) / 1000));
    res.append('Set-Cookie', this.cookie(token, maxAge, this.recoveryCookieName));
  }

  clearRecoveryCookie(res: Response): void {
    res.append('Set-Cookie', this.cookie('', 0, this.recoveryCookieName));
  }

  /** A live recovery session; normal sessions are never accepted here, and the reverse. */
  async authenticateRecovery(
    token: string | undefined,
    now = new Date(),
  ): Promise<AuthenticatedSession> {
    if (token === undefined || !TOKEN_TEXT.test(token)) throw new ApiException('unauthenticated');
    const session = await this.prisma.session.findUnique({
      where: { secretHash: sha256(token) },
      include: { device: { select: { status: true } } },
    });
    if (session?.kind !== 'recovery' || session.revokedAt !== null)
      throw new ApiException('unauthenticated');
    if (session.device.status === 'revoked') throw new ApiException('device_revoked');
    if (session.absoluteExpiresAt <= now) throw new ApiException('session_expired');
    return {
      sessionId: session.id,
      accountId: session.accountId,
      deviceId: session.deviceId,
      deviceStatus: session.device.status,
      authAt: session.authAt,
    };
  }

  /** Creates a cookie session for a device and returns the raw token, which is never stored. */
  async create(
    accountId: string,
    deviceId: string,
    tx: Prisma.TransactionClient = this.prisma,
    now = new Date(),
  ): Promise<{ token: string; absoluteExpiresAt: Date }> {
    const token = randomToken();
    const absoluteExpiresAt = new Date(now.getTime() + SESSION_ABSOLUTE_MS);
    await tx.session.create({
      data: {
        id: randomUUID(),
        accountId,
        deviceId,
        kind: 'cookie',
        secretHash: sha256(token),
        authAt: now,
        createdAt: now,
        lastUsedAt: now,
        idleExpiresAt: new Date(now.getTime() + SESSION_IDLE_MS),
        absoluteExpiresAt,
      },
    });
    return { token, absoluteExpiresAt };
  }

  /**
   * A token session (authentication.md §5): `secret_hash` is the current access token's hash, and
   * the first refresh token of the family goes to `refresh_tokens`. Neither raw token is stored.
   */
  async createToken(
    accountId: string,
    deviceId: string,
    tx: Prisma.TransactionClient = this.prisma,
    now = new Date(),
  ): Promise<TokenPair> {
    const accessToken = randomToken();
    const refreshToken = randomToken();
    const accessExpiresAt = new Date(now.getTime() + ACCESS_TOKEN_MS);
    const sessionId = randomUUID();
    await tx.session.create({
      data: {
        id: sessionId,
        accountId,
        deviceId,
        kind: 'token',
        secretHash: sha256(accessToken),
        accessExpiresAt,
        authAt: now,
        createdAt: now,
        lastUsedAt: now,
        idleExpiresAt: new Date(now.getTime() + REFRESH_IDLE_MS),
        absoluteExpiresAt: new Date(now.getTime() + REFRESH_ABSOLUTE_MS),
      },
    });
    await tx.refreshToken.create({
      data: { tokenHash: sha256(refreshToken), sessionId, createdAt: now },
    });
    return { accessToken, refreshToken, accessExpiresAt: accessExpiresAt.toISOString() };
  }

  /**
   * Exchanges a refresh token once. A token that was already exchanged is a reuse: the whole
   * family (the session) is revoked and the caller learns only `unauthenticated`. The idle expiry
   * slides with each refresh, never past the absolute one.
   */
  async refresh(
    refreshToken: string,
    now = new Date(),
  ): Promise<
    { tokens: TokenPair } | { reused: { sessionId: string; accountId: string; deviceId: string } }
  > {
    if (!TOKEN_TEXT.test(refreshToken)) throw new ApiException('unauthenticated');
    return this.prisma.$transaction(async (tx) => {
      const row = await tx.refreshToken.findUnique({
        where: { tokenHash: sha256(refreshToken) },
        include: { session: { include: { device: { select: { status: true } } } } },
      });
      if (!row) throw new ApiException('unauthenticated');
      const session = row.session;
      if (session.kind !== 'token') throw new ApiException('unauthenticated');
      if (session.device.status === 'revoked') throw new ApiException('device_revoked');
      if (session.revokedAt !== null) throw new ApiException('unauthenticated');
      if (row.rotatedAt !== null) {
        await tx.session.update({
          where: { id: session.id },
          data: { revokedAt: now, revokeReason: 'refresh_reuse' },
        });
        return {
          reused: {
            sessionId: session.id,
            accountId: session.accountId,
            deviceId: session.deviceId,
          },
        };
      }
      if (session.idleExpiresAt <= now || session.absoluteExpiresAt <= now)
        throw new ApiException('session_expired');
      // Conditional on rotated_at still being null, so two concurrent refreshes cannot both win.
      const claimed = await tx.refreshToken.updateMany({
        where: { tokenHash: row.tokenHash, rotatedAt: null },
        data: { rotatedAt: now },
      });
      if (claimed.count !== 1) throw new ApiException('unauthenticated');
      const accessToken = randomToken();
      const next = randomToken();
      const accessExpiresAt = new Date(now.getTime() + ACCESS_TOKEN_MS);
      await tx.session.update({
        where: { id: session.id },
        data: {
          secretHash: sha256(accessToken),
          accessExpiresAt,
          lastUsedAt: now,
          idleExpiresAt: new Date(
            Math.min(now.getTime() + REFRESH_IDLE_MS, session.absoluteExpiresAt.getTime()),
          ),
        },
      });
      await tx.refreshToken.create({
        data: { tokenHash: sha256(next), sessionId: session.id, createdAt: now },
      });
      await tx.device.update({ where: { id: session.deviceId }, data: { lastSeenAt: now } });
      return {
        tokens: { accessToken, refreshToken: next, accessExpiresAt: accessExpiresAt.toISOString() },
      };
    });
  }

  /** `__Host-` cookie attributes of authentication.md §5; no `Domain`, `Path=/`. */
  setCookie(res: Response, token: string, absoluteExpiresAt: Date, now = new Date()): void {
    const maxAge = Math.max(0, Math.floor((absoluteExpiresAt.getTime() - now.getTime()) / 1000));
    res.append('Set-Cookie', this.cookie(token, maxAge));
  }

  clearCookie(res: Response): void {
    res.append('Set-Cookie', this.cookie('', 0));
  }

  private cookie(value: string, maxAge: number, name = this.cookieName): string {
    const parts = [
      `${name}=${value}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Strict',
      `Max-Age=${maxAge}`,
    ];
    if (this.secure) parts.push('Secure');
    return parts.join('; ');
  }

  /**
   * Resolves a cookie value to a live session, failing with the documented codes. Revocation is
   * checked on every request, and the idle expiry slides at most once a minute.
   */
  async authenticate(
    token: string | undefined,
    now = new Date(),
    kind: 'cookie' | 'token' = 'cookie',
  ): Promise<AuthenticatedSession> {
    if (token === undefined || !TOKEN_TEXT.test(token)) throw new ApiException('unauthenticated');
    const session = await this.prisma.session.findUnique({
      where: { secretHash: sha256(token) },
      include: { device: { select: { status: true } } },
    });
    // A cookie value is never accepted as a bearer token, nor the reverse.
    if (session?.kind !== kind) throw new ApiException('unauthenticated');
    if (session.device.status === 'revoked') throw new ApiException('device_revoked');
    if (session.revokedAt !== null) throw new ApiException('unauthenticated');
    if (session.idleExpiresAt <= now || session.absoluteExpiresAt <= now)
      throw new ApiException('session_expired');
    // A token session's access token expires on its own; the client refreshes it.
    if (kind === 'token' && (session.accessExpiresAt === null || session.accessExpiresAt <= now))
      throw new ApiException('session_expired');

    if (kind === 'token') {
      if (now.getTime() - session.lastUsedAt.getTime() >= TOUCH_INTERVAL_MS)
        await this.prisma.$transaction([
          this.prisma.session.update({ where: { id: session.id }, data: { lastUsedAt: now } }),
          this.prisma.device.update({ where: { id: session.deviceId }, data: { lastSeenAt: now } }),
        ]);
    } else if (now.getTime() - session.lastUsedAt.getTime() >= TOUCH_INTERVAL_MS) {
      const idle = new Date(
        Math.min(now.getTime() + SESSION_IDLE_MS, session.absoluteExpiresAt.getTime()),
      );
      await this.prisma.$transaction([
        this.prisma.session.update({
          where: { id: session.id },
          data: { lastUsedAt: now, idleExpiresAt: idle },
        }),
        this.prisma.device.update({ where: { id: session.deviceId }, data: { lastSeenAt: now } }),
      ]);
    }
    return {
      sessionId: session.id,
      accountId: session.accountId,
      deviceId: session.deviceId,
      deviceStatus: session.device.status,
      authAt: session.authAt,
    };
  }

  async revoke(sessionId: string, reason: RevokeReason, now = new Date()): Promise<void> {
    await this.prisma.session.updateMany({
      where: { id: sessionId, revokedAt: null },
      data: { revokedAt: now, revokeReason: reason },
    });
  }
}
