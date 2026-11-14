import { randomBytes } from 'node:crypto';
import { Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import {
  RELOAD_TICKET_HEARTBEAT_TTL_MS,
  type ReloadTicketCreateResponse,
  type ReloadTicketRedeemResponse,
} from '@ruvee/contracts';
import { initRuveeCrypto, uuidToBytes, type RuveeCrypto } from '@ruvee/crypto';
import { OpaqueServerService } from '../auth/opaque-server.service.js';
import { ApiException } from '../common/api-exception.js';
import { fromBase64url, sha256, toBase64url } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import type { AuthenticatedSession } from '../sessions/session.service.js';

const TICKET_ID_BYTES = 16;

/**
 * The server side of web reload tickets (D-34, docs/security/web-reload-unlock.md §5, INV-25).
 *
 * A row holds only `SHA-256(tid)`, the session, device and account it belongs to, and its two
 * limits: 3 minutes after the last heartbeat, and the auto-lock period after the last activity.
 * The server half `H_srv` is never stored: it is recomputed from `K_srv` (a key of the OPAQUE setup
 * file, which is not in the database or its backups), `tid`, the session and the device. So the
 * table, a dump of it, or the tab's copy of `tid` do not give `H_srv`; the live server gives it once
 * through `redeem`, and only to the ticket's own session, which the access guard has already found
 * live, not revoked, of an active device, and proven (INV-24).
 *
 * Only web cookie sessions get tickets; one per session, replaced by the next. A ticket of a
 * session revoked elsewhere is unusable at once (its session can never authenticate again), and its
 * row is removed at the next ticket write or by `SessionService.revoke`.
 */
@Injectable()
export class ReloadTicketsService implements OnModuleInit, OnModuleDestroy {
  private crypto: RuveeCrypto | undefined;
  /** `K_srv`, derived once from the setup; wiped when the module stops. */
  private key: Uint8Array | undefined;

  constructor(
    private readonly prisma: PrismaService,
    private readonly opaque: OpaqueServerService,
  ) {}

  async onModuleInit(): Promise<void> {
    this.crypto = await initRuveeCrypto();
  }

  onModuleDestroy(): void {
    this.key?.fill(0);
    this.key = undefined;
  }

  private serverHalf(ticketId: Uint8Array, sessionId: string, deviceId: string): string {
    if (!this.crypto) throw new Error('reload-ticket crypto not loaded');
    if (!this.key) {
      const setup = this.opaque.setupBytes();
      try {
        this.key = this.crypto.deriveReloadServerKey(setup);
      } finally {
        setup.fill(0);
      }
    }
    const half = this.crypto.reloadServerHalf({
      serverKey: this.key,
      ticketId,
      sessionId: uuidToBytes(sessionId),
      deviceId: uuidToBytes(deviceId),
    });
    try {
      return toBase64url(half);
    } finally {
      half.fill(0);
    }
  }

  /** Removes ended tickets: past either limit, or of a session that was revoked or has expired. */
  private async prune(now: Date): Promise<void> {
    await this.prisma.$executeRaw`
      DELETE FROM reload_tickets t USING sessions s
      WHERE s.id = t.session_id
        AND (t.expires_at <= ${now} OR t.idle_expires_at <= ${now} OR s.revoked_at IS NOT NULL
             OR s.idle_expires_at <= ${now} OR s.absolute_expires_at <= ${now})`;
  }

  async create(
    session: AuthenticatedSession,
    idleSeconds: number,
    now = new Date(),
  ): Promise<ReloadTicketCreateResponse> {
    const row = await this.prisma.session.findUnique({
      where: { id: session.sessionId },
      select: { kind: true, device: { select: { platform: true } } },
    });
    // The web app only: the extension keeps AK in chrome.storage.session instead (D-27).
    if (row?.kind !== 'cookie' || row.device.platform !== 'web' || !session.proven)
      throw new ApiException('forbidden');
    await this.prune(now);
    const ticketId = randomBytes(TICKET_ID_BYTES);
    const data = {
      idHash: Buffer.from(sha256(ticketId)),
      accountId: session.accountId,
      deviceId: session.deviceId,
      idleSeconds,
      createdAt: now,
      expiresAt: new Date(now.getTime() + RELOAD_TICKET_HEARTBEAT_TTL_MS),
      idleExpiresAt: new Date(now.getTime() + idleSeconds * 1000),
    };
    await this.prisma.$transaction([
      this.prisma.reloadTicket.deleteMany({ where: { sessionId: session.sessionId } }),
      this.prisma.reloadTicket.create({ data: { ...data, sessionId: session.sessionId } }),
    ]);
    const response = {
      ticketId: ticketId.toString('base64url'),
      serverHalf: this.serverHalf(ticketId, session.sessionId, session.deviceId),
    };
    ticketId.fill(0);
    return response;
  }

  /**
   * Moves the heartbeat limit, and the idle limit when the user was active. Bound to the session and
   * its device like redeem, so a row naming another device is neither moved nor removed.
   */
  async heartbeat(
    session: AuthenticatedSession,
    ticketId: string,
    active: boolean,
    now = new Date(),
  ): Promise<void> {
    const idHash = Buffer.from(sha256(fromBase64url(ticketId)));
    const expiresAt = new Date(now.getTime() + RELOAD_TICKET_HEARTBEAT_TTL_MS);
    const updated = await this.prisma.$executeRaw`
      UPDATE reload_tickets
      SET expires_at = ${expiresAt},
          idle_expires_at = CASE WHEN ${active}
            THEN ${now}::timestamptz(3) + make_interval(secs => idle_seconds)
            ELSE idle_expires_at END
      WHERE id_hash = ${idHash} AND session_id = ${session.sessionId}::uuid
        AND device_id = ${session.deviceId}::uuid
        AND expires_at > ${now} AND idle_expires_at > ${now}`;
    if (updated !== 1) {
      await this.prisma.reloadTicket.deleteMany({
        where: { idHash, sessionId: session.sessionId, deviceId: session.deviceId },
      });
      throw new ApiException('not_found');
    }
  }

  /**
   * Single use (INV-25): one statement deletes the row and returns it, so two concurrent redeems
   * give one success. Another session's ticket is neither returned nor removed.
   */
  async redeem(
    session: AuthenticatedSession,
    ticketId: string,
    now = new Date(),
  ): Promise<ReloadTicketRedeemResponse> {
    const id = fromBase64url(ticketId);
    const idHash = Buffer.from(sha256(id));
    const [row] = await this.prisma.$queryRaw<{ expires_at: Date; idle_expires_at: Date }[]>`
      DELETE FROM reload_tickets
      WHERE id_hash = ${idHash} AND session_id = ${session.sessionId}::uuid
        AND device_id = ${session.deviceId}::uuid
      RETURNING expires_at, idle_expires_at`;
    if (!row || row.expires_at <= now || row.idle_expires_at <= now)
      throw new ApiException('not_found');
    return { serverHalf: this.serverHalf(id, session.sessionId, session.deviceId) };
  }

  async remove(session: AuthenticatedSession): Promise<void> {
    await this.prisma.reloadTicket.deleteMany({ where: { sessionId: session.sessionId } });
  }
}
