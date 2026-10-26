import { Controller, Get } from '@nestjs/common';
import type {
  AccountKeysResponse,
  AccountResponse,
  Device,
  DevicesResponse,
} from '@ruvee/contracts';
import { ApiException } from '../common/api-exception.js';
import { toBase64url } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import type { Device as DeviceRow } from '../generated/prisma/client.js';
import { Access, CurrentSession } from '../sessions/access.decorator.js';
import type { AuthenticatedSession } from '../sessions/session.service.js';

const iso = (date: Date) => date.toISOString();
const isoOrNull = (date: Date | null) => (date === null ? null : date.toISOString());

export function toDevice(row: DeviceRow): Device {
  return {
    id: row.id,
    platform: row.platform,
    status: row.status,
    enrolledVia: row.enrolledVia,
    label: row.label === null ? null : toBase64url(row.label),
    createdAt: iso(row.createdAt),
    enrolledAt: isoOrNull(row.enrolledAt),
    lastSeenAt: isoOrNull(row.lastSeenAt),
    revokedAt: isoOrNull(row.revokedAt),
  };
}

@Controller('api/v1')
export class AccountController {
  constructor(private readonly prisma: PrismaService) {}

  @Get('account')
  @Access('session')
  async account(@CurrentSession() session: AuthenticatedSession): Promise<AccountResponse> {
    const account = await this.prisma.account.findUnique({
      where: { id: session.accountId },
      include: { opaqueCredential: { select: { updatedAt: true } } },
    });
    if (!account?.opaqueCredential) throw new ApiException('unauthenticated');
    // Every device shows when the Recovery Kit was last used (account-recovery.md §3 step 2).
    const recovery = await this.prisma.securityEvent.findFirst({
      where: { accountId: account.id, type: 'recovery_started' },
      orderBy: { createdAt: 'desc' },
      select: { createdAt: true },
    });
    // The latest restore of this server, for clients' wording only (backup-restore.md §3.6).
    const restore = await this.prisma.securityEvent.findFirst({
      where: { type: 'server_restored' },
      orderBy: { createdAt: 'desc' },
      select: { createdAt: true, details: true },
    });
    const restoreId = (restore?.details as { restoreId?: unknown } | undefined)?.restoreId;
    return {
      accountId: account.id,
      username: account.usernameNormalized,
      createdAt: iso(account.createdAt),
      passwordChangedAt: iso(account.opaqueCredential.updatedAt),
      lastRecoveryAt: recovery ? iso(recovery.createdAt) : null,
      lastRestore:
        restore && typeof restoreId === 'string'
          ? { restoredAt: iso(restore.createdAt), restoreId }
          : null,
    };
  }

  /** The password wrap and keyset for unlocking; the recovery wrap is never returned here. */
  @Get('account/keys')
  @Access('active')
  async keys(@CurrentSession() session: AuthenticatedSession): Promise<AccountKeysResponse> {
    const keys = await this.prisma.accountKeys.findUnique({
      where: { accountId: session.accountId },
    });
    if (!keys) throw new ApiException('not_found');
    return {
      kdfProfile: keys.kdfProfile as 1,
      saltPw: toBase64url(keys.saltPw),
      akId: toBase64url(keys.akId),
      akEpoch: keys.akEpoch,
      wrappedAkPassword: toBase64url(keys.wrappedAkPassword),
      keysetVersion: Number(keys.keysetVersion),
      keyset: toBase64url(keys.keyset),
      rowVersion: Number(keys.rowVersion),
    };
  }

  /** The calling device; a pending device polls this while it waits to be enrolled. */
  @Get('devices/current')
  @Access('session')
  async currentDevice(@CurrentSession() session: AuthenticatedSession): Promise<Device> {
    const device = await this.prisma.device.findUniqueOrThrow({ where: { id: session.deviceId } });
    return toDevice(device);
  }

  @Get('devices')
  @Access('active')
  async devices(@CurrentSession() session: AuthenticatedSession): Promise<DevicesResponse> {
    const rows = await this.prisma.device.findMany({
      where: { accountId: session.accountId },
      orderBy: { createdAt: 'asc' },
      take: 1000,
    });
    return { devices: rows.map(toDevice) };
  }
}
