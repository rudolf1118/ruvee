import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../database/prisma.service.js';
import type { Prisma, SecurityEventType } from '../generated/prisma/client.js';

/**
 * Allow-listed `details` fields per event type (database-design.md §security_events, INV-12).
 * Values are ids and closed-set strings; request bodies, usernames and secrets never appear.
 */
const DETAIL_FIELDS: Readonly<Record<SecurityEventType, readonly string[]>> = {
  login_succeeded: ['newDevice'],
  login_failed: [],
  session_revoked: ['sessionId', 'reason'],
  refresh_reuse: ['sessionId'],
  password_changed: [],
  recovery_started: [],
  recovery_failed: [],
  recovery_completed: [],
  recovery_key_rotated: [],
  secret_key_rotated: [],
  device_pairing_requested: ['requesterDeviceId'],
  device_enrolled: ['enrolledDeviceId', 'via'],
  device_revoked: ['revokedDeviceId', 'reason'],
  pairing_mac_failed: ['requesterDeviceId'],
  vault_reset: [],
  bootstrap_used: [],
  bootstrap_failed: [],
  integrity_warning_reported: ['kind'],
};

const DETAIL_VALUE = /^[A-Za-z0-9_-]{1,64}$/;

export interface SecurityEventInput {
  readonly accountId?: string | null;
  readonly deviceId?: string | null;
  readonly ip?: string | undefined;
  readonly userAgent?: string | undefined;
  readonly details?: Readonly<Record<string, string | boolean>>;
}

/** Drops anything outside the allowlist, so a caller mistake cannot store request input. */
export function allowedDetails(
  type: SecurityEventType,
  details: Readonly<Record<string, string | boolean>> = {},
): Record<string, string | boolean> {
  const allowed = new Set(DETAIL_FIELDS[type]);
  const out: Record<string, string | boolean> = {};
  for (const [key, value] of Object.entries(details)) {
    if (!allowed.has(key)) continue;
    if (typeof value === 'boolean' || DETAIL_VALUE.test(value)) out[key] = value;
  }
  return out;
}

@Injectable()
export class SecurityEventsService {
  constructor(private readonly prisma: PrismaService) {}

  async record(
    type: SecurityEventType,
    input: SecurityEventInput = {},
    tx: Prisma.TransactionClient = this.prisma,
  ): Promise<void> {
    await tx.securityEvent.create({
      data: {
        id: randomUUID(),
        type,
        accountId: input.accountId ?? null,
        deviceId: input.deviceId ?? null,
        ip: input.ip ?? null,
        userAgent: input.userAgent ?? null,
        details: allowedDetails(type, input.details),
      },
    });
  }
}
