import { timingSafeEqual } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import {
  OPAQUE_CONFIG_ID,
  type ProofNonceOperation,
  type RecoveryCompleteRequest,
  type RecoveryMaterialResponse,
  type RecoveryStartRequest,
  type RecoveryStartResponse,
  type SessionResponse,
} from '@ruvee/contracts';
import type { ClientContext } from '../auth/auth.service.js';
import { OpaqueServerService } from '../auth/opaque-server.service.js';
import { ThrottleService } from '../auth/throttle.service.js';
import { ApiException } from '../common/api-exception.js';
import { envelopeHeaderOk, fromBase64url, sha256, toBase64url } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import { SecurityEventsService } from '../security-events/security-events.service.js';
import { proveCompletion } from '../sessions/completion-proof.js';
import { ProofService } from '../sessions/proof.service.js';
import { SessionService, type AuthenticatedSession } from '../sessions/session.service.js';

/** Compared against when the username is unknown, so both paths do the same work. */
const DUMMY_VERIFIER = new Uint8Array(32);

/**
 * Recovery with the Recovery Key (account-recovery.md §3). `RAK` proves possession of `RK`; the
 * server stores only `SHA-256(RAK)` and can decrypt nothing it is given. Every failure looks the
 * same (`401 recovery_failed`), whether the username exists or not.
 */
@Injectable()
export class RecoveryService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly opaque: OpaqueServerService,
    private readonly sessions: SessionService,
    private readonly throttle: ThrottleService,
    private readonly events: SecurityEventsService,
    private readonly proofs: ProofService,
  ) {}

  async start(
    body: RecoveryStartRequest,
    client: ClientContext,
  ): Promise<RecoveryStartResponse & { token: string; absoluteExpiresAt: Date }> {
    this.throttle.assertIpAllowed(client.ip);
    await this.throttle.reserveRecoveryAttempt(body.username);
    const account = await this.prisma.account.findUnique({
      where: { usernameNormalized: body.username },
      include: { accountKeys: { select: { recoveryVerifier: true } } },
    });
    const stored = account?.accountKeys?.recoveryVerifier ?? DUMMY_VERIFIER;
    const matches = timingSafeEqual(sha256(fromBase64url(body.recoveryAuthKey)), stored);
    if (!account?.accountKeys || !matches) {
      await this.events.record('recovery_failed', { accountId: account?.id ?? null, ...client });
      throw new ApiException('recovery_failed');
    }
    const accountId = account.id;
    const existing = await this.prisma.device.findUnique({ where: { id: body.device.id } });
    // A device of another account, or a revoked one, cannot recover (same generic failure).
    if (existing && (existing.accountId !== accountId || existing.status === 'revoked')) {
      await this.events.record('recovery_failed', { accountId, ...client });
      throw new ApiException('recovery_failed');
    }
    const now = new Date();
    const session = await this.prisma.$transaction(async (tx) => {
      if (!existing)
        await tx.device.create({
          data: {
            id: body.device.id,
            accountId,
            platform: body.device.platform,
            status: 'pending',
            createdAt: now,
            lastSeenAt: now,
          },
        });
      const created = await this.sessions.createRecovery(accountId, body.device.id, tx, now);
      // Raised now, not at completion: the material alone yields AK (V-07).
      await this.events.record(
        'recovery_started',
        { accountId, deviceId: body.device.id, ...client },
        tx,
      );
      return created;
    });
    return {
      accountId,
      deviceId: body.device.id,
      expiresAt: session.absoluteExpiresAt.toISOString(),
      ...session,
    };
  }

  async material(session: AuthenticatedSession): Promise<RecoveryMaterialResponse> {
    const keys = await this.prisma.accountKeys.findUnique({
      where: { accountId: session.accountId },
    });
    if (!keys) throw new ApiException('recovery_failed');
    return {
      accountId: session.accountId,
      recoveryKeyId: toBase64url(keys.recoveryKeyId),
      wrappedAkRecovery: toBase64url(keys.wrappedAkRecovery),
      akId: toBase64url(keys.akId),
      akEpoch: keys.akEpoch,
      keysetVersion: Number(keys.keysetVersion),
      keyset: toBase64url(keys.keyset),
      rowVersion: Number(keys.rowVersion),
    };
  }

  /** A nonce for `recovery_complete`, bound to this recovery session (device-proof.md §6). */
  proofNonce(session: AuthenticatedSession, operation: ProofNonceOperation) {
    if (operation !== 'recovery_complete') throw new ApiException('forbidden');
    return this.proofs.issue(session, operation);
  }

  async passwordStart(session: AuthenticatedSession, registrationRequest: string): Promise<string> {
    const account = await this.prisma.account.findUniqueOrThrow({
      where: { id: session.accountId },
    });
    try {
      return this.opaque.createRegistrationResponse(
        account.usernameNormalized,
        registrationRequest,
      );
    } catch {
      throw new ApiException('invalid_request');
    }
  }

  /**
   * One transaction (§3 step 6): new OPAQUE record, password wrap, rotated recovery wrap and
   * verifier (the old wrap is overwritten), every other session ended, this device active.
   */
  async complete(
    session: AuthenticatedSession,
    body: RecoveryCompleteRequest,
    client: ClientContext,
  ): Promise<SessionResponse & { token: string; absoluteExpiresAt: Date }> {
    const keys = await this.prisma.accountKeys.findUniqueOrThrow({
      where: { accountId: session.accountId },
    });
    const recoveryKeyId = fromBase64url(body.recoveryKeyId);
    const wrappedAkPassword = fromBase64url(body.wrappedAkPassword);
    const wrappedAkRecovery = fromBase64url(body.wrappedAkRecovery);
    const label = body.label === undefined ? null : fromBase64url(body.label);
    if (
      !envelopeHeaderOk(wrappedAkPassword, 0x01, { min: 93, max: 93 }, keys.akId) ||
      !envelopeHeaderOk(wrappedAkRecovery, 0x02, { min: 93, max: 93 }, recoveryKeyId) ||
      (label !== null && !envelopeHeaderOk(label, 0x08, { min: 61, max: 189 })) ||
      // The Recovery Key was typed into this device: rotating it is mandatory (§3 step 5).
      Buffer.compare(recoveryKeyId, keys.recoveryKeyId) === 0
    )
      throw new ApiException('invalid_request');
    // device-proof.md §8: the recovering device's new key proves itself, and AK is proved.
    const proof = await proveCompletion(
      this.proofs,
      'recovery_complete',
      session,
      body,
      keys,
      fromBase64url(body.devicePublicKey),
    );
    const now = new Date();
    const result = await this.prisma.$transaction(async (tx) => {
      await this.proofs.consume(tx, session.sessionId, 'recovery_complete', proof.nonce);
      const updated = await tx.accountKeys.updateMany({
        where: { accountId: session.accountId, rowVersion: BigInt(body.expectedRowVersion) },
        data: {
          kdfProfile: body.kdfProfile,
          saltPw: fromBase64url(body.saltPw),
          wrappedAkPassword,
          recoveryKeyId,
          wrappedAkRecovery,
          recoveryVerifier: fromBase64url(body.recoveryVerifier),
          akVerifyKey: proof.akVerifyKey,
          rowVersion: { increment: 1 },
          updatedAt: now,
        },
      });
      if (updated.count !== 1) throw new ApiException('row_version_conflict');
      await tx.opaqueCredential.update({
        where: { accountId: session.accountId },
        data: {
          registrationRecord: fromBase64url(body.registrationRecord),
          configId: OPAQUE_CONFIG_ID,
          updatedAt: now,
        },
      });
      await tx.session.updateMany({
        where: { accountId: session.accountId, revokedAt: null },
        data: { revokedAt: now, revokeReason: 'recovery' },
      });
      await tx.device.update({
        where: { id: session.deviceId },
        data: {
          status: 'active',
          enrolledVia: 'recovery',
          enrolledAt: now,
          lastSeenAt: now,
          publicKey: proof.devicePublicKey,
          ...(label === null ? {} : { label }),
        },
      });
      const created = await this.sessions.create(
        session.accountId,
        session.deviceId,
        tx,
        now,
        true,
      );
      const context = { accountId: session.accountId, deviceId: session.deviceId, ...client };
      await this.events.record('recovery_completed', context, tx);
      await this.events.record('recovery_key_rotated', context, tx);
      return created;
    });
    const account = await this.prisma.account.findUniqueOrThrow({
      where: { id: session.accountId },
    });
    await this.throttle.resetRecovery(account.usernameNormalized);
    return {
      accountId: session.accountId,
      device: { id: session.deviceId, status: 'active' },
      proven: true,
      ...result,
    };
  }
}
