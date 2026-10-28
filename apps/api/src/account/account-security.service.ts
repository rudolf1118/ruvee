import { Injectable } from '@nestjs/common';
import {
  OPAQUE_CONFIG_ID,
  type PasswordChangeFinishRequest,
  type RevokeDeviceRequest,
  type RecoveryKeyRotateRequest,
  type SecretKeyRotateRequest,
  type SecurityEventsResponse,
  type SessionsResponse,
} from '@ruvee/contracts';
import type { ClientContext } from '../auth/auth.service.js';
import { OpaqueServerService } from '../auth/opaque-server.service.js';
import { ApiException } from '../common/api-exception.js';
import { envelopeHeaderOk, fromBase64url } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import {
  allowedDetails,
  SecurityEventsService,
} from '../security-events/security-events.service.js';
import { uuidToBytes, type ProofField, type ProofOperation } from '@ruvee/crypto';
import { ProofService } from '../sessions/proof.service.js';
import type { AuthenticatedSession } from '../sessions/session.service.js';
import type { Bytes } from '../common/secrets.js';

/** Sessions, device revocation (device-enrollment §6) and password change (authentication §9). */
/** Tier 3+ of device-proof.md §7: operations that replace key material prove AK as well. */
const NEEDS_ACCOUNT_KEY_PROOF: ReadonlySet<ProofOperation> = new Set([
  'password_change_v2',
  'secret_key_rotate',
  'recovery_key_rotate',
]);

@Injectable()
export class AccountSecurityService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly opaque: OpaqueServerService,
    private readonly events: SecurityEventsService,
    private readonly proofs: ProofService,
  ) {}

  /**
   * device-proof.md §7, tiers 3: the device's own `DSK` proof, and for key replacement an `AVSK`
   * proof, over this operation's exact payload and a nonce of this session. Checked before
   * anything changes; the caller consumes the returned nonce inside its transaction.
   */
  private async prove(
    session: AuthenticatedSession,
    operation: ProofOperation,
    body: { nonce: string; proof: { device: string; accountKey?: string } },
    fields: readonly ProofField[],
  ): Promise<Bytes> {
    const [device, keys] = await Promise.all([
      this.prisma.device.findUniqueOrThrow({ where: { id: session.deviceId } }),
      this.prisma.accountKeys.findUniqueOrThrow({ where: { accountId: session.accountId } }),
    ]);
    const nonce = fromBase64url(body.nonce);
    // device-proof.md §7: which operations also need AK's proof is fixed here, by operation,
    // never inferred from what the request happens to carry.
    const wantsAccountKey = NEEDS_ACCOUNT_KEY_PROOF.has(operation);
    if (
      !device.publicKey ||
      (wantsAccountKey && (!keys.akVerifyKey || body.proof.accountKey === undefined))
    )
      throw new ApiException('device_proof_failed');
    await this.proofs.verifyBound(
      {
        operation,
        accountId: session.accountId,
        deviceId: session.deviceId,
        binding: this.proofs.sessionRef(session.sessionId),
        nonce,
        payload: this.proofs.payload(operation, fields),
        device: { publicKey: device.publicKey, signature: fromBase64url(body.proof.device) },
        ...(wantsAccountKey && keys.akVerifyKey
          ? {
              accountKey: {
                akId: keys.akId,
                akEpoch: keys.akEpoch,
                publicKey: keys.akVerifyKey,
                signature: fromBase64url(body.proof.accountKey ?? ''),
              },
            }
          : {}),
      },
      session.sessionId,
    );
    return nonce;
  }

  async sessions(session: AuthenticatedSession): Promise<SessionsResponse> {
    const now = new Date();
    const rows = await this.prisma.session.findMany({
      where: {
        accountId: session.accountId,
        // Reopen sessions exist only while the installation is closed, and are never listed.
        kind: { in: ['cookie', 'token', 'recovery'] },
        revokedAt: null,
        idleExpiresAt: { gt: now },
        absoluteExpiresAt: { gt: now },
      },
      orderBy: { lastUsedAt: 'desc' },
      take: 1000,
    });
    return {
      sessions: rows.map((r) => ({
        id: r.id,
        deviceId: r.deviceId,
        kind: r.kind as 'cookie' | 'token' | 'recovery',
        current: r.id === session.sessionId,
        createdAt: r.createdAt.toISOString(),
        lastUsedAt: r.lastUsedAt.toISOString(),
        idleExpiresAt: r.idleExpiresAt.toISOString(),
        absoluteExpiresAt: r.absoluteExpiresAt.toISOString(),
      })),
    };
  }

  async endSession(
    session: AuthenticatedSession,
    sessionId: string,
    client: ClientContext,
  ): Promise<void> {
    // A recovery session is never ended from here: a stolen session could otherwise end every
    // recovery the owner starts (follow-up review F-1). A new Recovery Kit ends it, with a proof.
    const updated = await this.prisma.session.updateMany({
      where: {
        id: sessionId,
        accountId: session.accountId,
        kind: { in: ['cookie', 'token'] },
        revokedAt: null,
      },
      data: { revokedAt: new Date(), revokeReason: 'user' },
    });
    if (updated.count !== 1) {
      const recovery = await this.prisma.session.count({
        where: { id: sessionId, accountId: session.accountId, kind: 'recovery' },
      });
      throw new ApiException(recovery > 0 ? 'forbidden' : 'not_found');
    }
    await this.events.record('session_revoked', {
      accountId: session.accountId,
      deviceId: session.deviceId,
      ...client,
      details: { sessionId, reason: 'user' },
    });
  }

  /**
   * device-enrollment §6 step 1: the device is revoked, every session of it ends at once, and its
   * pairings are cancelled. The caller cannot revoke itself; it logs out instead.
   */
  async revokeDevice(
    session: AuthenticatedSession,
    deviceId: string,
    body: RevokeDeviceRequest,
    client: ClientContext,
  ): Promise<void> {
    if (deviceId === session.deviceId) throw new ApiException('forbidden');
    const reason = body.reason;
    const nonce = await this.prove(session, 'device_revoke', body, [
      uuidToBytes(deviceId),
      { text: reason },
    ]);
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      await this.proofs.consume(tx, session.sessionId, 'device_revoke', nonce);
      const updated = await tx.device.updateMany({
        where: { id: deviceId, accountId: session.accountId, status: { not: 'revoked' } },
        data: { status: 'revoked', revokedAt: now },
      });
      if (updated.count !== 1) throw new ApiException('not_found');
      await tx.session.updateMany({
        where: { deviceId, revokedAt: null },
        data: { revokedAt: now, revokeReason: 'device_revoked' },
      });
      await tx.pairing.deleteMany({
        where: { OR: [{ initiatorDeviceId: deviceId }, { requesterDeviceId: deviceId }] },
      });
      await this.events.record(
        'device_revoked',
        {
          accountId: session.accountId,
          deviceId: session.deviceId,
          ...client,
          details: { revokedDeviceId: deviceId, reason },
        },
        tx,
      );
    });
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
   * authentication.md §9 step 3: the OPAQUE record and the password wrap change together under
   * `row_version`; every other session ends; this one continues.
   *
   * Follow-up review F-4: the request names, and both proofs sign, the keyset version whose `SK`
   * the client says it derived the new wrap with. The update applies only while that is still the
   * account's version, in the same statement as the `row_version` check, so a client that has not
   * adopted a replaced `SK` cannot install a wrap under the old one by mistake. The server cannot
   * open the wrap: a client holding `AK` and a device key can still claim the current version
   * over a wrap made with an old `SK` (device-proof.md §3). This stops stale writes, not a
   * malicious device.
   */
  async passwordFinish(
    session: AuthenticatedSession,
    body: PasswordChangeFinishRequest,
    client: ClientContext,
  ): Promise<void> {
    const keys = await this.prisma.accountKeys.findUniqueOrThrow({
      where: { accountId: session.accountId },
    });
    const wrappedAkPassword = fromBase64url(body.wrappedAkPassword);
    if (!envelopeHeaderOk(wrappedAkPassword, 0x01, { min: 93, max: 93 }, keys.akId))
      throw new ApiException('invalid_request');
    const nonce = await this.prove(session, 'password_change_v2', body, [
      fromBase64url(body.registrationRecord),
      { u8: body.kdfProfile },
      fromBase64url(body.saltPw),
      wrappedAkPassword,
      { u64: body.expectedRowVersion },
      { u32: body.keysetVersion },
    ]);
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      await this.proofs.consume(tx, session.sessionId, 'password_change_v2', nonce);
      // A conflict rolls back the whole transaction, the nonce's consumption included. The open
      // nonce then authorizes only this exact payload, which stays stale: row_version and
      // keyset_version only grow, and a restore deletes every nonce (device-proof.md §6, §10;
      // follow-up review S-4, which stays open for the other operations).
      const updated = await tx.accountKeys.updateMany({
        where: {
          accountId: session.accountId,
          rowVersion: BigInt(body.expectedRowVersion),
          keysetVersion: BigInt(body.keysetVersion),
        },
        data: {
          kdfProfile: body.kdfProfile,
          saltPw: fromBase64url(body.saltPw),
          wrappedAkPassword,
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
        where: { accountId: session.accountId, revokedAt: null, id: { not: session.sessionId } },
        data: { revokedAt: now, revokeReason: 'password_changed' },
      });
      await this.events.record(
        'password_changed',
        { accountId: session.accountId, deviceId: session.deviceId, ...client },
        tx,
      );
    });
  }

  /**
   * D-24 and cryptographic-design §6.2. The server checks only what it can: the envelope headers
   * and that the keyset version is exactly the next one (INV-09); it cannot open either envelope.
   */
  async rotateSecretKey(
    session: AuthenticatedSession,
    body: SecretKeyRotateRequest,
    client: ClientContext,
  ): Promise<void> {
    const keys = await this.prisma.accountKeys.findUniqueOrThrow({
      where: { accountId: session.accountId },
    });
    // A concurrent change elsewhere (another rotation, a password change) is a conflict first.
    if (BigInt(body.expectedRowVersion) !== keys.rowVersion)
      throw new ApiException('row_version_conflict');
    const keyset = fromBase64url(body.keyset);
    const wrappedAkPassword = fromBase64url(body.wrappedAkPassword);
    if (
      !envelopeHeaderOk(keyset, 0x03, { min: 61, max: 16_445 }, keys.akId) ||
      !envelopeHeaderOk(wrappedAkPassword, 0x01, { min: 93, max: 93 }, keys.akId) ||
      BigInt(body.keysetVersion) !== keys.keysetVersion + 1n
    )
      throw new ApiException('invalid_request');
    const nonce = await this.prove(session, 'secret_key_rotate', body, [
      { u32: body.keysetVersion },
      keyset,
      { u8: body.kdfProfile },
      fromBase64url(body.saltPw),
      wrappedAkPassword,
      { u64: body.expectedRowVersion },
    ]);
    await this.prisma.$transaction(async (tx) => {
      await this.proofs.consume(tx, session.sessionId, 'secret_key_rotate', nonce);
      const updated = await tx.accountKeys.updateMany({
        where: {
          accountId: session.accountId,
          rowVersion: BigInt(body.expectedRowVersion),
          keysetVersion: keys.keysetVersion,
        },
        data: {
          keysetVersion: BigInt(body.keysetVersion),
          keyset,
          kdfProfile: body.kdfProfile,
          saltPw: fromBase64url(body.saltPw),
          wrappedAkPassword,
          rowVersion: { increment: 1 },
          updatedAt: new Date(),
        },
      });
      if (updated.count !== 1) throw new ApiException('row_version_conflict');
      await this.events.record(
        'secret_key_rotated',
        { accountId: session.accountId, deviceId: session.deviceId, ...client },
        tx,
      );
    });
  }

  /**
   * account-recovery.md §5. The old wrap and verifier are replaced in one transaction, so the old
   * kit stops working against this server. Unfinished recovery sessions end too, so a recovery
   * started with the old kit cannot complete. Backups taken earlier still hold the old wrap.
   */
  async rotateRecoveryKey(
    session: AuthenticatedSession,
    body: RecoveryKeyRotateRequest,
    client: ClientContext,
  ): Promise<void> {
    const keys = await this.prisma.accountKeys.findUniqueOrThrow({
      where: { accountId: session.accountId },
    });
    if (BigInt(body.expectedRowVersion) !== keys.rowVersion)
      throw new ApiException('row_version_conflict');
    const recoveryKeyId = fromBase64url(body.recoveryKeyId);
    const wrappedAkRecovery = fromBase64url(body.wrappedAkRecovery);
    if (
      !envelopeHeaderOk(wrappedAkRecovery, 0x02, { min: 93, max: 93 }, recoveryKeyId) ||
      Buffer.compare(recoveryKeyId, keys.recoveryKeyId) === 0
    )
      throw new ApiException('invalid_request');
    const recoveryVerifier = fromBase64url(body.recoveryVerifier);
    const nonce = await this.prove(session, 'recovery_key_rotate', body, [
      recoveryKeyId,
      wrappedAkRecovery,
      recoveryVerifier,
      { u64: body.expectedRowVersion },
    ]);
    const now = new Date();
    await this.prisma.$transaction(async (tx) => {
      await this.proofs.consume(tx, session.sessionId, 'recovery_key_rotate', nonce);
      const updated = await tx.accountKeys.updateMany({
        where: { accountId: session.accountId, rowVersion: keys.rowVersion },
        data: {
          recoveryKeyId,
          wrappedAkRecovery,
          recoveryVerifier,
          rowVersion: { increment: 1 },
          updatedAt: now,
        },
      });
      if (updated.count !== 1) throw new ApiException('row_version_conflict');
      await tx.session.updateMany({
        where: { accountId: session.accountId, kind: 'recovery', revokedAt: null },
        data: { revokedAt: now, revokeReason: 'user' },
      });
      await this.events.record(
        'recovery_key_rotated',
        { accountId: session.accountId, deviceId: session.deviceId, ...client },
        tx,
      );
    });
  }

  /** The activity screen (P2-15): newest first, 50 per page, keyset pagination. */
  async activity(session: AuthenticatedSession, cursor?: string): Promise<SecurityEventsResponse> {
    let before: { at: Date; id: string } | undefined;
    if (cursor !== undefined) {
      const [ms = '', id = ''] = cursor.split('.');
      before = { at: new Date(Number(ms)), id };
    }
    const rows = await this.prisma.securityEvent.findMany({
      where: {
        accountId: session.accountId,
        ...(before
          ? {
              OR: [
                { createdAt: { lt: before.at } },
                { createdAt: before.at, id: { lt: before.id } },
              ],
            }
          : {}),
      },
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: 51,
    });
    const page = rows.slice(0, 50);
    const last = page.at(-1);
    return {
      events: page.map((row) => ({
        id: row.id,
        type: row.type,
        deviceId: row.deviceId,
        ip: row.ip,
        userAgent: row.userAgent,
        // Re-filtered on the way out too: only allow-listed fields ever leave (INV-12).
        details: allowedDetails(
          row.type,
          typeof row.details === 'object' && row.details !== null && !Array.isArray(row.details)
            ? (row.details as Record<string, string | boolean>)
            : {},
        ),
        createdAt: row.createdAt.toISOString(),
      })),
      nextCursor:
        rows.length > 50 && last ? `${String(last.createdAt.getTime())}.${last.id}` : null,
    };
  }
}
