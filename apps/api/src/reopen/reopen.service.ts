import { timingSafeEqual } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import {
  OPAQUE_CONFIG_ID,
  type LoginFinishRequest,
  type LoginStartResponse,
  type ProofNonceOperation,
  type RecoveryCompleteRequest,
  type ReopenLoginStartRequest,
  type ReopenMaterialResponse,
  type ReopenRecoveryStartRequest,
  type ReopenStartResponse,
  type SessionResponse,
} from '@ruvee/contracts';
import type { ClientContext } from '../auth/auth.service.js';
import { LoginStateStore } from '../auth/login-state.store.js';
import { OpaqueServerService } from '../auth/opaque-server.service.js';
import { ThrottleService } from '../auth/throttle.service.js';
import { ApiException } from '../common/api-exception.js';
import {
  constantTimeEqual,
  envelopeHeaderOk,
  fromBase64url,
  sha256,
  toBase64url,
} from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import type { Prisma } from '../generated/prisma/client.js';
import { MaintenanceService } from '../maintenance/maintenance.service.js';
import { SecurityEventsService } from '../security-events/security-events.service.js';
import { proveCompletion } from '../sessions/completion-proof.js';
import { ProofService } from '../sessions/proof.service.js';
import { SessionService, type AuthenticatedSession } from '../sessions/session.service.js';
import { reopenCodeHash } from './reopen-codes.js';

/** Compared against when the username is unknown, so both paths do the same work. */
const DUMMY_VERIFIER = new Uint8Array(32);

interface CodeRow {
  code_id: string;
  restore_id: string;
  account_id: string;
}

type NewReopen = ReopenStartResponse & { token: string; absoluteExpiresAt: Date };

/**
 * Reopening a restored installation (backup-restore.md §3.13, D-30 option B). The host-issued
 * code authenticates **who may reopen**; the snapshot-time password (from a device that holds
 * `SK`) or Recovery Key authenticates **the account**, and is also what decrypts: the code alone
 * opens nothing. Every failure is `401 reopen_failed`. The code is consumed only in the
 * transaction that creates the one reopen session, after the credentials verified.
 *
 * Two kinds of failure are kept apart (review R11). A wrong, malformed, expired or used code
 * proves nothing about any real code: it is limited per client address and never counts against
 * the usable code, so nobody can use that code up without holding it. Wrong credentials (or
 * another account or device) presented **with** the usable code count on that code, and five
 * revoke it. The owner's recovery budget is charged only once the code is right.
 *
 * The codes and the guard belong to the operator role (F-25): this service reads and changes them
 * only through the `ruvee_control.reopen_*` functions (admin/reopen-functions.ts), each of which
 * checks the persisted state itself.
 */
@Injectable()
export class ReopenService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly opaque: OpaqueServerService,
    private readonly sessions: SessionService,
    private readonly loginStates: LoginStateStore,
    private readonly throttle: ThrottleService,
    private readonly events: SecurityEventsService,
    private readonly maintenance: MaintenanceService,
    private readonly proofs: ProofService,
  ) {}

  /** A nonce for `reopen_complete`, bound to this reopen session (device-proof.md §6). */
  proofNonce(session: AuthenticatedSession, operation: ProofNonceOperation) {
    if (operation !== 'reopen_complete') throw new ApiException('forbidden');
    return this.proofs.issue(session, operation);
  }

  /** The usable code with this value, while reopening; or undefined. Never consumes it. */
  private async usableCode(reopenCode: string): Promise<CodeRow | undefined> {
    if ((await this.maintenance.state()) !== 'reopening') return undefined;
    const hash = reopenCodeHash(reopenCode);
    if (!hash) return undefined;
    const [row] = await this.prisma.$queryRaw<CodeRow[]>`
      SELECT code_id, restore_id, account_id FROM ruvee_control.reopen_code_find(${hash})`;
    return row;
  }

  /**
   * The usable code, or a refusal for a wrong one. Addresses that sent too many wrong codes are
   * refused before any lookup; a wrong code is counted against its address only.
   */
  private async presentedCode(reopenCode: string, client: ClientContext): Promise<CodeRow> {
    this.throttle.assertReopenCodeGuessesAllowed(client.ip);
    const code = await this.usableCode(reopenCode);
    if (code) return code;
    this.throttle.recordWrongReopenCode(client.ip);
    if ((await this.maintenance.state()) === 'reopening')
      await this.events.record('reopen_failed', {
        accountId: null,
        ...client,
        details: { reason: 'code' },
      });
    throw new ApiException('reopen_failed');
  }

  /**
   * Failed credentials presented with the usable code: counted on that code, and a code reaching
   * the limit is revoked. The operator then issues a new one on the host.
   */
  private async fail(client: ClientContext, codeId: string, accountId: string): Promise<never> {
    await this.prisma.$executeRaw`SELECT ruvee_control.reopen_code_failed(${codeId}::uuid)`;
    await this.events.record('reopen_failed', {
      accountId,
      ...client,
      details: { reason: 'credentials' },
    });
    throw new ApiException('reopen_failed');
  }

  /**
   * Creates the one reopen session and consumes the code for it, in one transaction. The function
   * locks the guard row first, so concurrent reopenings serialize, and links the code only if it
   * is still usable and belongs to this restore and the session's account; the others roll back.
   */
  private async consume(
    tx: Prisma.TransactionClient,
    code: { code_id: string; account_id: string },
    deviceId: string,
    via: 'password' | 'recovery',
    client: ClientContext,
    now: Date,
  ) {
    const session = await this.sessions.createReopen(code.account_id, deviceId, tx, now);
    const [consumed] = await tx.$queryRaw<{ ok: boolean }[]>`
      SELECT ruvee_control.reopen_code_consume(${code.code_id}::uuid, ${session.id}::uuid, ${via})
        AS ok`;
    if (consumed?.ok !== true) throw new ApiException('reopen_failed');
    await this.events.record(
      'reopen_started',
      { accountId: code.account_id, deviceId, ...client, details: { via } },
      tx,
    );
    return session;
  }

  /** Password path, step 1: the code, then OPAQUE as for a login. */
  async loginStart(
    body: ReopenLoginStartRequest,
    client: ClientContext,
  ): Promise<LoginStartResponse> {
    this.throttle.assertIpAllowed(client.ip);
    const code = await this.presentedCode(body.reopenCode, client);
    await this.throttle.assertLoginAllowed(body.username);
    const account = await this.prisma.account.findUnique({
      where: { usernameNormalized: body.username },
      select: { id: true, opaqueCredential: { select: { registrationRecord: true } } },
    });
    // The code is for one account; any other username fails like a wrong code.
    if (account?.id !== code.account_id || !account.opaqueCredential)
      return this.fail(client, code.code_id, code.account_id);
    let started: { serverLoginState: string; loginResponse: string };
    try {
      started = this.opaque.startLogin(
        body.username,
        Buffer.from(account.opaqueCredential.registrationRecord).toString('base64url'),
        body.startLoginRequest,
      );
    } catch {
      throw new ApiException('invalid_request');
    }
    const { loginId, challenge } = this.loginStates.put({
      serverLoginState: started.serverLoginState,
      username: body.username,
      accountId: account.id,
      deviceId: body.deviceId,
      platform: 'web',
      reopenCodeId: code.code_id,
    });
    return { loginId, loginResponse: started.loginResponse, challenge: toBase64url(challenge) };
  }

  /**
   * Password path, step 2: OPAQUE finish with the snapshot-time password, from a device that is
   * active in the snapshot (only such a device holds `SK`, without which the password wrap
   * opens nothing). Then the code is consumed and the reopen session created.
   */
  async loginFinish(body: LoginFinishRequest, client: ClientContext): Promise<NewReopen> {
    this.throttle.assertIpAllowed(client.ip);
    const pending = this.loginStates.consume(body.loginId);
    if (!pending?.reopenCodeId || pending.accountId === null || !pending.deviceId)
      throw new ApiException('reopen_failed');
    const accountId = pending.accountId;
    await this.throttle.reserveLoginAttempt(pending.username);
    const verified = this.opaque.finishLogin(pending.serverLoginState, body.finishLoginRequest);
    if (!verified) {
      return this.fail(client, pending.reopenCodeId, accountId);
    }
    const device = await this.prisma.device.findFirst({
      where: { id: pending.deviceId, accountId },
    });
    if (device?.status !== 'active') return this.fail(client, pending.reopenCodeId, accountId);
    // device-proof.md §8 (R12): the device active in the snapshot proves its restored key (op
    // 10). A snapshot from before D-31 has no key: only the Recovery Kit path reopens it.
    const proven =
      device.publicKey !== null &&
      body.deviceProof !== undefined &&
      this.proofs.valid({
        operation: 'reopen_login',
        accountId,
        deviceId: device.id,
        binding: this.proofs.loginBinding(fromBase64url(body.loginId)),
        nonce: pending.challenge,
        payload: this.proofs.payload('reopen_login', [fromBase64url(body.finishLoginRequest)]),
        device: { publicKey: device.publicKey, signature: fromBase64url(body.deviceProof) },
      });
    if (!proven) return this.fail(client, pending.reopenCodeId, accountId);
    const code = { code_id: pending.reopenCodeId, account_id: accountId };
    const now = new Date();
    const session = await this.prisma.$transaction((tx) =>
      this.consume(tx, code, device.id, 'password', client, now),
    );
    await this.throttle.resetLogin(pending.username);
    return {
      accountId,
      deviceId: device.id,
      via: 'password',
      expiresAt: session.absoluteExpiresAt.toISOString(),
      token: session.token,
      absoluteExpiresAt: session.absoluteExpiresAt,
    };
  }

  /**
   * Recovery Kit path: the code and `RAK` of the snapshot-time kit, as in recovery
   * (account-recovery.md §3). The device is new (pending) or this account's own.
   */
  async recoveryStart(body: ReopenRecoveryStartRequest, client: ClientContext): Promise<NewReopen> {
    this.throttle.assertIpAllowed(client.ip);
    const code = await this.presentedCode(body.reopenCode, client);
    // Only now, with the right code, does this count against the owner's recovery budget.
    await this.throttle.reserveRecoveryAttempt(body.username);
    const account = await this.prisma.account.findUnique({
      where: { usernameNormalized: body.username },
      include: { accountKeys: { select: { recoveryVerifier: true, akVerifyKey: true } } },
    });
    const stored = account?.accountKeys?.recoveryVerifier ?? DUMMY_VERIFIER;
    const matches = timingSafeEqual(sha256(fromBase64url(body.recoveryAuthKey)), stored);
    if (!account?.accountKeys || !matches || account.id !== code.account_id)
      return this.fail(client, code.code_id, code.account_id);
    // device-proof.md §9: a snapshot from before D-31 has no AVPK to check AK against, so it
    // cannot be reopened; the code is left as it was.
    if (!account.accountKeys.akVerifyKey) throw new ApiException('migration_required');
    const existing = await this.prisma.device.findUnique({ where: { id: body.device.id } });
    if (existing && (existing.accountId !== account.id || existing.status === 'revoked'))
      return this.fail(client, code.code_id, account.id);
    const now = new Date();
    const session = await this.prisma.$transaction(async (tx) => {
      if (!existing)
        await tx.device.create({
          data: {
            id: body.device.id,
            accountId: account.id,
            platform: body.device.platform,
            status: 'pending',
            createdAt: now,
            lastSeenAt: now,
          },
        });
      return this.consume(tx, code, body.device.id, 'recovery', client, now);
    });
    return {
      accountId: account.id,
      deviceId: body.device.id,
      via: 'recovery',
      expiresAt: session.absoluteExpiresAt.toISOString(),
      token: session.token,
      absoluteExpiresAt: session.absoluteExpiresAt,
    };
  }

  /** The encrypted material of the session's own path only. */
  async material(session: AuthenticatedSession): Promise<ReopenMaterialResponse> {
    const keys = await this.prisma.accountKeys.findUnique({
      where: { accountId: session.accountId },
    });
    if (!keys || !session.via) throw new ApiException('reopen_failed');
    return {
      accountId: session.accountId,
      via: session.via,
      akId: toBase64url(keys.akId),
      akEpoch: keys.akEpoch,
      keysetVersion: Number(keys.keysetVersion),
      keyset: toBase64url(keys.keyset),
      recoveryKeyId: toBase64url(keys.recoveryKeyId),
      rowVersion: Number(keys.rowVersion),
      ...(session.via === 'password'
        ? {
            password: {
              kdfProfile: keys.kdfProfile as 1,
              saltPw: toBase64url(keys.saltPw),
              wrappedAkPassword: toBase64url(keys.wrappedAkPassword),
            },
          }
        : { wrappedAkRecovery: toBase64url(keys.wrappedAkRecovery) }),
    };
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
   * One transaction, the final authorization transition: the new OPAQUE record, password wrap
   * and salt, the new Recovery Kit (a different key id is required) with its wrap and verifier;
   * every session revoked, every code revoked, the guard `reopening` → `open`; this device
   * active; a normal session for it. Either all of it happens or none: there is no state with a
   * new password and the old kit.
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
      Buffer.compare(recoveryKeyId, keys.recoveryKeyId) === 0
    )
      throw new ApiException('invalid_request');
    const via = session.via ?? 'password';
    // device-proof.md §8 (R12): the password path keeps and proves the restored device key; the
    // Recovery Kit path enrolls a new one, like a recovery. Both prove AK.
    const device = await this.prisma.device.findUniqueOrThrow({ where: { id: session.deviceId } });
    const presented = fromBase64url(body.devicePublicKey);
    if (via === 'password' && !(device.publicKey && constantTimeEqual(device.publicKey, presented)))
      throw new ApiException('device_proof_failed');
    const proof = await proveCompletion(
      this.proofs,
      'reopen_complete',
      session,
      body,
      keys,
      presented,
    );
    const now = new Date();
    const result = await this.proofs.spend(
      session.sessionId,
      'reopen_complete',
      proof.nonce,
      async (tx) => {
        // First, under the guard row's lock (`ruvee-admin restore-reopen-code` takes it too, so a
        // host revocation either commits before this check or waits for this transaction, R13):
        // the session, re-checked because it was authenticated before this transaction, must
        // still be live and linked to an unrevoked code of this restore. Only then does the
        // function revoke every code and open the guard; the rest of this transaction commits
        // with that change or rolls it back.
        const [opened] = await tx.$queryRaw<{ restore_id: string | null }[]>`
        SELECT ruvee_control.reopen_complete(${session.sessionId}::uuid)::text AS restore_id`;
        const restoreId = opened?.restore_id;
        if (!restoreId) throw new ApiException('reopen_failed');
        const updated = await tx.accountKeys.updateMany({
          where: { accountId: session.accountId, rowVersion: BigInt(body.expectedRowVersion) },
          data: {
            kdfProfile: body.kdfProfile,
            saltPw: fromBase64url(body.saltPw),
            wrappedAkPassword,
            recoveryKeyId,
            wrappedAkRecovery,
            recoveryVerifier: fromBase64url(body.recoveryVerifier),
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
          data: { revokedAt: now, revokeReason: 'reopened' },
        });
        await tx.device.update({
          where: { id: session.deviceId },
          data:
            via === 'recovery'
              ? {
                  status: 'active',
                  enrolledVia: 'recovery',
                  enrolledAt: now,
                  lastSeenAt: now,
                  publicKey: proof.devicePublicKey,
                  ...(label === null ? {} : { label }),
                }
              : { lastSeenAt: now, ...(label === null ? {} : { label }) },
        });
        const created = await this.sessions.create(
          session.accountId,
          session.deviceId,
          tx,
          now,
          true,
        );
        const context = { accountId: session.accountId, deviceId: session.deviceId, ...client };
        await this.events.record(
          'restore_reopened',
          { ...context, details: { restoreId, via } },
          tx,
        );
        await this.events.record('password_changed', context, tx);
        await this.events.record('recovery_key_rotated', context, tx);
        if (via === 'recovery')
          await this.events.record(
            'device_enrolled',
            { ...context, details: { enrolledDeviceId: session.deviceId, via: 'recovery' } },
            tx,
          );
        return created;
      },
    );
    const account = await this.prisma.account.findUniqueOrThrow({
      where: { id: session.accountId },
    });
    await this.throttle.resetRecovery(account.usernameNormalized);
    await this.throttle.resetLogin(account.usernameNormalized);
    return {
      accountId: session.accountId,
      device: { id: session.deviceId, status: 'active' },
      proven: true,
      ...result,
    };
  }
}
