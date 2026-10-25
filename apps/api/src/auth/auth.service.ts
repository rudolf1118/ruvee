import { randomUUID } from 'node:crypto';
import { Injectable } from '@nestjs/common';
import {
  OPAQUE_CONFIG_ID,
  type LoginFinishRequest,
  type LoginStartRequest,
  type LoginStartResponse,
  type ReauthStartRequest,
  type RegisterFinishRequest,
  type RegisterStartRequest,
  type SessionResponse,
  type RefreshRequest,
  type TokenPair,
} from '@ruvee/contracts';
import { ApiException } from '../common/api-exception.js';
import { envelopeHeaderOk, fromBase64url, sha256 } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import { Prisma } from '../generated/prisma/client.js';
import { SecurityEventsService } from '../security-events/security-events.service.js';
import { SessionService, type AuthenticatedSession } from '../sessions/session.service.js';
import { LoginStateStore } from './login-state.store.js';
import { OpaqueServerService } from './opaque-server.service.js';
import { ThrottleService } from './throttle.service.js';

/** One account per server in V1 (authentication.md §3). Serializes concurrent registrations. */
const REGISTRATION_LOCK = 0x52_56_52_47; // "RVRG"

export interface ClientContext {
  readonly ip: string | undefined;
  readonly userAgent: string | undefined;
}

export interface CookieSession {
  readonly body: SessionResponse;
  readonly token: string;
  readonly absoluteExpiresAt: Date;
}

/** A web login carries a cookie; a token login returns its tokens in the body instead. */
export type NewSession =
  CookieSession | { readonly body: SessionResponse; readonly token?: undefined };

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly opaque: OpaqueServerService,
    private readonly sessions: SessionService,
    private readonly loginStates: LoginStateStore,
    private readonly throttle: ThrottleService,
    private readonly events: SecurityEventsService,
  ) {}

  private async assertRegistrationOpen(): Promise<void> {
    if ((await this.prisma.account.count()) > 0) throw new ApiException('not_found');
  }

  /** Checks the bootstrap token (hash lookup, unused, unexpired); counts failures (INV-20). */
  private async assertBootstrapToken(token: string, client: ClientContext): Promise<void> {
    await this.throttle.assertBootstrapAllowed();
    const row = await this.prisma.bootstrapToken.findUnique({
      where: { tokenHash: sha256(fromBase64url(token)) },
    });
    if (row?.usedAt !== null || row.expiresAt <= new Date()) {
      await this.throttle.recordBootstrapFailure();
      await this.events.record('bootstrap_failed', client);
      throw new ApiException('bootstrap_failed');
    }
  }

  async registerStart(body: RegisterStartRequest, client: ClientContext): Promise<string> {
    this.throttle.assertIpAllowed(client.ip);
    await this.assertRegistrationOpen();
    await this.assertBootstrapToken(body.bootstrapToken, client);
    try {
      return this.opaque.createRegistrationResponse(body.username, body.registrationRequest);
    } catch {
      throw new ApiException('invalid_request');
    }
  }

  /**
   * Stores, in one transaction: the OPAQUE record, the key material, the first device (active),
   * its session and the empty vault, and marks the token used. Afterwards registration is closed.
   */
  async registerFinish(body: RegisterFinishRequest, client: ClientContext): Promise<CookieSession> {
    this.throttle.assertIpAllowed(client.ip);
    await this.assertRegistrationOpen();
    await this.assertBootstrapToken(body.bootstrapToken, client);

    const keys = body.keys;
    const akId = fromBase64url(keys.akId);
    const recoveryKeyId = fromBase64url(keys.recoveryKeyId);
    const wrappedAkPassword = fromBase64url(keys.wrappedAkPassword);
    const wrappedAkRecovery = fromBase64url(keys.wrappedAkRecovery);
    const keyset = fromBase64url(keys.keyset);
    const label = body.device.label === undefined ? null : fromBase64url(body.device.label);
    const vkId = fromBase64url(body.vault.vkId);
    if (
      !envelopeHeaderOk(wrappedAkPassword, 0x01, { min: 93, max: 93 }, akId) ||
      !envelopeHeaderOk(wrappedAkRecovery, 0x02, { min: 93, max: 93 }, recoveryKeyId) ||
      !envelopeHeaderOk(keyset, 0x03, { min: 61, max: 16_445 }, akId) ||
      (label !== null && !envelopeHeaderOk(label, 0x08, { min: 61, max: 189 }))
    )
      throw new ApiException('invalid_request');

    const now = new Date();
    try {
      const token = await this.prisma.$transaction(async (tx) => {
        await tx.$executeRaw`SELECT pg_advisory_xact_lock(${REGISTRATION_LOCK})`;
        if ((await tx.account.count()) > 0) throw new ApiException('not_found');
        const used = await tx.bootstrapToken.updateMany({
          where: {
            tokenHash: sha256(fromBase64url(body.bootstrapToken)),
            usedAt: null,
            expiresAt: { gt: now },
          },
          data: { usedAt: now },
        });
        if (used.count !== 1) throw new ApiException('bootstrap_failed');

        await tx.account.create({
          data: { id: body.accountId, usernameNormalized: body.username, createdAt: now },
        });
        await tx.opaqueCredential.create({
          data: {
            accountId: body.accountId,
            registrationRecord: fromBase64url(body.registrationRecord),
            configId: OPAQUE_CONFIG_ID,
            updatedAt: now,
          },
        });
        await tx.accountKeys.create({
          data: {
            accountId: body.accountId,
            kdfProfile: keys.kdfProfile,
            saltPw: fromBase64url(keys.saltPw),
            akId,
            akEpoch: keys.akEpoch,
            wrappedAkPassword,
            recoveryKeyId,
            wrappedAkRecovery,
            recoveryVerifier: fromBase64url(keys.recoveryVerifier),
            keysetVersion: BigInt(keys.keysetVersion),
            keyset,
            updatedAt: now,
          },
        });
        await tx.device.create({
          data: {
            id: body.device.id,
            accountId: body.accountId,
            platform: body.device.platform,
            status: 'active',
            enrolledVia: 'bootstrap',
            label,
            createdAt: now,
            enrolledAt: now,
            lastSeenAt: now,
          },
        });
        await tx.vault.create({
          data: {
            id: body.vault.id,
            accountId: body.accountId,
            vkId,
            createdAt: now,
            updatedAt: now,
          },
        });
        const session = await this.sessions.create(body.accountId, body.device.id, tx, now);
        await this.events.record(
          'bootstrap_used',
          { accountId: body.accountId, deviceId: body.device.id, ...client },
          tx,
        );
        await this.events.record(
          'device_enrolled',
          {
            accountId: body.accountId,
            deviceId: body.device.id,
            ...client,
            details: { enrolledDeviceId: body.device.id, via: 'bootstrap' },
          },
          tx,
        );
        return session;
      });
      return {
        body: { accountId: body.accountId, device: { id: body.device.id, status: 'active' } },
        ...token,
      };
    } catch (error) {
      // A client-chosen id that already exists (another device or vault) is a bad request.
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002')
        throw new ApiException('invalid_request');
      throw error;
    }
  }

  async loginStart(body: LoginStartRequest, client: ClientContext): Promise<LoginStartResponse> {
    this.throttle.assertIpAllowed(client.ip);
    await this.throttle.assertLoginAllowed(body.username);
    const account = await this.prisma.account.findUnique({
      where: { usernameNormalized: body.username },
      select: { id: true, opaqueCredential: { select: { registrationRecord: true } } },
    });
    const record = account?.opaqueCredential
      ? Buffer.from(account.opaqueCredential.registrationRecord).toString('base64url')
      : null;
    let started: { serverLoginState: string; loginResponse: string };
    try {
      started = this.opaque.startLogin(body.username, record, body.startLoginRequest);
    } catch {
      throw new ApiException('invalid_request');
    }
    const loginId = this.loginStates.put({
      serverLoginState: started.serverLoginState,
      username: body.username,
      accountId: account?.opaqueCredential ? account.id : null,
      deviceId: body.deviceId,
      platform: body.platform,
    });
    return { loginId, loginResponse: started.loginResponse };
  }

  async loginFinish(body: LoginFinishRequest, client: ClientContext): Promise<NewSession> {
    this.throttle.assertIpAllowed(client.ip);
    // Consumed before anything else, so a replayed loginId always fails (INV-23).
    const pending = this.loginStates.consume(body.loginId);
    // A step-up state is bound to its session and can never create a new one.
    if (!pending || pending.sessionId !== undefined) throw new ApiException('login_failed');
    const verified = this.opaque.finishLogin(pending.serverLoginState, body.finishLoginRequest);
    if (!verified || pending.accountId === null) {
      await this.throttle.recordLoginFailure(pending.username);
      await this.events.record('login_failed', { accountId: pending.accountId, ...client });
      throw new ApiException('login_failed');
    }
    const accountId = pending.accountId;
    await this.throttle.resetLogin(pending.username);

    const known = pending.deviceId
      ? await this.prisma.device.findFirst({ where: { id: pending.deviceId, accountId } })
      : null;
    if (known?.status === 'revoked') {
      await this.events.record('login_failed', { accountId, deviceId: known.id, ...client });
      throw new ApiException('device_revoked');
    }
    // A device id belongs to one platform; a web device cannot log in as an extension.
    if (known && known.platform !== pending.platform) throw new ApiException('invalid_request');
    const now = new Date();
    const result = await this.prisma.$transaction(async (tx) => {
      // An unknown device becomes a pending record that can do nothing but enroll (§4 step 4).
      const device =
        known ??
        (await tx.device.create({
          data: {
            id: randomUUID(),
            accountId,
            platform: pending.platform,
            status: 'pending',
            createdAt: now,
            lastSeenAt: now,
          },
        }));
      const cookie =
        pending.platform === 'web'
          ? await this.sessions.create(accountId, device.id, tx, now)
          : undefined;
      const tokens = cookie
        ? undefined
        : await this.sessions.createToken(accountId, device.id, tx, now);
      await this.events.record(
        'login_succeeded',
        { accountId, deviceId: device.id, ...client, details: { newDevice: known === null } },
        tx,
      );
      return { device, cookie, tokens };
    });
    const response = { accountId, device: { id: result.device.id, status: result.device.status } };
    if (result.cookie) return { body: response, ...result.cookie };
    if (!result.tokens) throw new ApiException('internal_error');
    return { body: { ...response, tokens: result.tokens } };
  }

  /**
   * Step-up (authentication.md §5, INV-14): OPAQUE again for the session's own account. The
   * login state is bound to this session and consumed once, like a login (INV-23).
   */
  async reauthStart(
    session: AuthenticatedSession,
    body: ReauthStartRequest,
    client: ClientContext,
  ) {
    this.throttle.assertIpAllowed(client.ip);
    const account = await this.prisma.account.findUniqueOrThrow({
      where: { id: session.accountId },
      select: {
        usernameNormalized: true,
        opaqueCredential: { select: { registrationRecord: true } },
      },
    });
    await this.throttle.assertLoginAllowed(account.usernameNormalized);
    const record = account.opaqueCredential
      ? Buffer.from(account.opaqueCredential.registrationRecord).toString('base64url')
      : null;
    let started: { serverLoginState: string; loginResponse: string };
    try {
      started = this.opaque.startLogin(account.usernameNormalized, record, body.startLoginRequest);
    } catch {
      throw new ApiException('invalid_request');
    }
    const loginId = this.loginStates.put({
      serverLoginState: started.serverLoginState,
      username: account.usernameNormalized,
      accountId: session.accountId,
      deviceId: session.deviceId,
      platform: 'web',
      sessionId: session.sessionId,
    });
    return { loginId, loginResponse: started.loginResponse };
  }

  async reauthFinish(
    session: AuthenticatedSession,
    body: LoginFinishRequest,
    client: ClientContext,
  ): Promise<{ authAt: string }> {
    this.throttle.assertIpAllowed(client.ip);
    const pending = this.loginStates.consume(body.loginId);
    if (pending?.sessionId !== session.sessionId) throw new ApiException('login_failed');
    if (!this.opaque.finishLogin(pending.serverLoginState, body.finishLoginRequest)) {
      await this.throttle.recordLoginFailure(pending.username);
      await this.events.record('login_failed', {
        accountId: session.accountId,
        deviceId: session.deviceId,
        ...client,
      });
      throw new ApiException('login_failed');
    }
    await this.throttle.resetLogin(pending.username);
    const authAt = new Date();
    await this.prisma.session.update({ where: { id: session.sessionId }, data: { authAt } });
    return { authAt: authAt.toISOString() };
  }

  async logout(sessionId: string, accountId: string, deviceId: string, client: ClientContext) {
    await this.sessions.revoke(sessionId, 'logout');
    await this.events.record('session_revoked', {
      accountId,
      deviceId,
      ...client,
      details: { sessionId, reason: 'logout' },
    });
  }

  /**
   * Token clients (authentication.md §5). A reused refresh token revokes its family and is
   * recorded; the caller sees the same `unauthenticated` as for an unknown token.
   */
  async refresh(body: RefreshRequest, client: ClientContext): Promise<TokenPair> {
    this.throttle.assertIpAllowed(client.ip);
    const result = await this.sessions.refresh(body.refreshToken);
    if ('reused' in result) {
      await this.events.record('refresh_reuse', {
        accountId: result.reused.accountId,
        deviceId: result.reused.deviceId,
        ...client,
        details: { sessionId: result.reused.sessionId },
      });
      throw new ApiException('unauthenticated');
    }
    return result.tokens;
  }
}
