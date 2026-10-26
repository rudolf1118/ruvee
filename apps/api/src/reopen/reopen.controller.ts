import { Body, Controller, Get, HttpCode, Post, Req, Res } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  loginFinishRequestSchema,
  recoveryCompleteRequestSchema,
  recoveryPasswordStartRequestSchema,
  reopenLoginStartRequestSchema,
  reopenRecoveryStartRequestSchema,
  type LoginFinishRequest,
  type LoginStartResponse,
  type RecoveryCompleteRequest,
  type RecoveryPasswordStartRequest,
  type RegisterStartResponse,
  type ReopenLoginStartRequest,
  type ReopenMaterialResponse,
  type ReopenRecoveryStartRequest,
  type ReopenStartResponse,
  type SessionResponse,
} from '@ruvee/contracts';
import type { Request, Response } from 'express';
import type { ClientContext } from '../auth/auth.service.js';
import { ContractValidationPipe } from '../common/contract-validation.pipe.js';
import type { Env } from '../config/env.js';
import { Access, CurrentSession } from '../sessions/access.decorator.js';
import { clientIp, userAgent } from '../sessions/client-info.js';
import { SessionService, type AuthenticatedSession } from '../sessions/session.service.js';
import { ReopenService } from './reopen.service.js';

/**
 * Reopening a restored installation (backup-restore.md §3.13). The only routes served while the
 * guard is `reopening`; outside that state every call fails with `reopen_failed`. The reopen
 * session has its own cookie and never receives a normal one until completion.
 */
@Controller('api/v1/reopen')
export class ReopenController {
  private readonly trustedProxy: string | undefined;

  constructor(
    private readonly reopen: ReopenService,
    private readonly sessions: SessionService,
    config: ConfigService<Env, true>,
  ) {
    this.trustedProxy = config.get('TRUSTED_PROXY_ADDRESS', { infer: true });
  }

  private client(req: Request): ClientContext {
    return { ip: clientIp(req, this.trustedProxy), userAgent: userAgent(req) };
  }

  @Post('login/start')
  @HttpCode(200)
  @Access('none')
  loginStart(
    @Body(new ContractValidationPipe(reopenLoginStartRequestSchema)) body: ReopenLoginStartRequest,
    @Req() req: Request,
  ): Promise<LoginStartResponse> {
    return this.reopen.loginStart(body, this.client(req));
  }

  @Post('login/finish')
  @HttpCode(200)
  @Access('none')
  async loginFinish(
    @Body(new ContractValidationPipe(loginFinishRequestSchema)) body: LoginFinishRequest,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ReopenStartResponse> {
    const { token, absoluteExpiresAt, ...response } = await this.reopen.loginFinish(
      body,
      this.client(req),
    );
    this.sessions.setReopenCookie(res, token, absoluteExpiresAt);
    return response;
  }

  @Post('recovery/start')
  @HttpCode(200)
  @Access('none')
  async recoveryStart(
    @Body(new ContractValidationPipe(reopenRecoveryStartRequestSchema))
    body: ReopenRecoveryStartRequest,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<ReopenStartResponse> {
    const { token, absoluteExpiresAt, ...response } = await this.reopen.recoveryStart(
      body,
      this.client(req),
    );
    this.sessions.setReopenCookie(res, token, absoluteExpiresAt);
    return response;
  }

  @Get('material')
  @Access('reopen')
  material(@CurrentSession() session: AuthenticatedSession): Promise<ReopenMaterialResponse> {
    return this.reopen.material(session);
  }

  @Post('password/start')
  @HttpCode(200)
  @Access('reopen')
  async passwordStart(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(recoveryPasswordStartRequestSchema))
    body: RecoveryPasswordStartRequest,
  ): Promise<RegisterStartResponse> {
    return {
      registrationResponse: await this.reopen.passwordStart(session, body.registrationRequest),
    };
  }

  @Post('complete')
  @HttpCode(200)
  @Access('reopen')
  async complete(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(recoveryCompleteRequestSchema)) body: RecoveryCompleteRequest,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<SessionResponse> {
    const { token, absoluteExpiresAt, ...response } = await this.reopen.complete(
      session,
      body,
      this.client(req),
    );
    this.sessions.clearReopenCookie(res);
    this.sessions.setCookie(res, token, absoluteExpiresAt);
    return response;
  }
}
