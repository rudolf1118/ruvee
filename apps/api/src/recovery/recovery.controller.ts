import { Body, Controller, Get, HttpCode, Post, Req, Res } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  proofNonceRequestSchema,
  recoveryCompleteRequestSchema,
  recoveryPasswordStartRequestSchema,
  recoveryStartRequestSchema,
  type ProofNonceRequest,
  type ProofNonceResponse,
  type RecoveryCompleteRequest,
  type RecoveryMaterialResponse,
  type RecoveryPasswordStartRequest,
  type RecoveryStartRequest,
  type RecoveryStartResponse,
  type RegisterStartResponse,
  type SessionResponse,
} from '@ruvee/contracts';
import type { Request, Response } from 'express';
import type { ClientContext } from '../auth/auth.service.js';
import { ContractValidationPipe } from '../common/contract-validation.pipe.js';
import type { Env } from '../config/env.js';
import { Access, CurrentSession } from '../sessions/access.decorator.js';
import { RouteClassOf } from '../sessions/route-class.js';
import { clientIp, userAgent } from '../sessions/client-info.js';
import { SessionService, type AuthenticatedSession } from '../sessions/session.service.js';
import { RecoveryService } from './recovery.service.js';

@Controller('api/v1/recovery')
@RouteClassOf('recovery')
export class RecoveryController {
  private readonly trustedProxy: string | undefined;

  constructor(
    private readonly recovery: RecoveryService,
    private readonly sessions: SessionService,
    config: ConfigService<Env, true>,
  ) {
    this.trustedProxy = config.get('TRUSTED_PROXY_ADDRESS', { infer: true });
  }

  private client(req: Request): ClientContext {
    return { ip: clientIp(req, this.trustedProxy), userAgent: userAgent(req) };
  }

  @Post('start')
  @HttpCode(200)
  @Access('none')
  async start(
    @Body(new ContractValidationPipe(recoveryStartRequestSchema)) body: RecoveryStartRequest,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<RecoveryStartResponse> {
    const { token, absoluteExpiresAt, ...response } = await this.recovery.start(
      body,
      this.client(req),
    );
    this.sessions.setRecoveryCookie(res, token, absoluteExpiresAt);
    return response;
  }

  @Get('material')
  @Access('recovery')
  material(@CurrentSession() session: AuthenticatedSession): Promise<RecoveryMaterialResponse> {
    return this.recovery.material(session);
  }

  @Post('proof-nonce')
  @HttpCode(200)
  @Access('recovery')
  proofNonce(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(proofNonceRequestSchema)) body: ProofNonceRequest,
  ): Promise<ProofNonceResponse> {
    return this.recovery.proofNonce(session, body.operation);
  }

  @Post('password/start')
  @HttpCode(200)
  @Access('recovery')
  async passwordStart(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(recoveryPasswordStartRequestSchema))
    body: RecoveryPasswordStartRequest,
  ): Promise<RegisterStartResponse> {
    return {
      registrationResponse: await this.recovery.passwordStart(session, body.registrationRequest),
    };
  }

  @Post('complete')
  @HttpCode(200)
  @Access('recovery')
  async complete(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(recoveryCompleteRequestSchema)) body: RecoveryCompleteRequest,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<SessionResponse> {
    const { token, absoluteExpiresAt, ...response } = await this.recovery.complete(
      session,
      body,
      this.client(req),
    );
    this.sessions.clearRecoveryCookie(res);
    this.sessions.setCookie(res, token, absoluteExpiresAt);
    return response;
  }
}
