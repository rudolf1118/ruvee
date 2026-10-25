import { Body, Controller, HttpCode, Post, Req, Res } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  loginFinishRequestSchema,
  loginStartRequestSchema,
  reauthStartRequestSchema,
  registerFinishRequestSchema,
  registerStartRequestSchema,
  type LoginFinishRequest,
  type LoginStartRequest,
  type LoginStartResponse,
  type ReauthFinishResponse,
  type ReauthStartRequest,
  type RegisterFinishRequest,
  type RegisterStartRequest,
  type RegisterStartResponse,
  type SessionResponse,
} from '@ruvee/contracts';
import type { Request, Response } from 'express';
import { ContractValidationPipe } from '../common/contract-validation.pipe.js';
import type { Env } from '../config/env.js';
import { Access, CurrentSession } from '../sessions/access.decorator.js';
import { clientIp, userAgent } from '../sessions/client-info.js';
import { SessionService, type AuthenticatedSession } from '../sessions/session.service.js';
import { AuthService, type ClientContext } from './auth.service.js';

@Controller('api/v1/auth')
export class AuthController {
  private readonly trustedProxy: string | undefined;

  constructor(
    private readonly auth: AuthService,
    private readonly sessions: SessionService,
    config: ConfigService<Env, true>,
  ) {
    this.trustedProxy = config.get('TRUSTED_PROXY_ADDRESS', { infer: true });
  }

  private client(req: Request): ClientContext {
    return { ip: clientIp(req, this.trustedProxy), userAgent: userAgent(req) };
  }

  @Post('register/start')
  @HttpCode(200)
  @Access('none')
  async registerStart(
    @Body(new ContractValidationPipe(registerStartRequestSchema)) body: RegisterStartRequest,
    @Req() req: Request,
  ): Promise<RegisterStartResponse> {
    return { registrationResponse: await this.auth.registerStart(body, this.client(req)) };
  }

  @Post('register/finish')
  @HttpCode(201)
  @Access('none')
  async registerFinish(
    @Body(new ContractValidationPipe(registerFinishRequestSchema)) body: RegisterFinishRequest,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<SessionResponse> {
    const session = await this.auth.registerFinish(body, this.client(req));
    this.sessions.setCookie(res, session.token, session.absoluteExpiresAt);
    return session.body;
  }

  @Post('login/start')
  @HttpCode(200)
  @Access('none')
  loginStart(
    @Body(new ContractValidationPipe(loginStartRequestSchema)) body: LoginStartRequest,
    @Req() req: Request,
  ): Promise<LoginStartResponse> {
    return this.auth.loginStart(body, this.client(req));
  }

  @Post('login/finish')
  @HttpCode(200)
  @Access('none')
  async loginFinish(
    @Body(new ContractValidationPipe(loginFinishRequestSchema)) body: LoginFinishRequest,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<SessionResponse> {
    const session = await this.auth.loginFinish(body, this.client(req));
    this.sessions.setCookie(res, session.token, session.absoluteExpiresAt);
    return session.body;
  }

  @Post('reauth/start')
  @HttpCode(200)
  @Access('active')
  reauthStart(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(reauthStartRequestSchema)) body: ReauthStartRequest,
    @Req() req: Request,
  ): Promise<LoginStartResponse> {
    return this.auth.reauthStart(session, body, this.client(req));
  }

  @Post('reauth/finish')
  @HttpCode(200)
  @Access('active')
  reauthFinish(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(loginFinishRequestSchema)) body: LoginFinishRequest,
    @Req() req: Request,
  ): Promise<ReauthFinishResponse> {
    return this.auth.reauthFinish(session, body, this.client(req));
  }

  @Post('logout')
  @HttpCode(204)
  @Access('session')
  async logout(
    @CurrentSession() session: AuthenticatedSession,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.auth.logout(
      session.sessionId,
      session.accountId,
      session.deviceId,
      this.client(req),
    );
    this.sessions.clearCookie(res);
  }
}
