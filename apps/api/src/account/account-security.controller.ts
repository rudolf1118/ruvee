import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Post,
  Put,
  Query,
  Req,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  passwordChangeFinishRequestSchema,
  recoveryKeyRotateRequestSchema,
  recoveryPasswordStartRequestSchema,
  revokeDeviceRequestSchema,
  secretKeyRotateRequestSchema,
  securityEventsQuerySchema,
  uuidSchema,
  type PasswordChangeFinishRequest,
  type RecoveryKeyRotateRequest,
  type RecoveryPasswordStartRequest,
  type RegisterStartResponse,
  type RevokeDeviceRequest,
  type SecretKeyRotateRequest,
  type SecurityEventsQuery,
  type SecurityEventsResponse,
  type SessionsResponse,
} from '@ruvee/contracts';
import type { Request } from 'express';
import type { ClientContext } from '../auth/auth.service.js';
import { ContractValidationPipe } from '../common/contract-validation.pipe.js';
import type { Env } from '../config/env.js';
import { Access, CurrentSession } from '../sessions/access.decorator.js';
import { clientIp, userAgent } from '../sessions/client-info.js';
import type { AuthenticatedSession } from '../sessions/session.service.js';
import { AccountSecurityService } from './account-security.service.js';

const idPipe = new ContractValidationPipe(uuidSchema);

@Controller('api/v1')
export class AccountSecurityController {
  private readonly trustedProxy: string | undefined;

  constructor(
    private readonly security: AccountSecurityService,
    config: ConfigService<Env, true>,
  ) {
    this.trustedProxy = config.get('TRUSTED_PROXY_ADDRESS', { infer: true });
  }

  private client(req: Request): ClientContext {
    return { ip: clientIp(req, this.trustedProxy), userAgent: userAgent(req) };
  }

  @Get('sessions')
  @Access('active')
  sessions(@CurrentSession() session: AuthenticatedSession): Promise<SessionsResponse> {
    return this.security.sessions(session);
  }

  @Delete('sessions/:sessionId')
  @HttpCode(204)
  @Access('active')
  async endSession(
    @CurrentSession() session: AuthenticatedSession,
    @Param('sessionId', idPipe) sessionId: string,
    @Req() req: Request,
  ): Promise<void> {
    await this.security.endSession(session, sessionId, this.client(req));
  }

  /** Step-up (INV-14). */
  @Post('devices/:deviceId/revoke')
  @HttpCode(204)
  @Access('step-up')
  async revoke(
    @CurrentSession() session: AuthenticatedSession,
    @Param('deviceId', idPipe) deviceId: string,
    @Body(new ContractValidationPipe(revokeDeviceRequestSchema)) body: RevokeDeviceRequest,
    @Req() req: Request,
  ): Promise<void> {
    await this.security.revokeDevice(session, deviceId, body, this.client(req));
  }

  @Post('account/password/start')
  @HttpCode(200)
  @Access('step-up')
  async passwordStart(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(recoveryPasswordStartRequestSchema))
    body: RecoveryPasswordStartRequest,
  ): Promise<RegisterStartResponse> {
    return {
      registrationResponse: await this.security.passwordStart(session, body.registrationRequest),
    };
  }

  @Post('account/password/finish')
  @HttpCode(204)
  @Access('step-up')
  async passwordFinish(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(passwordChangeFinishRequestSchema))
    body: PasswordChangeFinishRequest,
    @Req() req: Request,
  ): Promise<void> {
    await this.security.passwordFinish(session, body, this.client(req));
  }

  /** D-24: after revoking a lost device, and offered at the end of a recovery. Step-up. */
  @Post('account/secret-key')
  @HttpCode(204)
  @Access('step-up')
  async rotateSecretKey(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(secretKeyRotateRequestSchema)) body: SecretKeyRotateRequest,
    @Req() req: Request,
  ): Promise<void> {
    await this.security.rotateSecretKey(session, body, this.client(req));
  }

  /** account-recovery.md §5: Recovery Kit rotation from Security. Step-up. */
  @Put('account/recovery')
  @HttpCode(204)
  @Access('step-up')
  async rotateRecoveryKey(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(recoveryKeyRotateRequestSchema))
    body: RecoveryKeyRotateRequest,
    @Req() req: Request,
  ): Promise<void> {
    await this.security.rotateRecoveryKey(session, body, this.client(req));
  }

  @Get('account/events')
  @Access('active')
  events(
    @CurrentSession() session: AuthenticatedSession,
    @Query(new ContractValidationPipe(securityEventsQuerySchema)) query: SecurityEventsQuery,
  ): Promise<SecurityEventsResponse> {
    return this.security.activity(session, query.cursor);
  }
}
