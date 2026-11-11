import { Body, Controller, Delete, Get, HttpCode, Param, Post, Req } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  createPairingRequestSchema,
  pairingApproveRequestSchema,
  pairingCancelRequestSchema,
  pairingIdParamSchema,
  pairingJoinRequestSchema,
  type CreatePairingRequest,
  type PairingApproveRequest,
  type PairingCancelRequest,
  type PairingJoinRequest,
  type PairingStateResponse,
} from '@ruvee/contracts';
import type { Request } from 'express';
import type { ClientContext } from '../auth/auth.service.js';
import { ContractValidationPipe } from '../common/contract-validation.pipe.js';
import type { Env } from '../config/env.js';
import { Access, CurrentSession } from '../sessions/access.decorator.js';
import { clientIp, userAgent } from '../sessions/client-info.js';
import type { AuthenticatedSession } from '../sessions/session.service.js';
import { PairingService } from './pairing.service.js';

const idPipe = new ContractValidationPipe(pairingIdParamSchema);

@Controller('api/v1/pairings')
export class PairingController {
  private readonly trustedProxy: string | undefined;

  constructor(
    private readonly pairings: PairingService,
    config: ConfigService<Env, true>,
  ) {
    this.trustedProxy = config.get('TRUSTED_PROXY_ADDRESS', { infer: true });
  }

  private client(req: Request): ClientContext {
    return { ip: clientIp(req, this.trustedProxy), userAgent: userAgent(req) };
  }

  @Post()
  @HttpCode(201)
  @Access('active')
  create(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(createPairingRequestSchema)) body: CreatePairingRequest,
  ): Promise<{ expiresAt: string }> {
    return this.pairings.create(session, body.pairingId);
  }

  @Get(':pairingId')
  @Access('session')
  state(
    @CurrentSession() session: AuthenticatedSession,
    @Param('pairingId', idPipe) pairingId: string,
  ): Promise<PairingStateResponse> {
    return this.pairings.state(session, pairingId);
  }

  @Post(':pairingId/request')
  @HttpCode(204)
  @Access('session')
  async request(
    @CurrentSession() session: AuthenticatedSession,
    @Param('pairingId', idPipe) pairingId: string,
    @Body(new ContractValidationPipe(pairingJoinRequestSchema)) body: PairingJoinRequest,
    @Req() req: Request,
  ): Promise<void> {
    await this.pairings.request(session, pairingId, body, this.client(req));
  }

  @Post(':pairingId/approve')
  @HttpCode(204)
  @Access('active')
  async approve(
    @CurrentSession() session: AuthenticatedSession,
    @Param('pairingId', idPipe) pairingId: string,
    @Body(new ContractValidationPipe(pairingApproveRequestSchema)) body: PairingApproveRequest,
    @Req() req: Request,
  ): Promise<void> {
    await this.pairings.approve(session, pairingId, body, this.client(req));
  }

  @Post(':pairingId/complete')
  @HttpCode(204)
  @Access('active')
  async complete(
    @CurrentSession() session: AuthenticatedSession,
    @Param('pairingId', idPipe) pairingId: string,
  ): Promise<void> {
    await this.pairings.complete(session, pairingId);
  }

  @Delete(':pairingId')
  @HttpCode(204)
  @Access('session')
  async cancel(
    @CurrentSession() session: AuthenticatedSession,
    @Param('pairingId', idPipe) pairingId: string,
    @Body(new ContractValidationPipe(pairingCancelRequestSchema.optional()))
    body: PairingCancelRequest | undefined,
    @Req() req: Request,
  ): Promise<void> {
    await this.pairings.cancel(session, pairingId, body?.reason, this.client(req));
  }
}
