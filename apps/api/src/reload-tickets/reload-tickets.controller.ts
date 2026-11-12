import { Body, Controller, Delete, HttpCode, Post } from '@nestjs/common';
import {
  reloadTicketCreateRequestSchema,
  reloadTicketHeartbeatRequestSchema,
  reloadTicketRedeemRequestSchema,
  type ReloadTicketCreateRequest,
  type ReloadTicketCreateResponse,
  type ReloadTicketHeartbeatRequest,
  type ReloadTicketRedeemRequest,
  type ReloadTicketRedeemResponse,
} from '@ruvee/contracts';
import { ContractValidationPipe } from '../common/contract-validation.pipe.js';
import { Access, CurrentSession } from '../sessions/access.decorator.js';
import type { AuthenticatedSession } from '../sessions/session.service.js';
import { ReloadTicketsService } from './reload-tickets.service.js';

/**
 * D-34 web reload tickets. Every handler needs an active device's proven session; none is on the
 * pre-proof allowlist (device-proof.md §5).
 */
@Controller('api/v1/reload-tickets')
export class ReloadTicketsController {
  constructor(private readonly tickets: ReloadTicketsService) {}

  @Post()
  @HttpCode(201)
  @Access('active')
  create(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(reloadTicketCreateRequestSchema))
    body: ReloadTicketCreateRequest,
  ): Promise<ReloadTicketCreateResponse> {
    return this.tickets.create(session, body.idleSeconds);
  }

  @Delete()
  @HttpCode(204)
  @Access('session')
  remove(@CurrentSession() session: AuthenticatedSession): Promise<void> {
    return this.tickets.remove(session);
  }

  @Post('heartbeat')
  @HttpCode(204)
  @Access('active')
  heartbeat(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(reloadTicketHeartbeatRequestSchema))
    body: ReloadTicketHeartbeatRequest,
  ): Promise<void> {
    return this.tickets.heartbeat(session, body.ticketId, body.active);
  }

  @Post('redeem')
  @HttpCode(200)
  @Access('active')
  redeem(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(reloadTicketRedeemRequestSchema))
    body: ReloadTicketRedeemRequest,
  ): Promise<ReloadTicketRedeemResponse> {
    return this.tickets.redeem(session, body.ticketId);
  }
}
