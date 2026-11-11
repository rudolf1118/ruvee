import { Body, Controller, Get, HttpCode, Post, Query } from '@nestjs/common';
import {
  commitRequestSchema,
  SYNC_PAGE_MAX,
  syncChangesQuerySchema,
  type CommitRequest,
  type CommitResponse,
  type SyncChangesQuery,
  type SyncChangesResponse,
  type VaultStateResponse,
} from '@ruvee/contracts';
import { ContractValidationPipe } from '../common/contract-validation.pipe.js';
import { Access, CurrentSession } from '../sessions/access.decorator.js';
import type { AuthenticatedSession } from '../sessions/session.service.js';
import { SyncService } from './sync.service.js';

@Controller('api/v1')
export class VaultController {
  constructor(private readonly sync: SyncService) {}

  @Get('vault')
  @Access('active')
  state(@CurrentSession() session: AuthenticatedSession): Promise<VaultStateResponse> {
    return this.sync.state(session.accountId);
  }

  @Get('sync/changes')
  @Access('active')
  changes(
    @CurrentSession() session: AuthenticatedSession,
    @Query(new ContractValidationPipe(syncChangesQuerySchema)) query: SyncChangesQuery,
  ): Promise<SyncChangesResponse> {
    return this.sync.changes(
      session.accountId,
      Number(query.since),
      query.limit === undefined ? SYNC_PAGE_MAX : Number(query.limit),
    );
  }

  @Post('sync/commits')
  @HttpCode(200)
  @Access('active')
  commit(
    @CurrentSession() session: AuthenticatedSession,
    @Body(new ContractValidationPipe(commitRequestSchema)) body: CommitRequest,
  ): Promise<CommitResponse> {
    return this.sync.commit(session.accountId, session.deviceId, body);
  }
}
