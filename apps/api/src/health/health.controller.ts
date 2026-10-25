import { Controller, Get, HttpStatus, Res } from '@nestjs/common';
import type { LivenessResponse, ReadinessResponse } from '@ruvee/contracts';
import type { Response } from 'express';
import { DatabaseHealthService } from '../database/database-health.service.js';
import { Access } from '../sessions/access.decorator.js';

@Controller('health')
@Access('none')
export class HealthController {
  constructor(private readonly database: DatabaseHealthService) {}

  /** The process is running and can serve HTTP. Does not touch dependencies. */
  @Get('live')
  live(): LivenessResponse {
    return { status: 'ok' };
  }

  /** The API can serve traffic: every required dependency is reachable. */
  @Get('ready')
  async ready(@Res({ passthrough: true }) res: Response): Promise<ReadinessResponse> {
    const database = await this.database.check();
    res.setHeader('Cache-Control', 'no-store');
    if (database === 'up') {
      res.status(HttpStatus.OK);
      return { status: 'ok', checks: { database } };
    }
    res.status(HttpStatus.SERVICE_UNAVAILABLE);
    return { status: 'unavailable', checks: { database } };
  }
}
