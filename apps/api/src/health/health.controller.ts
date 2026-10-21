import { Controller, Get, HttpStatus, Res } from '@nestjs/common';
import type { Response } from 'express';
import {
  DatabaseHealthService,
  type DependencyStatus,
} from '../database/database-health.service.js';

export interface LivenessResponse {
  status: 'ok';
}

export interface ReadinessResponse {
  status: 'ok' | 'unavailable';
  checks: { database: DependencyStatus };
}

@Controller('health')
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
    const ready = database === 'up';
    res.status(ready ? HttpStatus.OK : HttpStatus.SERVICE_UNAVAILABLE);
    res.setHeader('Cache-Control', 'no-store');
    return { status: ready ? 'ok' : 'unavailable', checks: { database } };
  }
}
