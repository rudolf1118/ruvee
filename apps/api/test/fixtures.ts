import {
  BadRequestException,
  Body,
  Controller,
  ForbiddenException,
  Get,
  HttpCode,
  Param,
  Post,
} from '@nestjs/common';
import { base64urlBytes } from '@ruvee/contracts';
import { z } from 'zod';
import { ContractValidationPipe } from '../src/common/contract-validation.pipe.js';
import { Access } from '../src/sessions/access.decorator.js';

/** MaintenanceService for unit tests without a database: an installation never restored. */
export const neverRestored = {
  state: () => Promise.resolve('open' as const),
  isOpen: () => Promise.resolve(true),
  gate: () => Promise.resolve(),
};

/** InstanceLockService for unit tests without a database: this process is the serving one. */
export const servingProcess = { held: true, assertServing: () => undefined };

/** Synthetic secret. It must never appear in a response or a log line. */
export const SENTINEL = 'SENTINEL-7f3a9c-not-a-real-secret';

export const testBodySchema = z.strictObject({
  label: z.string().min(1).max(32),
  blob: base64urlBytes({ length: 32 }),
  options: z.strictObject({ count: z.int().min(0).max(10) }).optional(),
  tags: z.array(z.string().max(8)).max(4).optional(),
});

/** Test-only routes. They are never registered by the application module. */
@Controller('test-only')
@Access('none')
export class TestOnlyController {
  @Post('echo')
  @HttpCode(200)
  echo(@Body(new ContractValidationPipe(testBodySchema)) body: z.infer<typeof testBodySchema>) {
    // Field names only, never values.
    return { fields: Object.keys(body).sort() };
  }

  @Get('items/:itemId')
  item(@Param('itemId') itemId: string): never {
    throw new Error(`lookup failed for ${itemId} with password ${SENTINEL}`);
  }

  @Get('crash')
  crash(): never {
    throw new Error(`connection to postgresql://admin:${SENTINEL}@db failed`);
  }

  @Get('bad-request')
  badRequest(): never {
    throw new BadRequestException(`Title ${SENTINEL} is required`);
  }

  @Get('forbidden')
  forbidden(): never {
    throw new ForbiddenException(SENTINEL);
  }
}
