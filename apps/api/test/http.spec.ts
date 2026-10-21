import { BadRequestException, Controller, Get } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import {
  DatabaseHealthService,
  type DependencyStatus,
} from '../src/database/database-health.service.js';
import { createTestApp } from './create-test-app.js';

@Controller('test-errors')
class ThrowingController {
  @Get('bad-request')
  badRequest(): never {
    throw new BadRequestException('Title is required');
  }

  @Get('crash')
  crash(): never {
    throw new Error('connection to postgresql://admin:hunter2@db failed');
  }
}

describe('HTTP behaviour', () => {
  let app: NestExpressApplication;
  let databaseStatus: DependencyStatus;

  beforeAll(async () => {
    app = await createTestApp({
      controllers: [ThrowingController],
      override: (builder) =>
        builder
          .overrideProvider(DatabaseHealthService)
          .useValue({ check: () => Promise.resolve(databaseStatus) }),
    });
  });

  afterAll(async () => {
    await app.close();
  });

  describe('GET /health/live', () => {
    it('reports ok even when the database is down', async () => {
      databaseStatus = 'down';
      const res = await request(app.getHttpServer()).get('/health/live').expect(200);
      expect(res.body).toEqual({ status: 'ok' });
    });
  });

  describe('GET /health/ready', () => {
    it('returns 200 when the database is reachable', async () => {
      databaseStatus = 'up';
      const res = await request(app.getHttpServer()).get('/health/ready').expect(200);
      expect(res.body).toEqual({ status: 'ok', checks: { database: 'up' } });
      expect(res.headers['cache-control']).toBe('no-store');
    });

    it('returns 503 when the database is unreachable', async () => {
      databaseStatus = 'down';
      const res = await request(app.getHttpServer()).get('/health/ready').expect(503);
      expect(res.body).toEqual({ status: 'unavailable', checks: { database: 'down' } });
    });
  });

  describe('errors', () => {
    it('renders client errors with a consistent shape', async () => {
      const res = await request(app.getHttpServer()).get('/test-errors/bad-request').expect(400);
      expect(res.body).toEqual({
        statusCode: 400,
        error: 'BAD_REQUEST',
        message: 'Title is required',
        requestId: expect.any(String) as string,
      });
    });

    it('hides internal details of unexpected errors', async () => {
      const res = await request(app.getHttpServer()).get('/test-errors/crash').expect(500);
      expect(res.body).toMatchObject({
        statusCode: 500,
        error: 'INTERNAL_SERVER_ERROR',
        message: 'Internal server error',
      });
      expect(JSON.stringify(res.body)).not.toContain('hunter2');
    });

    it('returns 404 in the same shape for unknown routes', async () => {
      const res = await request(app.getHttpServer()).get('/nope').expect(404);
      expect(res.body).toMatchObject({ statusCode: 404, error: 'NOT_FOUND' });
    });
  });

  describe('request ids', () => {
    it('echoes a well-formed incoming x-request-id', async () => {
      const res = await request(app.getHttpServer())
        .get('/nope')
        .set('x-request-id', 'trace-123')
        .expect(404);
      expect(res.headers['x-request-id']).toBe('trace-123');
      expect(res.body).toMatchObject({ requestId: 'trace-123' });
    });

    it('replaces a malformed x-request-id with a generated one', async () => {
      const res = await request(app.getHttpServer())
        .get('/health/live')
        .set('x-request-id', 'bad id <with> spaces')
        .expect(200);
      expect(res.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
    });
  });

  it('does not advertise the framework', async () => {
    const res = await request(app.getHttpServer()).get('/health/live');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});
