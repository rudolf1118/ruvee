import { gzipSync } from 'node:zlib';
import type { NestExpressApplication } from '@nestjs/platform-express';
import {
  API_ERRORS,
  errorResponseSchema,
  livenessResponseSchema,
  MAX_REQUEST_BODY_BYTES,
  notReadyResponseSchema,
  readyResponseSchema,
} from '@ruvee/contracts';
import request from 'supertest';
import {
  DatabaseHealthService,
  type DependencyStatus,
} from '../src/database/database-health.service.js';
import { createTestApp } from './create-test-app.js';
import { SENTINEL, TestOnlyController } from './fixtures.js';

const blob = Buffer.alloc(32, 7).toString('base64url');
const validBody = { label: 'ok', blob };

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status).toBe(API_ERRORS[code].status);
  const parsed = errorResponseSchema.parse(res.body);
  expect(parsed.error).toBe(code);
  expect(res.headers['x-request-id']).toBe(parsed.requestId);
  expect(res.headers['cache-control']).toBe('no-store');
  expect(res.text).not.toContain(SENTINEL);
  return parsed;
}

describe('HTTP behaviour', () => {
  let app: NestExpressApplication;
  let databaseStatus: DependencyStatus;
  const http = () => request(app.getHttpServer());

  beforeAll(async () => {
    app = await createTestApp({
      controllers: [TestOnlyController],
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
      const res = await http().get('/health/live').expect(200);
      expect(livenessResponseSchema.parse(res.body)).toEqual({ status: 'ok' });
      expect(res.headers['cache-control']).toBe('no-store');
    });
  });

  describe('GET /health/ready', () => {
    it('returns 200 when the database is reachable', async () => {
      databaseStatus = 'up';
      const res = await http().get('/health/ready').expect(200);
      expect(readyResponseSchema.parse(res.body)).toEqual({
        status: 'ok',
        checks: { database: 'up' },
      });
      expect(res.headers['cache-control']).toBe('no-store');
    });

    it('returns 503 when the database is unreachable', async () => {
      databaseStatus = 'down';
      const res = await http().get('/health/ready').expect(503);
      expect(notReadyResponseSchema.parse(res.body)).toEqual({
        status: 'unavailable',
        checks: { database: 'down' },
      });
    });

    it('ignores a request body on GET instead of parsing it', async () => {
      databaseStatus = 'up';
      await http()
        .get('/health/ready')
        .set('Content-Type', 'text/plain')
        .send(`{"broken": ${SENTINEL}`)
        .expect(200);
    });
  });

  describe('errors', () => {
    it('replaces framework messages with the fixed message for the code', async () => {
      const res = await http().get('/test-only/bad-request');
      const body = expectError(res, 'invalid_request');
      expect(body.message).toBe(API_ERRORS.invalid_request.message);
      expect(body).not.toHaveProperty('details');
    });

    it('hides internal details of unexpected errors', async () => {
      const res = await http().get('/test-only/crash');
      expectError(res, 'internal_error');
      expect(res.text).not.toMatch(/postgresql|at .*\.ts|stack/i);
    });

    it('treats HTTP exceptions without a contract code as internal errors', async () => {
      expectError(await http().get('/test-only/forbidden'), 'internal_error');
    });

    it('returns not_found for unknown routes without repeating the path', async () => {
      const res = await http().get(`/nope/${SENTINEL}?token=${SENTINEL}`);
      expectError(res, 'not_found');
    });
  });

  describe('request bodies', () => {
    it('accepts a valid JSON body', async () => {
      const res = await http().post('/test-only/echo').send(validBody).expect(200);
      expect(res.body).toEqual({ fields: ['blob', 'label'] });
      expect(res.headers['cache-control']).toBe('no-store');
    });

    it('accepts an explicit UTF-8 charset', async () => {
      await http()
        .post('/test-only/echo')
        .set('Content-Type', 'application/json; charset=UTF-8')
        .send(JSON.stringify(validBody))
        .expect(200);
    });

    it('rejects malformed JSON without quoting it', async () => {
      const res = await http()
        .post('/test-only/echo')
        .set('Content-Type', 'application/json')
        .send(`{"label": "${SENTINEL}", "blob": ${SENTINEL}`);
      expectError(res, 'malformed_json');
    });

    it('rejects JSON that is not an object or array', async () => {
      const res = await http()
        .post('/test-only/echo')
        .set('Content-Type', 'application/json')
        .send(`"${SENTINEL}"`);
      expectError(res, 'malformed_json');
    });

    it.each([
      ['text/plain', `password=${SENTINEL}`],
      ['application/x-www-form-urlencoded', `password=${SENTINEL}`],
      ['application/json; charset=latin1', JSON.stringify(validBody)],
      ['application/json; version=2', JSON.stringify(validBody)],
      ['application/jsonx', JSON.stringify(validBody)],
    ])('rejects the content type %s', async (contentType, payload) => {
      const res = await http()
        .post('/test-only/echo')
        .set('Content-Type', contentType)
        .send(payload);
      expectError(res, 'unsupported_media_type');
    });

    it('rejects a body without a content type', async () => {
      const res = await http()
        .post('/test-only/echo')
        .set('Content-Type', '')
        .send(Buffer.from(JSON.stringify(validBody)));
      expectError(res, 'unsupported_media_type');
    });

    it('rejects compressed bodies', async () => {
      const res = await http()
        .post('/test-only/echo')
        .set('Content-Type', 'application/json')
        .set('Content-Encoding', 'gzip')
        .send(JSON.stringify(validBody));
      expectError(res, 'unsupported_media_type');
    });

    it('refuses a gzip body with trailing bytes and keeps serving (GHSA-27r3-jxmh-p828)', async () => {
      // The advisory's payload: one valid compressed frame, then trailing bytes. With
      // `inflate: false` no decompression stream is ever created, so nothing can throw later.
      const payload = Buffer.concat([
        gzipSync(Buffer.from(JSON.stringify(validBody))),
        Buffer.from('trailing bytes after the gzip frame'),
      ]);
      const res = await http()
        .post('/test-only/echo')
        .set('Content-Type', 'application/json')
        .set('Content-Encoding', 'gzip')
        .send(payload);
      expectError(res, 'unsupported_media_type');
      await new Promise((resolve) => setTimeout(resolve, 50));
      await http().get('/health/live').expect(200);
    });

    it('accepts a body at the size limit and rejects one byte more', async () => {
      const json = JSON.stringify(validBody);
      const exact = `${json.slice(0, -1)}${' '.repeat(MAX_REQUEST_BODY_BYTES - json.length)}}`;
      expect(Buffer.byteLength(exact)).toBe(MAX_REQUEST_BODY_BYTES);
      await http()
        .post('/test-only/echo')
        .set('Content-Type', 'application/json')
        .send(exact)
        .expect(200);
      const res = await http()
        .post('/test-only/echo')
        .set('Content-Type', 'application/json')
        .send(`${exact} `);
      expectError(res, 'payload_too_large');
    });

    it('rejects an oversized body that contains a secret', async () => {
      const res = await http()
        .post('/test-only/echo')
        .send({ ...validBody, label: SENTINEL.repeat(4096) });
      expectError(res, 'payload_too_large');
    });

    it('rejects a missing body', async () => {
      const body = expectError(await http().post('/test-only/echo'), 'invalid_request');
      expect(body).toMatchObject({ details: { issues: [{ path: [], code: 'invalid_type' }] } });
    });

    it('reports invalid fields by path and code only', async () => {
      const res = await http()
        .post('/test-only/echo')
        .send({ label: SENTINEL.repeat(2), blob: `${SENTINEL}==`, options: { count: 11 } });
      const body = expectError(res, 'invalid_request');
      expect(body).toMatchObject({
        details: {
          issues: expect.arrayContaining([
            { path: ['label'], code: 'too_big' },
            { path: ['blob'], code: 'invalid_format' },
            { path: ['options', 'count'], code: 'too_big' },
          ]) as unknown,
        },
      });
    });

    it('rejects unknown fields without naming them', async () => {
      const res = await http()
        .post('/test-only/echo')
        .send({ ...validBody, password: SENTINEL, [SENTINEL]: 1, options: { count: 1, x: 2 } });
      const body = expectError(res, 'invalid_request');
      expect(body.error === 'invalid_request' && body.details?.issues).toHaveLength(2);
      expect(body).toMatchObject({
        details: {
          issues: expect.arrayContaining([
            { path: [], code: 'unknown_field' },
            { path: ['options'], code: 'unknown_field' },
          ]) as unknown,
        },
      });
      expect(res.text).not.toContain('password');
    });

    it('rejects a __proto__ key as an unknown field', async () => {
      const res = await http()
        .post('/test-only/echo')
        .set('Content-Type', 'application/json')
        .send(`{"label":"ok","blob":"${blob}","__proto__":{"admin":true}}`);
      expectError(res, 'invalid_request');
    });

    it('checks the decoded length of byte fields', async () => {
      const short = Buffer.alloc(31).toString('base64url');
      const res = await http()
        .post('/test-only/echo')
        .send({ ...validBody, blob: short });
      expect(expectError(res, 'invalid_request')).toMatchObject({
        details: { issues: [{ path: ['blob'], code: 'too_small' }] },
      });
    });

    it('bounds array lengths', async () => {
      const res = await http()
        .post('/test-only/echo')
        .send({ ...validBody, tags: ['a', 'b', 'c', 'd', 'e'] });
      expect(expectError(res, 'invalid_request')).toMatchObject({
        details: { issues: [{ path: ['tags'], code: 'too_big' }] },
      });
    });
  });

  describe('request ids', () => {
    it('echoes a well-formed incoming x-request-id', async () => {
      const res = await http().get('/nope').set('x-request-id', 'trace-123');
      expect(res.headers['x-request-id']).toBe('trace-123');
      expect(expectError(res, 'not_found').requestId).toBe('trace-123');
    });

    it.each([`${SENTINEL} with spaces`, 'x'.repeat(65), 'a/b', ''])(
      'replaces the malformed x-request-id %j with a generated one',
      async (id) => {
        const res = await http().get('/nope').set('x-request-id', id);
        expect(res.headers['x-request-id']).toMatch(/^[0-9a-f-]{36}$/);
        expect(expectError(res, 'not_found').requestId).toBe(res.headers['x-request-id']);
      },
    );

    it('gives requests rejected before routing a request id too', async () => {
      const res = await http()
        .post('/test-only/echo')
        .set('Content-Type', 'text/plain')
        .set('x-request-id', 'trace-415')
        .send('x');
      expect(expectError(res, 'unsupported_media_type').requestId).toBe('trace-415');
    });
  });

  it('does not advertise the framework', async () => {
    const res = await http().get('/health/live');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });
});
