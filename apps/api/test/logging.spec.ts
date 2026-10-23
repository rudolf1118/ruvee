import { Writable } from 'node:stream';
import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { LOG_DESTINATION, UNMATCHED_ROUTE } from '../src/logging/logger-options.js';
import { SENTINEL, TestOnlyController } from './fixtures.js';

// The configuration is read when the app module is imported, so it is imported after this.
vi.stubEnv('LOG_LEVEL', 'trace');

interface LogLine {
  msg?: string;
  route?: string;
  req?: Record<string, unknown>;
  res?: { statusCode?: number };
  errorKind?: string;
  frames?: string[];
  [key: string]: unknown;
}

describe('logs', () => {
  const raw: string[] = [];
  let app: NestExpressApplication;
  const http = () => request(app.getHttpServer());

  const lines = () => raw.map((line) => JSON.parse(line) as LogLine);
  const completion = (id: string) =>
    lines().find((line) => line.req?.id === id && line.res?.statusCode !== undefined);

  beforeAll(async () => {
    const destination = new Writable({
      write(chunk: Buffer, _encoding, callback) {
        raw.push(...chunk.toString('utf8').split('\n').filter(Boolean));
        callback();
      },
    });
    const { createTestApp } = await import('./create-test-app.js');
    app = await createTestApp({
      controllers: [TestOnlyController],
      override: (builder) => builder.overrideProvider(LOG_DESTINATION).useValue(destination),
    });

    const secretHeaders = {
      Authorization: `Bearer ${SENTINEL}`,
      Cookie: `__Host-ruvee_session=${SENTINEL}`,
      'X-Ruvee-Token': SENTINEL,
    };
    await http()
      .get(`/test-only/items/${SENTINEL}?token=${SENTINEL}`)
      .set(secretHeaders)
      .set('x-request-id', 'log-item');
    await http().get('/test-only/crash').set('x-request-id', 'log-crash');
    await http().get('/test-only/bad-request').set('x-request-id', 'log-bad');
    await http().get('/test-only/forbidden').set('x-request-id', 'log-forbidden');
    await http().get(`/nope/${SENTINEL}?q=${SENTINEL}`).set('x-request-id', 'log-404');
    await http().get('/nope').set('x-request-id', `${SENTINEL} invalid`);
    await http()
      .post('/test-only/echo')
      .set(secretHeaders)
      .set('Content-Type', 'application/json')
      .set('x-request-id', 'log-malformed')
      .send(`{"password": ${SENTINEL}`);
    await http()
      .post('/test-only/echo')
      .set('x-request-id', 'log-too-large')
      .send({ password: SENTINEL.repeat(4096) });
    await http()
      .post('/test-only/echo')
      .set('x-request-id', 'log-unknown-field')
      .send({ label: 'ok', blob: SENTINEL, password: SENTINEL, [SENTINEL]: SENTINEL });
    await http()
      .post('/test-only/echo')
      .set('Content-Type', 'text/plain')
      .set('x-request-id', 'log-415')
      .send(`password=${SENTINEL}`);
    // Completion lines are written on the response's 'finish' event.
    await new Promise((resolve) => setImmediate(resolve));
  });

  afterAll(async () => {
    await app.close();
    vi.unstubAllEnvs();
  });

  it('captured log output', () => {
    expect(raw.length).toBeGreaterThan(10);
  });

  it('never contains the sentinel secret', () => {
    for (const line of raw) expect(line).not.toContain(SENTINEL);
  });

  it('never logs paths, query strings, headers or bodies', () => {
    for (const line of lines()) {
      expect(Object.keys(line.req ?? {}).sort()).toEqual(line.req ? ['id', 'method'] : []);
      expect(line).not.toHaveProperty('body');
      expect(line).not.toHaveProperty('headers');
      expect(JSON.stringify(line)).not.toMatch(/\/nope|token=|Bearer|__Host-/);
    }
  });

  it('logs the route template for matched routes', () => {
    expect(completion('log-item')).toMatchObject({
      route: '/test-only/items/:itemId',
      res: { statusCode: 500 },
    });
  });

  it('logs a fixed value for unknown routes and requests rejected before routing', () => {
    for (const id of ['log-404', 'log-malformed', 'log-too-large', 'log-415']) {
      expect(completion(id), id).toMatchObject({ route: UNMATCHED_ROUTE });
    }
    expect(completion('log-unknown-field')).toMatchObject({
      route: '/test-only/echo',
      res: { statusCode: 400 },
    });
  });

  it('logs unexpected errors by class and stack frames, without the message', () => {
    const errors = lines().filter((line) => line.msg === 'Unhandled exception');
    expect(errors.map((line) => line.req?.id).sort()).toEqual(['log-crash', 'log-item']);
    for (const line of errors) {
      expect(line.errorKind).toBe('Error');
      expect(line.frames?.length).toBeGreaterThan(0);
      expect(line).not.toHaveProperty('err');
    }
    expect(lines().find((line) => line.msg === 'Unmapped HTTP exception')).toMatchObject({
      status: 403,
      errorKind: 'ForbiddenException',
    });
  });
});
