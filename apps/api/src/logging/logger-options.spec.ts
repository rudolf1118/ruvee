import type { IncomingMessage } from 'node:http';
import {
  buildLoggerOptions,
  isQuietProbe,
  pathOnly,
  routeTemplate,
  UNMATCHED_ROUTE,
} from './logger-options.js';

type Serializer = (value: unknown) => unknown;

function pinoHttpOptions() {
  const options = buildLoggerOptions({ NODE_ENV: 'production', LOG_LEVEL: 'info' });
  return options.pinoHttp as { serializers: Record<'req' | 'res', Serializer> };
}

const asRequest = (value: object) => value as IncomingMessage;

describe('logger options', () => {
  it('strips query strings from paths used for log filtering', () => {
    expect(pathOnly('/health/ready?token=abc')).toBe('/health/ready');
    expect(pathOnly(undefined)).toBe('');
  });

  it('skips access logs only for health probes', () => {
    expect(isQuietProbe({ method: 'GET', url: '/health/live' })).toBe(true);
    expect(isQuietProbe({ method: 'HEAD', url: '/health/ready?x=1' })).toBe(true);
    expect(isQuietProbe({ method: 'POST', url: '/health/live' })).toBe(false);
    expect(isQuietProbe({ method: 'GET', url: '/health/livez' })).toBe(false);
  });

  it('logs only an allow-list of request fields, without the path', () => {
    const logged = pinoHttpOptions().serializers.req({
      id: 'r1',
      method: 'GET',
      url: '/items/secret-id?q=secret',
      headers: { authorization: 'Bearer abc', cookie: 'sid=1' },
      body: { password: 'x' },
    });
    expect(logged).toEqual({ id: 'r1', method: 'GET' });
  });

  it('logs only the status code of responses', () => {
    expect(pinoHttpOptions().serializers.res({ statusCode: 201, headers: { a: 'b' } })).toEqual({
      statusCode: 201,
    });
  });

  it('uses the route template, or a fixed value when no route matched', () => {
    expect(routeTemplate(asRequest({ route: { path: '/items/:itemId' }, baseUrl: '' }))).toBe(
      '/items/:itemId',
    );
    expect(routeTemplate(asRequest({ url: '/items/secret-id' }))).toBe(UNMATCHED_ROUTE);
    expect(routeTemplate(asRequest({ route: { path: /regex/ } }))).toBe(UNMATCHED_ROUTE);
    // Nest mounts middleware on this route; it is all that matched for an unknown path.
    expect(routeTemplate(asRequest({ route: { path: '{/*splat}' } }))).toBe(UNMATCHED_ROUTE);
  });

  it('uses pretty output only in development, and never with a custom destination', () => {
    const dev = buildLoggerOptions({ NODE_ENV: 'development', LOG_LEVEL: 'debug' });
    const prod = buildLoggerOptions({ NODE_ENV: 'production', LOG_LEVEL: 'info' });
    expect(dev.pinoHttp).toHaveProperty('transport');
    expect(prod.pinoHttp).not.toHaveProperty('transport');
    const captured = buildLoggerOptions(
      { NODE_ENV: 'development', LOG_LEVEL: 'debug' },
      { write: () => undefined },
    );
    expect(Array.isArray(captured.pinoHttp)).toBe(true);
    expect((captured.pinoHttp as object[])[0]).not.toHaveProperty('transport');
  });
});
