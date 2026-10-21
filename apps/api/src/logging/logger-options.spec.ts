import { buildLoggerOptions, pathOnly } from './logger-options.js';

type Serializer = (value: unknown) => unknown;

function serializers() {
  const options = buildLoggerOptions({ NODE_ENV: 'production', LOG_LEVEL: 'info' });
  const pinoHttp = options.pinoHttp as { serializers: Record<'req' | 'res', Serializer> };
  return pinoHttp.serializers;
}

describe('logger options', () => {
  it('strips query strings from logged paths', () => {
    expect(pathOnly('/health/ready?token=abc')).toBe('/health/ready');
    expect(pathOnly(undefined)).toBe('');
  });

  it('logs only an allow-list of request fields', () => {
    const logged = serializers().req({
      id: 'r1',
      method: 'GET',
      url: '/items?q=secret',
      headers: { authorization: 'Bearer abc', cookie: 'sid=1' },
      body: { password: 'x' },
    });
    expect(logged).toEqual({ id: 'r1', method: 'GET', path: '/items' });
  });

  it('logs only the status code of responses', () => {
    expect(serializers().res({ statusCode: 201, headers: { 'set-cookie': 'sid=1' } })).toEqual({
      statusCode: 201,
    });
  });

  it('uses pretty output only in development', () => {
    const dev = buildLoggerOptions({ NODE_ENV: 'development', LOG_LEVEL: 'debug' });
    const prod = buildLoggerOptions({ NODE_ENV: 'production', LOG_LEVEL: 'info' });
    expect(dev.pinoHttp).toHaveProperty('transport');
    expect(prod.pinoHttp).not.toHaveProperty('transport');
  });
});
