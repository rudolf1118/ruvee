import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Params } from 'nestjs-pino';
import type { Env } from '../config/env.js';

const REQUEST_ID_HEADER = 'x-request-id';
const SAFE_REQUEST_ID = /^[A-Za-z0-9._-]{1,64}$/;
const QUIET_PATHS = new Set(['/health/live', '/health/ready']);

/** Paths only: query strings may carry tokens or other sensitive values. */
export function pathOnly(url: string | undefined): string {
  return (url ?? '').split('?')[0] ?? '';
}

export function requestIdFor(req: IncomingMessage, res: ServerResponse): string {
  const incoming = req.headers[REQUEST_ID_HEADER];
  const id =
    typeof incoming === 'string' && SAFE_REQUEST_ID.test(incoming) ? incoming : randomUUID();
  res.setHeader(REQUEST_ID_HEADER, id);
  return id;
}

export function buildLoggerOptions(env: Pick<Env, 'NODE_ENV' | 'LOG_LEVEL'>): Params {
  const pretty = env.NODE_ENV === 'development';
  return {
    pinoHttp: {
      level: env.LOG_LEVEL,
      genReqId: requestIdFor,
      autoLogging: { ignore: (req) => QUIET_PATHS.has(pathOnly(req.url)) },
      // Serializers allow-list what is logged, so headers, cookies and bodies never reach logs.
      serializers: {
        req: (req: { id: string; method: string; url: string }) => ({
          id: req.id,
          method: req.method,
          path: pathOnly(req.url),
        }),
        res: (res: { statusCode: number }) => ({ statusCode: res.statusCode }),
      },
      redact: {
        paths: ['req.headers', 'res.headers', '*.password', '*.token', '*.authorization'],
        censor: '[redacted]',
      },
      ...(pretty ? { transport: { target: 'pino-pretty', options: { singleLine: true } } } : {}),
    },
  };
}
