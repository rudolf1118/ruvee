import { randomUUID } from 'node:crypto';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { REQUEST_ID_HEADER, REQUEST_ID_PATTERN } from '@ruvee/contracts';
import type { Params } from 'nestjs-pino';
import type { DestinationStream } from 'pino';
import type { Env } from '../config/env.js';

const QUIET_PATHS = new Set(['/health/live', '/health/ready']);

/** Logged instead of a path when no route matched, or the request was rejected before routing. */
export const UNMATCHED_ROUTE = '(unmatched)';

/** Injection token for a log destination other than stdout. Tests use it to capture logs. */
export const LOG_DESTINATION = Symbol('LOG_DESTINATION');

/** Paths only: query strings may carry tokens or other sensitive values. */
export function pathOnly(url: string | undefined): string {
  return (url ?? '').split('?')[0] ?? '';
}

/** Health probes are not access-logged. Any other request to those paths is. */
export function isQuietProbe(req: Pick<IncomingMessage, 'method' | 'url'>): boolean {
  return (req.method === 'GET' || req.method === 'HEAD') && QUIET_PATHS.has(pathOnly(req.url));
}

export function requestIdFor(req: IncomingMessage, res: ServerResponse): string {
  const incoming = req.headers[REQUEST_ID_HEADER];
  const id =
    typeof incoming === 'string' && REQUEST_ID_PATTERN.test(incoming) ? incoming : randomUUID();
  res.setHeader(REQUEST_ID_HEADER, id);
  return id;
}

/**
 * The Express route template, such as `/items/:itemId`, so identifiers in
 * paths never reach the logs. Only known once routing has run. Nest mounts
 * middleware on wildcard routes, which stay in `req.route` when no controller
 * route matches; controllers must therefore not declare wildcard routes.
 */
export function routeTemplate(req: IncomingMessage): string {
  const { route, baseUrl } = req as IncomingMessage & {
    route?: { path?: unknown };
    baseUrl?: unknown;
  };
  if (typeof route?.path !== 'string' || route.path.includes('*')) return UNMATCHED_ROUTE;
  return `${typeof baseUrl === 'string' ? baseUrl : ''}${route.path}`;
}

/** The completion log line: status, timing and route template. Errors are logged by the filter. */
function completionObject(req: IncomingMessage, res: ServerResponse, value: object) {
  const { responseTime } = value as { responseTime?: unknown };
  return { res, responseTime, route: routeTemplate(req) };
}

export function buildLoggerOptions(
  env: Pick<Env, 'NODE_ENV' | 'LOG_LEVEL'>,
  destination?: DestinationStream,
): Params {
  const pretty = env.NODE_ENV === 'development' && destination === undefined;
  const options = {
    level: env.LOG_LEVEL,
    genReqId: requestIdFor,
    autoLogging: { ignore: isQuietProbe },
    customSuccessObject: completionObject,
    customErrorObject: (
      req: IncomingMessage,
      res: ServerResponse,
      _error: unknown,
      value: object,
    ) => completionObject(req, res, value),
    // Serializers allow-list what is logged, so paths, headers, cookies and bodies never reach logs.
    serializers: {
      req: (req: { id: string; method: string }) => ({ id: req.id, method: req.method }),
      res: (res: { statusCode: number }) => ({ statusCode: res.statusCode }),
    },
    redact: {
      paths: ['req.headers', 'res.headers', '*.password', '*.token', '*.authorization'],
      censor: '[redacted]',
    },
    ...(pretty ? { transport: { target: 'pino-pretty', options: { singleLine: true } } } : {}),
  };
  return { pinoHttp: destination ? [options, destination] : options };
}
