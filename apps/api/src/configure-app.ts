import type { NestApplicationOptions } from '@nestjs/common';
import { ExpressAdapter, type NestExpressApplication } from '@nestjs/platform-express';
import express from 'express';
import { Logger } from 'nestjs-pino';

/**
 * Options for every application instance. Nest's default body parsers are off:
 * they would accept form bodies and a 100 KB limit before HttpConventionsMiddleware runs.
 */
export const appOptions = { bufferLogs: true, bodyParser: false } satisfies NestApplicationOptions;

/**
 * The HTTP adapter for every application instance. Routing is case-sensitive and strict
 * (predeployment-review R1): `/API/…`, `/Api/…` or `/api/v1/x/` match no handler, so they are a
 * plain 404 and can never reach a handler under a spelling the guard does not expect. The
 * settings are applied to a fresh Express instance before Nest registers any route; Express reads
 * them when it creates its router.
 */
export function createHttpAdapter(): ExpressAdapter {
  const instance = express();
  instance.set('case sensitive routing', true);
  instance.set('strict routing', true);
  return new ExpressAdapter(instance);
}

/** Application-level settings shared by the server entry point and tests. */
export function configureApp(app: NestExpressApplication): NestExpressApplication {
  app.useLogger(app.get(Logger));
  app.disable('x-powered-by');
  app.enableShutdownHooks();
  return app;
}
