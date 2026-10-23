import type { NestApplicationOptions } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Logger } from 'nestjs-pino';

/**
 * Options for every application instance. Nest's default body parsers are off:
 * they would accept form bodies and a 100 KB limit before HttpConventionsMiddleware runs.
 */
export const appOptions = { bufferLogs: true, bodyParser: false } satisfies NestApplicationOptions;

/** Application-level settings shared by the server entry point and tests. */
export function configureApp(app: NestExpressApplication): NestExpressApplication {
  app.useLogger(app.get(Logger));
  app.disable('x-powered-by');
  app.enableShutdownHooks();
  return app;
}
