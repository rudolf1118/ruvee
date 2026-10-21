import type { NestExpressApplication } from '@nestjs/platform-express';
import { Logger } from 'nestjs-pino';

/** Application-level settings shared by the server entry point and tests. */
export function configureApp(app: NestExpressApplication): NestExpressApplication {
  app.useLogger(app.get(Logger));
  app.disable('x-powered-by');
  app.enableShutdownHooks();
  return app;
}
