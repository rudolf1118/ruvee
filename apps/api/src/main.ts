import 'reflect-metadata';
import { ConfigService } from '@nestjs/config';
import { NestFactory } from '@nestjs/core';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AppModule } from './app.module.js';
import type { Env } from './config/env.js';
import { appOptions, configureApp, createHttpAdapter } from './configure-app.js';

async function bootstrap(): Promise<void> {
  const app = configureApp(
    await NestFactory.create<NestExpressApplication>(AppModule, createHttpAdapter(), appOptions),
  );
  const config = app.get(ConfigService<Env, true>);
  await app.listen(
    config.get('API_PORT', { infer: true }),
    config.get('API_HOST', { infer: true }),
  );
}

await bootstrap();
