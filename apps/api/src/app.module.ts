import { type MiddlewareConsumer, Module, type NestModule, RequestMethod } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_FILTER } from '@nestjs/core';
import { LoggerModule } from 'nestjs-pino';
import type { DestinationStream } from 'pino';
import { AuthModule } from './auth/auth.module.js';
import { AllExceptionsFilter } from './common/all-exceptions.filter.js';
import { HttpConventionsMiddleware } from './common/http-conventions.middleware.js';
import { type Env, validateEnv } from './config/env.js';
import { HealthModule } from './health/health.module.js';
import { buildLoggerOptions, LOG_DESTINATION } from './logging/logger-options.js';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      // Run from apps/api, so the repository-root .env is two levels up.
      envFilePath: ['.env', '../../.env'],
      ignoreEnvFile: process.env.NODE_ENV === 'test',
      validate: validateEnv,
    }),
    LoggerModule.forRootAsync({
      inject: [ConfigService, LOG_DESTINATION],
      providers: [{ provide: LOG_DESTINATION, useValue: null }],
      useFactory: (config: ConfigService<Env, true>, destination: DestinationStream | null) =>
        buildLoggerOptions(
          {
            NODE_ENV: config.get('NODE_ENV', { infer: true }),
            LOG_LEVEL: config.get('LOG_LEVEL', { infer: true }),
          },
          destination ?? undefined,
        ),
    }),
    HealthModule,
    AuthModule,
  ],
  providers: [{ provide: APP_FILTER, useClass: AllExceptionsFilter }],
})
export class AppModule implements NestModule {
  // Nest applies an imported module's middleware first, so the request logger runs before this.
  configure(consumer: MiddlewareConsumer): void {
    consumer
      .apply(HttpConventionsMiddleware)
      .forRoutes({ path: '{/*splat}', method: RequestMethod.ALL });
  }
}
