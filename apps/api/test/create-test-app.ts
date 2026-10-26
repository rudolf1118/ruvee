import type { Type } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { Test, type TestingModuleBuilder } from '@nestjs/testing';
import { AppModule } from '../src/app.module.js';
import { appOptions, configureApp, createHttpAdapter } from '../src/configure-app.js';

export async function createTestApp(
  options: {
    controllers?: Type[];
    override?: (builder: TestingModuleBuilder) => TestingModuleBuilder;
  } = {},
): Promise<NestExpressApplication> {
  let builder = Test.createTestingModule({
    imports: [AppModule],
    controllers: options.controllers ?? [],
  });
  if (options.override) builder = options.override(builder);
  const moduleRef = await builder.compile();
  const app = configureApp(
    moduleRef.createNestApplication<NestExpressApplication>(createHttpAdapter(), appOptions),
  );
  await app.init();
  return app;
}
