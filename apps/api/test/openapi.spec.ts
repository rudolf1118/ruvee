import type { NestExpressApplication } from '@nestjs/platform-express';
import { buildOpenApiDocument } from '@ruvee/contracts';
import { DatabaseHealthService } from '../src/database/database-health.service.js';
import { createTestApp } from './create-test-app.js';

interface RouterLayer {
  route?: { path: unknown; methods: Record<string, boolean> };
}

describe('OpenAPI document', () => {
  let app: NestExpressApplication;

  beforeAll(async () => {
    app = await createTestApp({
      override: (builder) =>
        builder.overrideProvider(DatabaseHealthService).useValue({ check: () => 'up' }),
    });
  });

  afterAll(async () => {
    await app.close();
  });

  it('lists exactly the routes the application registers', () => {
    const express = app.getHttpAdapter().getInstance() as { router: { stack: RouterLayer[] } };
    const registered = express.router.stack
      .flatMap(({ route }) =>
        route && typeof route.path === 'string' && !route.path.includes('*')
          ? Object.keys(route.methods).map(
              (method) => `${method.toUpperCase()} ${String(route.path)}`,
            )
          : [],
      )
      .sort();

    const paths = buildOpenApiDocument().paths as Record<string, Record<string, unknown>>;
    const documented = Object.entries(paths)
      .flatMap(([path, operations]) =>
        Object.keys(operations).map((method) => `${method.toUpperCase()} ${path}`),
      )
      .sort();

    expect(registered).toEqual(documented);
  });
});
