import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['src/**/*.spec.ts', 'test/**/*.spec.ts'],
    env: {
      // Never connected to: these tests stub the database check.
      DATABASE_URL: 'postgresql://ruvee:unused@127.0.0.1:9/ruvee_unit',
      LOG_LEVEL: 'silent',
      OPAQUE_SERVER_SETUP_FILE: 'test/fixtures/opaque-server-setup.test-only',
      PUBLIC_ORIGIN: 'http://127.0.0.1:3100',
    },
  },
});
