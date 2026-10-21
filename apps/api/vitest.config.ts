import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['src/**/*.spec.ts', 'test/**/*.spec.ts'],
    env: {
      // Never connected to: these tests stub the database check.
      DATABASE_URL: 'postgresql://ruvee:unused@127.0.0.1:9/ruvee_unit',
      LOG_LEVEL: 'silent',
    },
  },
});
