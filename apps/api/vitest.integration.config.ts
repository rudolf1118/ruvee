import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['test/**/*.int-spec.ts'],
    testTimeout: 20_000,
    env: {
      LOG_LEVEL: 'silent',
      OPAQUE_SERVER_SETUP_FILE: 'test/fixtures/opaque-server-setup.test-only',
      PUBLIC_ORIGIN: 'http://127.0.0.1:3100',
    },
  },
});
