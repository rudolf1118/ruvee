import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['test/**/*.int-spec.ts'],
    testTimeout: 20_000,
    env: { LOG_LEVEL: 'silent' },
  },
});
