import { defineConfig } from 'vitest/config';

export default defineConfig({
  define: { __RUVEE_TEST__: 'false', __RUVEE_BUILD__: '"unit-test"' },
  test: {
    globals: true,
    include: ['src/**/*.test.ts'],
  },
});
