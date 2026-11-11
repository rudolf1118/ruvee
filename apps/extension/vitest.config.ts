import { defineConfig } from 'vitest/config';

export default defineConfig({
  define: { __RUVEE_TEST__: 'false' },
  test: {
    globals: true,
    include: ['src/**/*.test.ts'],
  },
});
