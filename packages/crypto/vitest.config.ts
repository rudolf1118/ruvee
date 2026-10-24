import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    include: ['test/**/*.spec.ts'],
    // Argon2id at profile 1 in pure JavaScript (the noble reference) takes seconds per run.
    testTimeout: 120_000,
  },
});
