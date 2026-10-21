import { next } from '@ruvee/eslint-config/next';

export default [
  { ignores: ['next-env.d.ts', 'playwright-report/**', 'test-results/**'] },
  ...next({ tsconfigRootDir: import.meta.dirname }),
];
