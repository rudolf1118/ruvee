import { next } from '@ruvee/eslint-config/next';

export default [
  {
    ignores: [
      'next-env.d.ts',
      'playwright-report/**',
      'test-results/**',
      'out/**',
      'out-diagnostics/**',
    ],
  },
  ...next({ tsconfigRootDir: import.meta.dirname }),
  {
    files: ['src/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            {
              name: 'libsodium-wrappers-sumo',
              message: 'The web app must use @ruvee/crypto; do not call libsodium.js directly.',
            },
            {
              name: 'libsodium-sumo',
              message: 'The web app must use @ruvee/crypto; do not call libsodium.js directly.',
            },
          ],
        },
      ],
    },
  },
];
