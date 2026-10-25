import { next } from '@ruvee/eslint-config/next';

// The React and accessibility rules of the web app's preset; the Next.js rules simply never fire.
export default [
  { ignores: ['dist/**', 'dist-test/**', 'playwright-report/**', 'test-results/**'] },
  ...next({ tsconfigRootDir: import.meta.dirname }),
  {
    files: ['src/**/*.{ts,tsx}'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          paths: [
            { name: 'libsodium-wrappers-sumo', message: 'Use @ruvee/crypto.' },
            { name: 'libsodium-sumo', message: 'Use @ruvee/crypto.' },
          ],
        },
      ],
    },
  },
];
