import { base } from '@ruvee/eslint-config/base';

export default [
  ...base({ tsconfigRootDir: import.meta.dirname }),
  {
    files: ['src/**/*.ts'],
    ignores: ['src/**/*.test.ts', 'src/test-support.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            { group: ['node:*'], message: 'The engine runs in browsers and extensions.' },
            { group: ['react', 'react-dom', 'next', 'next/*'], message: 'The engine has no UI.' },
          ],
        },
      ],
    },
  },
];
