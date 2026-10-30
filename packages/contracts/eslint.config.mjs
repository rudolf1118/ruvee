import { base } from '@ruvee/eslint-config/base';

export default [
  ...base({ tsconfigRootDir: import.meta.dirname }),
  {
    files: ['src/**/*.ts'],
    ignores: ['src/**/*.spec.ts'],
    rules: {
      'no-restricted-imports': [
        'error',
        {
          patterns: [
            { group: ['node:*'], message: 'Contracts must also run in browsers.' },
            {
              group: ['@nestjs/*', 'express'],
              message: 'Contracts must not depend on the server.',
            },
          ],
        },
      ],
    },
  },
];
