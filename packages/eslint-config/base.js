import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import globals from 'globals';
import tseslint from 'typescript-eslint';

/**
 * Shared rules for every TypeScript package. Type-aware linting uses the
 * TypeScript project service, so each package's tsconfig.json drives it.
 */
export function base({ tsconfigRootDir }) {
  return tseslint.config(
    { ignores: ['**/dist/**', '**/.next/**', '**/coverage/**', '**/src/generated/**'] },
    js.configs.recommended,
    ...tseslint.configs.strictTypeChecked,
    ...tseslint.configs.stylisticTypeChecked,
    {
      languageOptions: {
        parserOptions: { projectService: true, tsconfigRootDir },
      },
      rules: {
        '@typescript-eslint/consistent-type-imports': [
          'error',
          { fixStyle: 'inline-type-imports' },
        ],
        '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
        '@typescript-eslint/restrict-template-expressions': ['error', { allowNumber: true }],
        eqeqeq: ['error', 'always'],
        'no-console': 'error',
      },
    },
    {
      files: ['**/*.js', '**/*.mjs', '**/*.cjs'],
      ...tseslint.configs.disableTypeChecked,
    },
    {
      files: ['**/scripts/**/*.{js,mjs}'],
      languageOptions: { globals: globals.node },
      rules: { 'no-console': 'off' },
    },
    prettier,
  );
}
