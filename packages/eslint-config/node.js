import globals from 'globals';
import tseslint from 'typescript-eslint';
import { base } from './base.js';

/** Rules for Node.js services (NestJS). */
export function node({ tsconfigRootDir }) {
  return tseslint.config(...base({ tsconfigRootDir }), {
    languageOptions: { globals: globals.node },
    rules: {
      // NestJS modules and DTOs are classes by design.
      '@typescript-eslint/no-extraneous-class': 'off',
    },
  });
}
