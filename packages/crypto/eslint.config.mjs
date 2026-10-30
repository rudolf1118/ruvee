import { base } from '@ruvee/eslint-config/base';

const browserSafe = [
  { group: ['node:*'], message: 'packages/crypto must run unchanged in browsers and workers.' },
  { group: ['@noble/*'], message: 'noble is the independent test oracle, never production code.' },
];
const libsodium = {
  group: ['libsodium-wrappers-sumo', 'libsodium-sumo'],
  message: 'Only src/libsodium.ts touches the library; use the guarded Primitives.',
};
const testOnly = {
  group: ['**/testing/**', './testing', '../testing'],
  message: 'The fixed-nonce entry point is test-only (INV-02).',
};

export default [
  ...base({ tsconfigRootDir: import.meta.dirname }),
  {
    files: ['src/**/*.ts'],
    ignores: ['src/libsodium.ts', 'src/testing/**'],
    rules: {
      'no-restricted-imports': ['error', { patterns: [...browserSafe, libsodium, testOnly] }],
    },
  },
  {
    files: ['src/libsodium.ts'],
    rules: { 'no-restricted-imports': ['error', { patterns: [...browserSafe, testOnly] }] },
  },
  {
    files: ['src/testing/**/*.ts'],
    rules: { 'no-restricted-imports': ['error', { patterns: [...browserSafe, libsodium] }] },
  },
];
