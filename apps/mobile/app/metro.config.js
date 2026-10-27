const path = require('node:path');
const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

/**
 * The app consumes the shared packages from their TypeScript sources, so the mobile client runs
 * exactly the code the web app and the extension run; nothing is copied or forked.
 *
 * - `@ruvee/crypto`, `@ruvee/vault` and `@ruvee/contracts` resolve to `packages/<name>/src`.
 * - `@ruvee/crypto-internal/<module>` reaches `packages/crypto/src/<module>.ts` for the two
 *   functions the package does not export yet (shared-change request SC-2 in
 *   docs/mobile/shared-change-requests.md). Only `src/crypto/` may import it.
 * - The packages' relative `./x.js` imports name TypeScript files.
 * - Third-party imports made by shared sources resolve from this app's node_modules, so every
 *   dependency (zod above all) has one copy, at the version pinned here.
 * - `libsodium-wrappers-sumo` (the WebAssembly build behind `initRuveeCrypto`) is replaced by a
 *   module that throws: the app uses native libsodium. The Hermes WebAssembly probe of the
 *   compatibility runner opts back in with RUVEE_WASM_PROBE=1.
 */
const appRoot = __dirname;
const repoRoot = path.resolve(appRoot, '../../..');
const packagesRoot = path.join(repoRoot, 'packages');
const SHARED = {
  '@ruvee/crypto': path.join(packagesRoot, 'crypto/src/index.ts'),
  '@ruvee/vault': path.join(packagesRoot, 'vault/src/index.ts'),
  '@ruvee/contracts': path.join(packagesRoot, 'contracts/src/index.ts'),
};
const CRYPTO_INTERNAL = '@ruvee/crypto-internal/';
const WASM_PROBE = process.env.RUVEE_WASM_PROBE === '1';
const appEntry = path.join(appRoot, 'index.js');
const LIBSODIUM_CJS = {
  'libsodium-wrappers-sumo': path.join(
    appRoot,
    'node_modules/libsodium-wrappers-sumo/dist/modules-sumo/libsodium-wrappers.js',
  ),
  'libsodium-sumo': path.join(
    appRoot,
    'node_modules/libsodium-sumo/dist/modules-sumo/libsodium-sumo.js',
  ),
};
const NODE_BUILTIN = /^(node:)?(fs|path|crypto|url|stream|module|worker_threads|os|util)$/;

function isBare(name) {
  return !name.startsWith('.') && !path.isAbsolute(name);
}

/** @type {import('@react-native/metro-config').MetroConfig} */
const config = {
  watchFolders: [
    path.join(packagesRoot, 'crypto'),
    path.join(packagesRoot, 'vault'),
    path.join(packagesRoot, 'contracts'),
  ],
  resolver: {
    nodeModulesPaths: [path.join(appRoot, 'node_modules')],
    resolveRequest(context, moduleName, platform) {
      if (Object.hasOwn(SHARED, moduleName))
        return { type: 'sourceFile', filePath: SHARED[moduleName] };
      if (moduleName.startsWith(CRYPTO_INTERNAL)) {
        const name = moduleName.slice(CRYPTO_INTERNAL.length);
        if (!/^[a-z-]+$/.test(name)) throw new Error(`Invalid internal module ${moduleName}`);
        return {
          type: 'sourceFile',
          filePath: path.join(packagesRoot, 'crypto/src', `${name}.ts`),
        };
      }
      if (moduleName === 'libsodium-wrappers-sumo' && !WASM_PROBE)
        return {
          type: 'sourceFile',
          filePath: path.join(appRoot, 'src/crypto/no-wasm-libsodium.ts'),
        };
      // The probe uses libsodium.js's CommonJS build: the ESM build uses `import.meta`, which
      // Hermes does not parse. Its Node-only branches name built-ins that are never reached.
      if (Object.hasOwn(LIBSODIUM_CJS, moduleName))
        return { type: 'sourceFile', filePath: LIBSODIUM_CJS[moduleName] };
      if (
        NODE_BUILTIN.test(moduleName) &&
        context.originModulePath.includes(`${path.sep}node_modules${path.sep}`)
      )
        return { type: 'empty' };
      // Development runner only: the portable checks of packages/crypto get the app's own
      // operations from `initRuveeCrypto` (src/compat/portable-index.ts).
      if (
        moduleName === '../../src/index.js' &&
        context.originModulePath.startsWith(path.join(packagesRoot, 'crypto/test') + path.sep)
      )
        return { type: 'sourceFile', filePath: path.join(appRoot, 'src/compat/portable-index.ts') };
      const fromShared = context.originModulePath.startsWith(packagesRoot + path.sep);
      if (fromShared && isBare(moduleName))
        return context.resolveRequest(
          { ...context, originModulePath: appEntry },
          moduleName,
          platform,
        );
      if (fromShared && moduleName.startsWith('.') && moduleName.endsWith('.js')) {
        const candidate = path.resolve(
          path.dirname(context.originModulePath),
          moduleName.slice(0, -3) + '.ts',
        );
        return { type: 'sourceFile', filePath: candidate };
      }
      return context.resolveRequest(context, moduleName, platform);
    },
  },
};

module.exports = mergeConfig(getDefaultConfig(appRoot), config);
