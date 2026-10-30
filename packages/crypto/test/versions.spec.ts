import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';
import sodium from 'libsodium-wrappers-sumo';
import { PINNED_LIBSODIUM_VERSION } from '../src/libsodium.js';

const root = new URL('../', import.meta.url);
const repo = new URL('../../', root);
const require = createRequire(import.meta.url);

function installedVersion(resolvedEntry: string): string {
  let dir = dirname(resolvedEntry);
  while (!existsSync(join(dir, 'package.json'))) dir = dirname(dir);
  return (JSON.parse(readFileSync(join(dir, 'package.json'), 'utf8')) as { version: string })
    .version;
}

/** The `integrity` of one package in the harness's npm lockfile. */
function harnessIntegrity(name: string): string | undefined {
  const lock = JSON.parse(
    readFileSync(new URL('tools/crypto-validation/package-lock.json', repo), 'utf8'),
  ) as { packages: Record<string, { version?: string; integrity?: string }> };
  return lock.packages[`node_modules/${name}`]?.integrity;
}

describe('exact crypto dependency versions (INV-22)', () => {
  const pkg = JSON.parse(readFileSync(new URL('package.json', root), 'utf8')) as {
    dependencies: Record<string, string>;
    devDependencies: Record<string, string>;
  };

  it('pins every dependency to an exact version', () => {
    for (const [name, range] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies }))
      if (!range.startsWith('workspace:')) expect(range, name).toMatch(/^\d+\.\d+\.\d+$/);
    expect(pkg.dependencies).toEqual({
      'libsodium-sumo': '0.8.4',
      'libsodium-wrappers-sumo': '0.8.4',
    });
  });

  it('resolves both libsodium packages to 0.8.4, including the one the wrapper loads', () => {
    const wrapperEntry = require.resolve('libsodium-wrappers-sumo');
    expect(installedVersion(wrapperEntry)).toBe('0.8.4');
    const fromWrapper = createRequire(wrapperEntry).resolve('libsodium-sumo');
    expect(installedVersion(fromWrapper)).toBe('0.8.4');
  });

  it('locks a single libsodium-sumo version, overridden to the exact pin', () => {
    const lock = readFileSync(new URL('pnpm-lock.yaml', repo), 'utf8');
    expect(lock).toMatch(/^overrides:\n {2}libsodium-sumo: 0\.8\.4$/m);
    expect(lock.match(/^ {2}libsodium-sumo@[^:]+:/gm)).toEqual([
      '  libsodium-sumo@0.8.4:',
      '  libsodium-sumo@0.8.4:',
    ]);
    expect(lock.match(/^ {2}libsodium-wrappers-sumo@[^:]+:/gm)).toEqual([
      '  libsodium-wrappers-sumo@0.8.4:',
      '  libsodium-wrappers-sumo@0.8.4:',
    ]);
  });

  it('uses the same package tarballs the P2-01 harness validated', () => {
    const lock = readFileSync(new URL('pnpm-lock.yaml', repo), 'utf8');
    for (const name of [
      'libsodium-sumo',
      'libsodium-wrappers-sumo',
      '@noble/hashes',
      '@noble/ciphers',
    ]) {
      const integrity = harnessIntegrity(name);
      expect(integrity, name).toMatch(/^sha512-/);
      expect(lock, name).toContain(`integrity: ${integrity ?? 'missing'}`);
    }
  });

  it('runs the pinned C library', async () => {
    await sodium.ready;
    expect(sodium.sodium_version_string()).toBe(PINNED_LIBSODIUM_VERSION);
  });
});
