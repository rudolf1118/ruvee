// Refuses to run unless node_modules and package-lock.json match the exact pins in package.json.

import { readFile } from 'node:fs/promises';

export const root = new URL('../', import.meta.url);
export const readJson = async (p) => JSON.parse(await readFile(new URL(p, root), 'utf8'));
export const readVector = async (file) =>
  new Uint8Array(await readFile(new URL(`vectors/${file}`, root)));
export const toJson = (value) =>
  JSON.stringify(value, (k, v) => (typeof v === 'bigint' ? v.toString() : v), 2);

export async function pinnedVersions() {
  const pkg = await readJson('package.json');
  const lock = await readJson('package-lock.json');
  const pins = { ...pkg.dependencies, ...pkg.devDependencies };
  const problems = [];
  const installed = {};
  for (const [name, version] of Object.entries(pins)) {
    if (!/^\d+\.\d+\.\d+$/.test(version))
      problems.push(`${name}: "${version}" is not an exact pin`);
    const got = (await readJson(`node_modules/${name}/package.json`).catch(() => ({}))).version;
    const locked = lock.packages[`node_modules/${name}`]?.version;
    installed[name] = got ?? null;
    if (got !== version) problems.push(`${name}: installed ${got}, pinned ${version}`);
    if (locked !== version) problems.push(`${name}: lockfile ${locked}, pinned ${version}`);
  }
  const nested = Object.keys(lock.packages).filter((k) =>
    /node_modules\/.+\/node_modules\/(libsodium|@noble)/.test(k),
  );
  if (nested.length) problems.push(`nested copies of pinned packages: ${nested.join(', ')}`);
  return { installed, problems };
}
