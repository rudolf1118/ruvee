import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  contentSecurityPolicy,
  inlineScriptBodies,
  sha256SourceHash,
} from '../security-headers.ts';

// `out/` is the ordinary export; RUVEE_EXPORT_DIR=out-diagnostics selects the test-only one.
const EXPORT_DIRS = new Set(['out', 'out-diagnostics']);
const exportName = process.env.RUVEE_EXPORT_DIR ?? 'out';
if (!EXPORT_DIRS.has(exportName))
  throw new Error(`RUVEE_EXPORT_DIR must be one of ${[...EXPORT_DIRS]}`);
export const exportDir = new URL(`../${exportName}/`, import.meta.url);

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest();
}

export async function htmlFiles(dir = exportDir.pathname) {
  const found = [];
  async function walk(current) {
    for (const entry of await readdir(current, { withFileTypes: true })) {
      const path = join(current, entry.name);
      if (entry.isDirectory()) await walk(path);
      else if (entry.name.endsWith('.html')) found.push(path);
    }
  }
  await walk(dir);
  return found.sort();
}

export async function scriptHashesFromExport(dir = exportDir.pathname) {
  const hashes = new Set();
  for (const file of await htmlFiles(dir)) {
    const html = await readFile(file, 'utf8');
    for (const body of inlineScriptBodies(html)) hashes.add(sha256SourceHash(body, sha256));
  }
  if (hashes.size === 0) {
    throw new Error(`No inline scripts found under ${dir}; the export is missing or unexpected.`);
  }
  return [...hashes].sort();
}

export async function productionCsp(dir = exportDir.pathname) {
  return contentSecurityPolicy(await scriptHashesFromExport(dir));
}
