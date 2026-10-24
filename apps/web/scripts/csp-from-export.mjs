import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  contentSecurityPolicy,
  inlineScriptBodies,
  sha256SourceHash,
} from '../security-headers.ts';

export const exportDir = new URL('../out/', import.meta.url);

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
