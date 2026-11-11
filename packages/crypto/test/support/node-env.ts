import { readFile } from 'node:fs/promises';
import sodium from 'libsodium-wrappers-sumo';
import { loadLibsodiumPrimitives } from '../../src/libsodium.js';
import type { PortableEnv } from '../portable/checks.js';
import type { ProvisionalVectorFile } from '../portable/provisional.js';

export const VECTOR_DIR = new URL('../../../../tools/crypto-validation/vectors/', import.meta.url);
export const PROVISIONAL_FILE = new URL(
  '../vectors/provisional-protocol-vectors.json',
  import.meta.url,
);

export async function readVector(file: string): Promise<Uint8Array> {
  return new Uint8Array(await readFile(new URL(file, VECTOR_DIR)));
}

export async function nodeEnv(): Promise<PortableEnv> {
  await sodium.ready;
  return {
    raw: await loadLibsodiumPrimitives(),
    sodium,
    readVector,
    committedVectors: JSON.parse(await readFile(PROVISIONAL_FILE, 'utf8')) as ProvisionalVectorFile,
  };
}
