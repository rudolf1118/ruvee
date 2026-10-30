import { readFile, writeFile } from 'node:fs/promises';
import { loadLibsodiumPrimitives } from '../src/libsodium.js';
import {
  packageOutputs,
  referenceOutputs,
  vectorFile,
  type ProvisionalVectorFile,
} from './portable/provisional.js';
import { PROVISIONAL_FILE } from './support/node-env.js';

const writing = process.env.WRITE_PROVISIONAL_VECTORS === '1';

describe('provisional protocol vectors', () => {
  it('the package and the noble reference agree, and the committed file matches', async () => {
    const fromPackage = packageOutputs(await loadLibsodiumPrimitives());
    expect(fromPackage).toEqual(referenceOutputs());
    const expected = vectorFile(fromPackage);
    if (writing) await writeFile(PROVISIONAL_FILE, `${JSON.stringify(expected, null, 2)}\n`);
    const committed = JSON.parse(await readFile(PROVISIONAL_FILE, 'utf8')) as ProvisionalVectorFile;
    expect(committed).toEqual(expected);
    expect(committed.status).toBe('provisional');
  });
});
