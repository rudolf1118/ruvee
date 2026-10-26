import { readdir, readFile } from 'node:fs/promises';
import * as publicApi from '../src/index.js';

const root = new URL('../', import.meta.url);

async function productionSources(): Promise<{ file: string; text: string }[]> {
  const entries = await readdir(new URL('src/', root), { recursive: true });
  const files = entries.filter((f) => f.endsWith('.ts') && !f.startsWith('testing'));
  return Promise.all(
    files.map(async (file) => ({
      file,
      text: await readFile(new URL(`src/${file}`, root), 'utf8'),
    })),
  );
}

describe('public surface (INV-02)', () => {
  it('exports exactly the allowlisted runtime values', () => {
    expect(Object.keys(publicApi).sort()).toEqual([
      'ACCOUNT_KEY_WRAP_BYTES',
      'CRYPTO_ERROR_CODES',
      'DEFAULT_KDF_PROFILE',
      'ITEM_BODY_ENVELOPE_MAX_BYTES',
      'ITEM_BODY_MAX_BYTES',
      'ITEM_KEY_ENVELOPE_BYTES',
      'ITEM_RECORD_MAX_BYTES',
      'ITEM_SCHEMA_VERSIONS',
      'KEYSET_ENVELOPE_MAX_BYTES',
      'KEYSET_FORMAT_VERSION',
      'LOCAL_RECORD_ENVELOPE_MAX_BYTES',
      'MANIFEST_ENVELOPE_BYTES',
      'PADDED_MAX_BYTES',
      'PADDING_BLOCK_BYTES',
      'PAIRING_ID_BYTES',
      'PAIRING_SECRET_BYTES',
      'PASSWORD_MAX_BYTES',
      'PLATFORM_CODES',
      'PROOF_OPERATIONS',
      'RECOVERY_KEY_BYTES',
      'RuveeCryptoError',
      'UUID_BYTES',
      'initRuveeCrypto',
      'isRuveeCryptoError',
      'manifestStructureProblem',
      'normalizePassword',
      'padPlaintext',
      'parseItemRecord',
      'unpadPlaintext',
      'uuidFromBytes',
      'uuidToBytes',
      'wipe',
    ]);
    expect(publicApi.ITEM_KEY_ENVELOPE_BYTES).toBe(93);
    expect(publicApi.ITEM_BODY_ENVELOPE_MAX_BYTES).toBe(65_597);
    expect(publicApi.ITEM_RECORD_MAX_BYTES).toBe(65_702);
    expect(publicApi.MANIFEST_ENVELOPE_BYTES).toBe(198);
    expect(publicApi.LOCAL_RECORD_ENVELOPE_MAX_BYTES).toBe(1_048_637);
    expect(publicApi.ACCOUNT_KEY_WRAP_BYTES).toBe(93);
    expect(publicApi.KEYSET_ENVELOPE_MAX_BYTES).toBe(16_445);
    expect(publicApi.KEYSET_FORMAT_VERSION).toBe(1);
  });

  it('ships only the main entry point; the fixed-nonce module is neither exported nor built', async () => {
    const pkg = JSON.parse(await readFile(new URL('package.json', root), 'utf8')) as {
      exports: Record<string, unknown>;
    };
    expect(Object.keys(pkg.exports)).toEqual(['.']);
    const build = await readFile(new URL('tsconfig.build.json', root), 'utf8');
    expect(build).toMatch(/"exclude": \[[^\]]*"src\/testing"/);
  });

  it('no production module imports the test-only entry point', async () => {
    for (const { file, text } of await productionSources())
      expect(text, file).not.toMatch(/from\s+['"][^'"]*testing[^'"]*['"]/);
  });

  it('no public operation input has a nonce field', async () => {
    for (const file of [
      'src/operations.ts',
      'src/vault-operations.ts',
      'src/pairing-operations.ts',
    ]) {
      const operations = await readFile(new URL(file, root), 'utf8');
      expect(operations, file).not.toMatch(/\bnonce\??\s*:/i);
    }
  });

  it('only src/libsodium.ts imports the library', async () => {
    for (const { file, text } of await productionSources())
      if (file !== 'libsodium.ts') expect(text, file).not.toMatch(/libsodium-(wrappers-)?sumo/);
  });

  it('production modules never call console', async () => {
    for (const { file, text } of await productionSources())
      expect(text, file).not.toMatch(/\bconsole\./);
  });
});
