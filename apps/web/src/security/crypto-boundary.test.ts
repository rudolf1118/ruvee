import { readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { CRYPTO_ERROR_CODES, KEYSET_FORMAT_VERSION, RuveeCryptoError } from '@ruvee/crypto';

const webSrc = join(process.cwd(), 'src');

function walk(dir: string, files: string[] = []): string[] {
  for (const name of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, name.name);
    if (name.isDirectory()) walk(path, files);
    else if (/\.(ts|tsx|mjs|js)$/.test(name.name)) files.push(path);
  }
  return files;
}

describe('P2-03 boundary as a web consumer', () => {
  it('exposes an explicit keyset format version for later expansion', () => {
    expect(KEYSET_FORMAT_VERSION).toBe(1);
  });

  it('keeps error codes stable and never interpolates a secret into the message', () => {
    const secret = 'synthetic-secret-value-not-a-real-key';
    expect(CRYPTO_ERROR_CODES).toEqual([
      'invalid_argument',
      'invalid_password',
      'unsupported_profile',
      'malformed_envelope',
      'unsupported_format',
      'wrong_purpose',
      'wrong_key',
      'integrity_failure',
      'malformed_plaintext',
      'library_failure',
    ]);
    for (const code of CRYPTO_ERROR_CODES) {
      const error = new RuveeCryptoError(code, { field: secret, reason: 'too_long' });
      expect(error.message).not.toContain(secret);
      expect(error.message).not.toMatch(/[0-9a-f]{32}/i);
      expect(error).not.toHaveProperty('cause');
    }
  });

  it('does not import libsodium from the web app or the probe worker', () => {
    const forbidden = /libsodium-(wrappers-)?sumo/;
    for (const file of walk(webSrc)) {
      if (file.includes(join('security', 'crypto-boundary.test.ts'))) continue;
      expect(readFileSync(file, 'utf8'), file).not.toMatch(forbidden);
    }
  });
});
