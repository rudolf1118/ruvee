// Loads the published vector files and refuses to continue unless every file matches the
// SHA-256 recorded in vectors/sources.json. Hashing uses WebCrypto, which is neither libsodium nor
// noble, so the integrity check does not depend on the implementations under test.

import { hex } from './bytes.mjs';

export class SourceIntegrityError extends Error {
  constructor(message) {
    super(message);
    this.name = 'SourceIntegrityError';
  }
}

async function sha256Hex(bytes) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new SourceIntegrityError('WebCrypto SHA-256 is unavailable in this runtime');
  return hex(new Uint8Array(await subtle.digest('SHA-256', bytes)));
}

// readBytes(fileName) must return a Uint8Array with the exact file contents.
export async function loadVerifiedSources(manifest, readBytes) {
  if (!manifest || !Array.isArray(manifest.sources) || manifest.sources.length === 0)
    throw new SourceIntegrityError('vector manifest is missing or empty');
  const out = {};
  for (const meta of manifest.sources) {
    if (!/^[0-9a-f]{64}$/.test(meta.sha256 ?? ''))
      throw new SourceIntegrityError(`${meta.id}: manifest has no valid SHA-256`);
    let bytes;
    try {
      bytes = await readBytes(meta.file);
    } catch (e) {
      throw new SourceIntegrityError(`${meta.id}: cannot read ${meta.file}: ${e?.message ?? e}`);
    }
    if (!(bytes instanceof Uint8Array) || bytes.length === 0)
      throw new SourceIntegrityError(`${meta.id}: ${meta.file} is empty or unreadable`);
    const actual = await sha256Hex(bytes);
    if (actual !== meta.sha256)
      throw new SourceIntegrityError(
        `${meta.id}: SHA-256 mismatch for ${meta.file} (expected ${meta.sha256}, got ${actual})`,
      );
    out[meta.id] = { meta, bytes, text: new TextDecoder('utf-8', { fatal: true }).decode(bytes) };
  }
  return out;
}
