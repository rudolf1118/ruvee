// Loads the published XChaCha20-Poly1305 vectors from tools/crypto-validation/vectors after
// checking each file against the SHA-256 recorded in sources.json. Expected values are read from
// the published text; nothing here computes them. The parser is separate from the harness's, so
// the package tests do not import harness code.

import { hex, unhex } from './bytes.js';

interface ManifestEntry {
  readonly id: string;
  readonly file: string;
  readonly sha256: string;
}

export type ReadVectorFile = (file: string) => Promise<Uint8Array>;

export interface AeadVector {
  readonly id: string;
  readonly key: Uint8Array;
  readonly nonce: Uint8Array;
  readonly aad: Uint8Array;
  readonly plaintext: Uint8Array;
  /** Ciphertext followed by the 16-byte tag (libsodium combined mode). */
  readonly sealed: Uint8Array;
  readonly valid: boolean;
}

export interface XChaChaVectors {
  readonly draft: AeadVector;
  readonly wycheproof: readonly AeadVector[];
}

async function sha256(bytes: Uint8Array): Promise<string> {
  const copy = new Uint8Array(bytes);
  return hex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', copy.buffer)));
}

async function verified(read: ReadVectorFile, manifest: readonly ManifestEntry[], id: string) {
  const entry = manifest.find((s) => s.id === id);
  if (!entry || !/^[0-9a-f]{64}$/.test(entry.sha256)) throw new Error(`${id}: no manifest hash`);
  const bytes = await read(entry.file);
  const actual = await sha256(bytes);
  if (actual !== entry.sha256) throw new Error(`${id}: SHA-256 mismatch`);
  return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
}

const pageNoise = /^(RFC \d+ .*\d{4}|.*\[Page \d+\]|Internet-Draft .*|Arciszewski .*)$/;

function parseDraftA31(text: string): AeadVector {
  const start = text.indexOf('A.3.1.  AEAD_XCHACHA20_POLY1305', text.indexOf('A.3.1.') + 1);
  const end = text.indexOf('A.3.2.  XChaCha20', start);
  if (start < 0 || end < 0) throw new Error('draft §A.3.1 not found');
  const blocks: Record<string, string> = {};
  let label: string | undefined;
  for (const raw of text.slice(start, end).split('\n')) {
    const line = raw.trim();
    if (!line || pageNoise.test(line)) continue;
    const heading = /^([A-Za-z0-9][A-Za-z0-9 -]*):$/.exec(line);
    if (heading?.[1]) {
      label = heading[1];
      blocks[label] = '';
    } else if (label && /^[0-9a-f]+$/.test(line)) {
      blocks[label] = (blocks[label] ?? '') + line;
    }
  }
  const field = (name: string) => {
    const value = blocks[name];
    if (!value) throw new Error(`draft §A.3.1: missing ${name}`);
    return unhex(value);
  };
  return {
    id: 'draft-irtf-cfrg-xchacha-03 §A.3.1',
    key: field('Key'),
    nonce: field('IV'),
    aad: field('AAD'),
    plaintext: field('Plaintext'),
    sealed: new Uint8Array([...field('Ciphertext'), ...field('Tag')]),
    valid: true,
  };
}

interface WycheproofFile {
  algorithm: string;
  testGroups: {
    tests: {
      tcId: number;
      key: string;
      iv: string;
      aad: string;
      msg: string;
      ct: string;
      tag: string;
      result: string;
    }[];
  }[];
}

function parseWycheproof(text: string): AeadVector[] {
  const data = JSON.parse(text) as WycheproofFile;
  if (data.algorithm !== 'XCHACHA20-POLY1305') throw new Error('wycheproof: wrong algorithm');
  return data.testGroups.flatMap((group) =>
    group.tests.map((t) => ({
      id: `wycheproof tcId ${t.tcId}`,
      key: unhex(t.key),
      nonce: unhex(t.iv),
      aad: unhex(t.aad),
      plaintext: unhex(t.msg),
      sealed: unhex(t.ct + t.tag),
      valid: t.result === 'valid',
    })),
  );
}

export async function loadXChaChaVectors(read: ReadVectorFile): Promise<XChaChaVectors> {
  const manifest = (
    JSON.parse(new TextDecoder().decode(await read('sources.json'))) as {
      sources: ManifestEntry[];
    }
  ).sources;
  return {
    draft: parseDraftA31(await verified(read, manifest, 'draft-xchacha-03')),
    wycheproof: parseWycheproof(await verified(read, manifest, 'wycheproof-xchacha')),
  };
}
