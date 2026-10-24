// Cross-implementation checks: the package's guarded primitives against @noble/*. There are no
// published vectors for keyed BLAKE2b-256 with a 32-byte key, crypto_kdf or Argon2id with
// libsodium's fixed p = 1 and 16-byte salt, so agreement with one independent implementation is
// the evidence (cryptographic-design §8). Agreement is not proof of correctness.

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { argon2id } from '@noble/hashes/argon2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { base64urlDecodeExact, base64urlEncode } from '../src/base64url.js';
import { loadLibsodiumPrimitives } from '../src/libsodium.js';
import { guardPrimitives, KDF_CONTEXTS, type Primitives } from '../src/primitives.js';
import { resolveKdfProfile } from '../src/profiles.js';
import { randomBytesFrom, seededRandom } from './support/bytes.js';

let p: Primitives;
const next = seededRandom(0xc0ffee);

beforeAll(async () => {
  p = guardPrimitives(await loadLibsodiumPrimitives());
});

describe('cross-implementation against noble', () => {
  it('keyed BLAKE2b-256 with 32-byte keys, around the 128-byte block boundary', () => {
    for (const len of [0, 1, 63, 64, 77, 127, 128, 129, 255, 256, 257, 1023, 1024]) {
      const key = randomBytesFrom(next, 32);
      const msg = randomBytesFrom(next, len);
      expect(p.mac(32, msg, key)).toEqual(blake2b(msg, { key, dkLen: 32 }));
    }
  });

  it('crypto_kdf for the keyset context matches its documented BLAKE2b definition', () => {
    for (let i = 0; i < 64; i++) {
      const key = randomBytesFrom(next, 32);
      const salt = new Uint8Array(16);
      salt[0] = 1;
      const personalization = new Uint8Array(16);
      personalization.set(new TextEncoder().encode(KDF_CONTEXTS.keyset));
      expect(p.kdf(32, 1, KDF_CONTEXTS.keyset, key)).toEqual(
        blake2b(new Uint8Array(0), { key, dkLen: 32, salt, personalization }),
      );
    }
  });

  it('Argon2id at profile 1 matches noble', () => {
    const profile = resolveKdfProfile(1);
    for (const len of [1, 33]) {
      const password = randomBytesFrom(next, len);
      const salt = randomBytesFrom(next, 16);
      expect(p.argon2id(password, salt, profile)).toEqual(
        argon2id(password, salt, { t: 3, m: 65_536, p: 1, dkLen: 32, version: 0x13 }),
      );
    }
  });

  it('XChaCha20-Poly1305 in both directions over plaintext and AAD length grids', () => {
    for (const ptLen of [0, 1, 15, 16, 17, 63, 64, 65, 255, 256, 1000, 16_384]) {
      for (const adLen of [0, 1, 57, 77, 1024]) {
        const key = randomBytesFrom(next, 32);
        const nonce = randomBytesFrom(next, 24);
        const pt = randomBytesFrom(next, ptLen);
        const ad = randomBytesFrom(next, adLen);
        const ours = p.aeadEncrypt(pt, ad, nonce, key);
        expect(ours).toEqual(xchacha20poly1305(key, nonce, ad).encrypt(pt));
        expect(xchacha20poly1305(key, nonce, ad).decrypt(ours)).toEqual(pt);
        expect(p.aeadDecrypt(ours, ad, nonce, key)).toEqual(pt);
      }
    }
  });

  it('base64url matches Node and accepts only canonical text', () => {
    for (let len = 0; len < 70; len++) {
      const bytes = randomBytesFrom(next, len);
      const text = Buffer.from(bytes).toString('base64url');
      expect(base64urlEncode(bytes)).toBe(text);
      expect(base64urlDecodeExact(text, len)).toEqual(bytes);
      if (len > 0) {
        expect(base64urlDecodeExact(`${text}=`, len)).toBeUndefined();
        expect(base64urlDecodeExact(text.slice(1), len)).toBeUndefined();
      }
    }
    // One trailing bit set in the last character: Node decodes it, Ruvee refuses it.
    expect(base64urlDecodeExact('AB', 1)).toBeUndefined();
    expect(base64urlDecodeExact('AAB', 2)).toBeUndefined();
    expect(base64urlDecodeExact('AAAB', 3)).toEqual(Uint8Array.of(0, 0, 1));
    expect(base64urlDecodeExact('AA+A', 3)).toBeUndefined();
    expect(base64urlDecodeExact('AA A', 3)).toBeUndefined();
  });
});
