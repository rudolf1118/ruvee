import { RuveeCryptoError } from '../errors.js';
import { buildRuveeCrypto, type RuveeCrypto } from '../operations.js';
import { guardPrimitives, type RawPrimitives } from '../primitives.js';

/**
 * TEST-ONLY. The one place where a caller chooses envelope nonces, for reproducible provisional
 * vectors (cryptographic-design §4.2, INV-02). It is not in the package's exports, not in the
 * build, and the lint configuration forbids importing it from production modules.
 */
export function createFixedNonceCrypto(
  raw: RawPrimitives,
  nonces: readonly Uint8Array[],
): RuveeCrypto {
  let next = 0;
  return buildRuveeCrypto(guardPrimitives(raw), () => {
    const nonce = nonces[next++];
    if (!nonce) throw new RuveeCryptoError('invalid_argument', { field: 'nonce' });
    return nonce.slice();
  });
}
