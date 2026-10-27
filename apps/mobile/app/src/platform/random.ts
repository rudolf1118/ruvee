import { randombytes_buf } from 'react-native-libsodium';

/**
 * `crypto.getRandomValues` for Hermes, backed by native libsodium's `randombytes_buf` (the OS
 * CSPRNG: `getrandom(2)` on Android, `arc4random_buf` on iOS). libsodium.js and the OPAQUE
 * WebAssembly module take all their randomness from this function, so it must follow the Web
 * Crypto contract exactly: integer typed arrays only, at most 65,536 bytes, filled in place.
 *
 * Installed only when the runtime has no implementation of its own; `randomSource()` reports
 * which one is in use.
 */
const MAX_BYTES = 65_536;
let installed = false;

function isIntegerArray(value: unknown): value is ArrayBufferView {
  return (
    value instanceof Int8Array ||
    value instanceof Uint8Array ||
    value instanceof Uint8ClampedArray ||
    value instanceof Int16Array ||
    value instanceof Uint16Array ||
    value instanceof Int32Array ||
    value instanceof Uint32Array ||
    value instanceof BigInt64Array ||
    value instanceof BigUint64Array
  );
}

function getRandomValues<T extends ArrayBufferView | null>(array: T): T {
  if (!isIntegerArray(array)) throw new TypeError('getRandomValues: not an integer typed array');
  if (array.byteLength > MAX_BYTES) throw new RangeError('getRandomValues: quota exceeded');
  if (array.byteLength === 0) return array;
  const bytes = randombytes_buf(array.byteLength);
  try {
    if (bytes.length !== array.byteLength) throw new Error('getRandomValues: short read');
    new Uint8Array(array.buffer, array.byteOffset, array.byteLength).set(bytes);
  } finally {
    bytes.fill(0);
  }
  return array;
}

interface CryptoGlobal {
  crypto?: { getRandomValues?: unknown };
}

export function installRandom(): void {
  const g = globalThis as CryptoGlobal;
  if (typeof g.crypto?.getRandomValues === 'function') return;
  const target = g.crypto ?? {};
  Object.defineProperty(target, 'getRandomValues', {
    value: getRandomValues,
    enumerable: true,
    configurable: false,
    writable: false,
  });
  if (!g.crypto)
    Object.defineProperty(globalThis, 'crypto', {
      value: target,
      enumerable: true,
      configurable: false,
      writable: false,
    });
  installed = true;
}

export function randomSource(): 'native-libsodium' | 'runtime' {
  return installed ? 'native-libsodium' : 'runtime';
}
