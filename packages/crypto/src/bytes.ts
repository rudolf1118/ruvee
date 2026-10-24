import { RuveeCryptoError } from './errors.js';

export const U32_MAX = 0xffff_ffff;

/** `Uint8Array` only: strings, arrays, `ArrayBuffer`s and other typed arrays are refused. */
export function isBytes(value: unknown): value is Uint8Array {
  return value instanceof Uint8Array;
}

export function requireBytes(value: unknown, field: string, length: number): Uint8Array {
  if (!isBytes(value) || value.length !== length)
    throw new RuveeCryptoError('invalid_argument', { field });
  return value;
}

export function requireBytesWithin(
  value: unknown,
  field: string,
  min: number,
  max: number,
): Uint8Array {
  if (!isBytes(value) || value.length < min || value.length > max)
    throw new RuveeCryptoError('invalid_argument', { field });
  return value;
}

export function requireU32(value: unknown, field: string): number {
  if (typeof value !== 'number' || !Number.isInteger(value) || value < 0 || value > U32_MAX)
    throw new RuveeCryptoError('invalid_argument', { field });
  return value;
}

export function concat(...parts: readonly Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function u8(value: number): Uint8Array {
  return Uint8Array.of(value);
}

export function u32be(value: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, value, false);
  return out;
}

/** Comparison for public values such as key ids. Not constant-time; never use it on secrets. */
export function publicBytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

export function ascii(text: string): Uint8Array {
  const out = new Uint8Array(text.length);
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i);
    if (code > 0x7e || code < 0x20)
      throw new RuveeCryptoError('invalid_argument', { field: 'ascii' });
    out[i] = code;
  }
  return out;
}

/**
 * Overwrites a buffer with zeros. Best effort only: JavaScript engines and WebAssembly may have
 * copied the bytes elsewhere (garbage-collector moves, JIT registers, the library's heap), and
 * strings cannot be erased at all.
 */
export function wipe(bytes: Uint8Array): void {
  if (!isBytes(bytes)) throw new RuveeCryptoError('invalid_argument', { field: 'bytes' });
  bytes.fill(0);
}
