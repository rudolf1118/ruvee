import type { RawPrimitives } from '../../src/primitives.js';

export interface RecordedCall {
  readonly method: keyof RawPrimitives;
  readonly args: readonly unknown[];
  result?: unknown;
}

/**
 * Wraps a raw implementation (or a fake that returns well-sized zero-free bytes) and records
 * every call that reaches it. A guard rejection must leave `calls` empty.
 */
export function recordingPrimitives(inner: RawPrimitives = fakePrimitives()): {
  raw: RawPrimitives;
  calls: RecordedCall[];
} {
  const calls: RecordedCall[] = [];
  const raw = Object.fromEntries(
    (Object.keys(inner) as (keyof RawPrimitives)[]).map((method) => [
      method,
      (...args: unknown[]) => {
        const call: RecordedCall = { method, args };
        calls.push(call);
        call.result = (inner[method] as (...a: unknown[]) => unknown)(...args);
        return call.result;
      },
    ]),
  ) as unknown as RawPrimitives;
  return { raw, calls };
}

/** Deterministic stand-in for the library. Its outputs are not cryptographic. */
export function fakePrimitives(): RawPrimitives {
  const fill = (n: number, v: number) => new Uint8Array(n).fill(v);
  return {
    randombytesBuf: (length) => fill(length, 0x11),
    pwhashArgon2id13: (outputLength) => fill(outputLength, 0x22),
    genericHash: (outputLength) => fill(outputLength, 0x33),
    kdfDeriveFromKey: (subkeyLength) => fill(subkeyLength, 0x44),
    aeadEncrypt: (message) => fill(message.length + 16, 0x55),
    aeadDecrypt: (ciphertext) => fill(ciphertext.length - 16, 0x66),
  };
}
