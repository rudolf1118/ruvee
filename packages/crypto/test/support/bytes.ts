// Test helpers that share no code with the package, so comparisons never depend on it.

export function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function unhex(text: string): Uint8Array {
  const clean = text.replace(/\s+/g, '');
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(clean)) throw new Error('not hex');
  return Uint8Array.from({ length: clean.length / 2 }, (_, i) =>
    parseInt(clean.slice(i * 2, i * 2 + 2), 16),
  );
}

export function cat(...parts: readonly (Uint8Array | readonly number[])[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** Public, synthetic, non-secret test bytes. */
export function pattern(seed: number, length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (seed * 31 + i * 7 + 3) & 0xff);
}

/** Seeded xorshift32, for reproducible fuzz inputs. Not a CSPRNG and not used as one. */
export function seededRandom(seed: number): (max: number) => number {
  let state = seed >>> 0 || 1;
  return (max) => {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state ^= state << 5;
    state >>>= 0;
    return state % max;
  };
}

export function randomBytesFrom(next: (max: number) => number, length: number): Uint8Array {
  return Uint8Array.from({ length }, () => next(256));
}
