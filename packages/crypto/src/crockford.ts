/** Crockford base32 (https://www.crockford.com/base32.html), without the optional check symbol. */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const VALUES = new Map<string, number>(
  Array.from({ length: ALPHABET.length }, (_, i) => [ALPHABET.charAt(i), i]),
);

/** Big-endian bit stream, 5 bits per symbol; the last symbol is padded with zero bits. */
export function crockfordEncode(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET.charAt((buffer >>> bits) & 31);
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET.charAt((buffer << (5 - bits)) & 31);
  return out;
}

/**
 * Decodes canonical symbols (already upper-cased and with `O`, `I` and `L` mapped) to exactly
 * `length` bytes, or returns undefined. Non-zero padding bits are refused, so each byte string
 * has one accepted form.
 */
export function crockfordDecodeExact(text: string, length: number): Uint8Array | undefined {
  if (text.length !== Math.ceil((length * 8) / 5)) return undefined;
  const out = new Uint8Array(length);
  let buffer = 0;
  let bits = 0;
  let o = 0;
  for (const ch of text) {
    const value = VALUES.get(ch);
    if (value === undefined) {
      out.fill(0);
      return undefined;
    }
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[o++] = (buffer >>> bits) & 0xff;
    }
    buffer &= (1 << bits) - 1;
  }
  if (o !== length || buffer !== 0) {
    out.fill(0);
    return undefined;
  }
  return out;
}

/** The decoding leniency of cryptographic-design §5.4: case, `O`→`0`, `I`/`L`→`1`, separators. */
export function crockfordNormalize(text: string): string {
  return text.replace(/[\s-]/g, '').toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1');
}
