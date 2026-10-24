const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const VALUES = new Map<string, number>(
  Array.from({ length: ALPHABET.length }, (_, i) => [ALPHABET.charAt(i), i]),
);

/** Unpadded base64url (RFC 4648 §5), as used for every binary value in Ruvee JSON. */
export function base64urlEncode(bytes: Uint8Array): string {
  let out = '';
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += ALPHABET.charAt(n >>> 18) + ALPHABET.charAt((n >>> 12) & 63);
    out += ALPHABET.charAt((n >>> 6) & 63) + ALPHABET.charAt(n & 63);
  }
  const rest = bytes.length - i;
  if (rest === 1) {
    const n = (bytes[i] ?? 0) << 16;
    out += ALPHABET.charAt(n >>> 18) + ALPHABET.charAt((n >>> 12) & 63);
  } else if (rest === 2) {
    const n = ((bytes[i] ?? 0) << 16) | ((bytes[i + 1] ?? 0) << 8);
    out += ALPHABET.charAt(n >>> 18) + ALPHABET.charAt((n >>> 12) & 63);
    out += ALPHABET.charAt((n >>> 6) & 63);
  }
  return out;
}

/**
 * Decodes canonical unpadded base64url to exactly `length` bytes, or returns undefined. Padding,
 * whitespace, the standard alphabet and non-zero trailing bits are all refused, so every byte
 * string has exactly one accepted text form.
 */
export function base64urlDecodeExact(text: string, length: number): Uint8Array | undefined {
  if (text.length !== Math.ceil((length * 4) / 3)) return undefined;
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
    buffer = (buffer << 6) | value;
    bits += 6;
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
