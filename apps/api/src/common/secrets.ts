import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

/** 32 random bytes as unpadded base64url: session tokens and the bootstrap token. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString('base64url');
}

/** Byte values are plain `Uint8Array`s over their own `ArrayBuffer`, as Prisma `Bytes` expects. */
export type Bytes = Uint8Array<ArrayBuffer>;

export function sha256(data: string | Uint8Array): Bytes {
  return new Uint8Array(createHash('sha256').update(data).digest());
}

/** Constant-time comparison of two equal-length byte strings; false for different lengths. */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

export function fromBase64url(text: string): Bytes {
  return new Uint8Array(Buffer.from(text, 'base64url'));
}

export function toBase64url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64url');
}

/**
 * Key-free header check of a client envelope (cryptographic-design §4.4 steps 1 to 4): magic,
 * version, algorithm, purpose, optionally the `key_id`, and the length bounds. The server cannot
 * check anything inside; this only refuses malformed uploads early.
 */
export function envelopeHeaderOk(
  envelope: Uint8Array,
  purpose: number,
  length: { min: number; max: number },
  keyId?: Uint8Array,
): boolean {
  if (envelope.length < length.min || envelope.length > length.max) return false;
  if (envelope[0] !== 0x52 || envelope[1] !== 0x56 || envelope[2] !== 1 || envelope[3] !== 1)
    return false;
  if (envelope[4] !== purpose) return false;
  return keyId === undefined || Buffer.compare(envelope.subarray(5, 21), keyId) === 0;
}
