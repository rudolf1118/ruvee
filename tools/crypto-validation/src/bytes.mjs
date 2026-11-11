// Byte helpers shared by every check. They deliberately avoid libsodium and noble so that
// comparisons and encodings do not depend on the implementations being tested.

export const te = new TextEncoder();
const td = new TextDecoder('utf-8', { fatal: true });

export function hex(u8) {
  return Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function unhex(s) {
  const clean = s.replace(/[\s:]/g, '');
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(clean)) throw new Error(`not hex: ${s.slice(0, 40)}`);
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function utf8(bytes) {
  return td.decode(bytes);
}

export function equal(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== b.length)
    return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  return out;
}

export function flipBit(u8, index = 0, bit = 0) {
  const c = u8.slice();
  c[index] ^= 1 << bit;
  return c;
}

export function base64Decode(s) {
  const bin = atob(
    s
      .replace(/-/g, '+')
      .replace(/_/g, '/')
      .padEnd(Math.ceil(s.length / 4) * 4, '='),
  );
  return Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
}

// Deterministic, public, non-secret test bytes. SplitMix32-style counter generator: it shares no
// code with the libraries under test, so synthetic inputs never depend on them.
export function synthetic(label, length) {
  let h = 0x811c9dc5;
  for (const b of te.encode(label)) h = Math.imul(h ^ b, 0x01000193) >>> 0;
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++) {
    h = (h + 0x9e3779b9) >>> 0;
    let z = h;
    z = Math.imul(z ^ (z >>> 16), 0x85ebca6b) >>> 0;
    z = Math.imul(z ^ (z >>> 13), 0xc2b2ae35) >>> 0;
    out[i] = (z ^ (z >>> 16)) & 0xff;
  }
  return out;
}

export class CheckFailure extends Error {
  constructor(message, data) {
    super(message);
    this.name = 'CheckFailure';
    this.data = data;
  }
}

export function assert(condition, message, data) {
  if (!condition) throw new CheckFailure(message, data);
}

export function errorSummary(e) {
  if (e instanceof Error) return `${e.name}: ${e.message}`;
  if (e && typeof e === 'object') return `non-Error ${JSON.stringify(e).slice(0, 120)}`;
  return `non-Error ${typeof e}: ${String(e)}`;
}

// Runs fn and reports whether it threw, without interpreting the error.
export function attempt(fn) {
  try {
    return { threw: false, value: fn() };
  } catch (e) {
    return { threw: true, error: errorSummary(e), isError: e instanceof Error };
  }
}
