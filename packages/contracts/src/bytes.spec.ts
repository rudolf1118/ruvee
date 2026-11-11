import { randomBytes } from 'node:crypto';
import { base64urlBytes, base64urlLength } from './bytes.js';

const encode = (bytes: Buffer) => bytes.toString('base64url');

describe('base64urlBytes', () => {
  it('accepts every canonical encoding within the bounds', () => {
    const schema = base64urlBytes({ min: 0, max: 40 });
    for (let n = 0; n <= 40; n += 1) {
      const encoded = encode(randomBytes(n));
      expect(encoded).toHaveLength(base64urlLength(n));
      expect(schema.safeParse(encoded).success).toBe(true);
    }
  });

  it('checks the decoded length', () => {
    const schema = base64urlBytes({ length: 32 });
    expect(schema.safeParse(encode(randomBytes(32))).success).toBe(true);
    for (const n of [0, 31, 33, 64]) {
      expect(schema.safeParse(encode(randomBytes(n))).success).toBe(false);
    }
  });

  it('rejects padding, standard base64 characters and impossible lengths', () => {
    const schema = base64urlBytes({ min: 0, max: 16 });
    expect(schema.safeParse('AA==').success).toBe(false);
    expect(schema.safeParse('ab+/').success).toBe(false);
    expect(schema.safeParse('AAAAA').success).toBe(false);
    expect(schema.safeParse('AA AA').success).toBe(false);
  });

  it('rejects non-canonical encodings whose unused bits are set', () => {
    const schema = base64urlBytes({ min: 1, max: 2 });
    expect(schema.safeParse('AA').success).toBe(true);
    expect(schema.safeParse('AB').success).toBe(false);
    expect(schema.safeParse('AAA').success).toBe(true);
    expect(schema.safeParse('AAB').success).toBe(false);
    // Node decodes both to the same byte, which is why the check exists.
    expect(Buffer.from('AB', 'base64url')).toEqual(Buffer.from('AA', 'base64url'));
  });

  it('rejects invalid bounds when the schema is defined', () => {
    expect(() => base64urlBytes({ min: 4, max: 2 })).toThrow(RangeError);
    expect(() => base64urlBytes({ length: -1 })).toThrow(RangeError);
    expect(() => base64urlBytes({ length: 1.5 })).toThrow(RangeError);
  });
});
