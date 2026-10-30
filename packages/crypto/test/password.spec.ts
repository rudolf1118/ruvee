import { RuveeCryptoError } from '../src/errors.js';
import { buildRuveeCrypto, randomNonces } from '../src/operations.js';
import {
  normalizePassword,
  passwordBytes,
  PASSWORD_MAX_INPUT_CODE_UNITS,
} from '../src/password.js';
import { guardPrimitives } from '../src/primitives.js';
import { pattern, seededRandom } from './support/bytes.js';
import { recordingPrimitives } from './support/recording.js';

const nativeWellFormed = (s: string) =>
  (s as unknown as { isWellFormed(): boolean }).isWellFormed();

describe('password input rule (D-20), Node-only checks', () => {
  it('agrees with String.prototype.isWellFormed on random strings rich in surrogates', () => {
    const next = seededRandom(20261024);
    const units = [0x41, 0xe9, 0x301, 0xd800, 0xdbff, 0xdc00, 0xdfff, 0xd83d, 0xde00, 0xfeff, 0x20];
    for (let i = 0; i < 20_000; i++) {
      const s = String.fromCharCode(
        ...Array.from({ length: 1 + next(8) }, () => units[next(units.length)] ?? 0x41),
      );
      const ours = (() => {
        try {
          normalizePassword(s);
          return true;
        } catch (e) {
          return !(e instanceof RuveeCryptoError && e.reason === 'malformed_unicode');
        }
      })();
      expect(ours, JSON.stringify(s)).toBe(nativeWellFormed(s));
    }
  });

  it('never calls normalize() on input above the work bound', () => {
    const spy = vi.spyOn(String.prototype, 'normalize');
    try {
      expect(() => normalizePassword('a'.repeat(PASSWORD_MAX_INPUT_CODE_UNITS + 1))).toThrow(
        expect.objectContaining({ code: 'invalid_password', reason: 'too_long' }),
      );
      expect(() => normalizePassword('\ud800')).toThrow();
      expect(spy).not.toHaveBeenCalled();
      // At the bound the input is normalized and then rejected on bytes.
      expect(() => normalizePassword('a'.repeat(PASSWORD_MAX_INPUT_CODE_UNITS))).toThrow(
        expect.objectContaining({ reason: 'too_long' }),
      );
      expect(spy).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });

  it('relies on canonical decompositions of at most 4 code points (basis of the work bound)', () => {
    let longest = 0;
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue;
      longest = Math.max(longest, Array.from(String.fromCodePoint(cp).normalize('NFD')).length);
    }
    expect(longest).toBeLessThanOrEqual(4);
  });

  it('is idempotent and returns the bytes of the normalized string', () => {
    for (const s of ['A\u030angstro\u0308m', '\u{1f510} x', '  spaced  ']) {
      const once = normalizePassword(s);
      expect(normalizePassword(once)).toBe(once);
      expect(passwordBytes(s)).toEqual(new TextEncoder().encode(once));
    }
  });

  it('rejects malformed passwords before any key derivation', () => {
    const { raw, calls } = recordingPrimitives();
    const p = guardPrimitives(raw);
    const crypto = buildRuveeCrypto(p, randomNonces(p));
    for (const password of ['', 'a\ud800', 'x'.repeat(4097), 7]) {
      expect(() =>
        crypto.deriveAccountUnlockKey({
          password: password as string,
          passwordSalt: pattern(1, 16),
          profile: 1,
          secretKey: pattern(2, 32),
          accountId: pattern(3, 16),
        }),
      ).toThrow(expect.objectContaining({ code: 'invalid_password' }));
    }
    expect(calls).toHaveLength(0);
  });
});
