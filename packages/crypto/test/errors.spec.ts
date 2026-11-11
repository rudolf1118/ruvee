import { RuveeCryptoError } from '../src/errors.js';
import { initRuveeCrypto, normalizePassword } from '../src/index.js';
import { buildRuveeCrypto, randomNonces } from '../src/operations.js';
import { guardPrimitives, type RawPrimitives } from '../src/primitives.js';
import { hex, pattern } from './support/bytes.js';
import { fakePrimitives } from './support/recording.js';

const SENTINEL = 'SENTINEL-not-a-real-password-7f3a';
const KEY = pattern(0x5e, 32);

function caught(fn: () => unknown): RuveeCryptoError {
  try {
    fn();
  } catch (e) {
    if (e instanceof RuveeCryptoError) return e;
    throw e;
  }
  throw new Error('did not throw');
}

function expectNoSecret(error: RuveeCryptoError, secrets: readonly string[]): void {
  const surfaces = [
    error.message,
    String(error),
    error.stack ?? '',
    JSON.stringify(error),
    JSON.stringify(Object.getOwnPropertyDescriptors(error)),
  ].join('\n');
  for (const secret of secrets) expect(surfaces).not.toContain(secret);
  expect('cause' in error).toBe(false);
}

describe('errors carry no secret values', () => {
  it('password rejections name a reason, never the input', () => {
    for (const input of [`${SENTINEL}\ud800`, SENTINEL.repeat(200), SENTINEL.repeat(3000)]) {
      const error = caught(() => normalizePassword(input));
      expect(error.code).toBe('invalid_password');
      expectNoSecret(error, [SENTINEL]);
    }
  });

  it('decryption failures carry only the code', async () => {
    const crypto = await initRuveeCrypto();
    const context = {
      accountUnlockKey: KEY,
      accountId: pattern(1, 16),
      accountKeyId: pattern(2, 16),
      accountKeyEpoch: 1,
      profile: 1,
      passwordSalt: pattern(3, 16),
    };
    const accountKey = pattern(4, 32);
    const wrap = crypto.wrapAccountKey({ ...context, accountKey });
    const tampered = wrap.slice();
    tampered[60] = (tampered[60] ?? 0) ^ 1;
    const error = caught(() => crypto.unwrapAccountKey({ ...context, envelope: tampered }));
    expect(error.code).toBe('integrity_failure');
    expectNoSecret(error, [hex(KEY), hex(accountKey), hex(tampered)]);
  });

  it('library exceptions are replaced, not wrapped', () => {
    const raw: RawPrimitives = {
      ...fakePrimitives(),
      genericHash: () => {
        throw new Error(`library said ${SENTINEL}`);
      },
    };
    const p = guardPrimitives(raw);
    const error = caught(() => p.mac(32, pattern(1, 4), KEY));
    expect(error).toMatchObject({ code: 'library_failure', reason: 'operation_failed' });
    expectNoSecret(error, [SENTINEL]);
  });

  it('argument errors name the field only', () => {
    const p = guardPrimitives(fakePrimitives());
    const crypto = buildRuveeCrypto(p, randomNonces(p));
    const error = caught(() =>
      crypto.deriveAccountUnlockKey({
        password: SENTINEL,
        passwordSalt: pattern(1, 15),
        profile: 1,
        secretKey: KEY,
        accountId: pattern(2, 16),
      }),
    );
    expect(error).toMatchObject({ code: 'invalid_argument', field: 'passwordSalt' });
    expectNoSecret(error, [SENTINEL, hex(KEY)]);
  });
});

describe('no logging', () => {
  it('writes nothing to the console across every operation and failure', async () => {
    const spies = (['log', 'info', 'warn', 'error', 'debug', 'trace'] as const).map((m) =>
      vi.spyOn(console, m).mockImplementation(() => undefined),
    );
    try {
      const crypto = await initRuveeCrypto();
      const auk = crypto.deriveAccountUnlockKey({
        password: SENTINEL,
        passwordSalt: pattern(1, 16),
        profile: 1,
        secretKey: KEY,
        accountId: pattern(2, 16),
      });
      const ctx = {
        accountUnlockKey: auk,
        accountId: pattern(2, 16),
        accountKeyId: pattern(3, 16),
        accountKeyEpoch: 1,
        profile: 1,
        passwordSalt: pattern(1, 16),
      };
      const wrap = crypto.wrapAccountKey({ ...ctx, accountKey: KEY });
      crypto.unwrapAccountKey({ ...ctx, envelope: wrap });
      expect(() =>
        crypto.unwrapAccountKey({ ...ctx, accountKeyEpoch: 9, envelope: wrap }),
      ).toThrow();
      expect(() => normalizePassword(`${SENTINEL}\udc00`)).toThrow();
      for (const spy of spies) expect(spy).not.toHaveBeenCalled();
    } finally {
      for (const spy of spies) spy.mockRestore();
    }
  });
});
