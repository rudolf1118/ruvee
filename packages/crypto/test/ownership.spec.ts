import { loadLibsodiumPrimitives } from '../src/libsodium.js';
import { buildRuveeCrypto, randomNonces, type RuveeCrypto } from '../src/operations.js';
import { guardPrimitives } from '../src/primitives.js';
import { pattern } from './support/bytes.js';
import { recordingPrimitives, type RecordedCall } from './support/recording.js';

function isZero(value: unknown): boolean {
  return value instanceof Uint8Array && value.every((b) => b === 0);
}

async function setup(): Promise<{ crypto: RuveeCrypto; calls: RecordedCall[] }> {
  const { raw, calls } = recordingPrimitives(await loadLibsodiumPrimitives());
  const p = guardPrimitives(raw);
  return { crypto: buildRuveeCrypto(p, randomNonces(p)), calls };
}

const inputs = () => ({
  accountId: pattern(1, 16),
  passwordSalt: pattern(2, 16),
  secretKey: pattern(3, 32),
  accountKey: pattern(4, 32),
  accountKeyId: pattern(5, 16),
  vkId: pattern(6, 16),
  vk: pattern(7, 32),
});

describe('buffer ownership and cleanup', () => {
  it('never modifies caller-owned inputs, on success or failure', async () => {
    const { crypto } = await setup();
    const i = inputs();
    const snapshot = structuredClone(i);
    const auk = crypto.deriveAccountUnlockKey({ password: 'pw', profile: 1, ...i });
    const aukCopy = auk.slice();
    const wrapContext = { ...i, accountUnlockKey: auk, accountKeyEpoch: 1, profile: 1 };
    const wrap = crypto.wrapAccountKey(wrapContext);
    const wrapCopy = wrap.slice();
    crypto.unwrapAccountKey({ ...wrapContext, envelope: wrap });
    expect(() =>
      crypto.unwrapAccountKey({ ...wrapContext, accountKeyEpoch: 2, envelope: wrap }),
    ).toThrow();
    const keyset = {
      secretKey: i.secretKey,
      vaults: [{ vaultId: '0b8f3c2e-9a1d-4f6b-8e7c-2d5a4b3c1e0f', vkId: i.vkId, vk: i.vk }],
    } as const;
    const keysetContext = {
      accountKey: i.accountKey,
      accountKeyId: i.accountKeyId,
      accountId: i.accountId,
      keysetVersion: 1,
    };
    const sealed = crypto.sealKeyset({ ...keysetContext, keyset });
    const sealedCopy = sealed.slice();
    crypto.openKeyset({ ...keysetContext, envelope: sealed });
    expect(() =>
      crypto.openKeyset({ ...keysetContext, keysetVersion: 2, envelope: sealed }),
    ).toThrow();
    expect(i).toEqual(snapshot);
    expect(auk).toEqual(aukCopy);
    expect(wrap).toEqual(wrapCopy);
    expect(sealed).toEqual(sealedCopy);
  });

  it('returns fresh buffers that do not alias inputs or library state', async () => {
    const { crypto } = await setup();
    const i = inputs();
    const wrapContext = { ...i, accountUnlockKey: pattern(8, 32), accountKeyEpoch: 1, profile: 1 };
    const wrap = crypto.wrapAccountKey(wrapContext);
    const ak1 = crypto.unwrapAccountKey({ ...wrapContext, envelope: wrap });
    ak1.fill(0xaa);
    const ak2 = crypto.unwrapAccountKey({ ...wrapContext, envelope: wrap });
    expect(ak2).toEqual(i.accountKey);
    expect(ak2.buffer).not.toBe(i.accountKey.buffer);
    expect(ak2.buffer).not.toBe(wrap.buffer);
  });

  it('wipes the password bytes, PwK, the AUK input and K_keyset after use', async () => {
    const { crypto, calls } = await setup();
    const i = inputs();
    crypto.deriveAccountUnlockKey({ password: 'correct horse', profile: 1, ...i });
    const argon = calls.find((c) => c.method === 'pwhashArgon2id13');
    const mac = calls.find((c) => c.method === 'genericHash');
    expect(isZero(argon?.args[1])).toBe(true); // password bytes
    expect(isZero(argon?.result)).toBe(true); // PwK
    expect(isZero(mac?.args[1])).toBe(true); // "ruvee/v1/auk" ‖ … ‖ PwK
    expect(isZero(mac?.result)).toBe(false); // AUK is returned to the caller

    calls.length = 0;
    const keysetContext = {
      accountKey: i.accountKey,
      accountKeyId: i.accountKeyId,
      accountId: i.accountId,
      keysetVersion: 1,
    };
    const keyset = {
      secretKey: i.secretKey,
      vaults: [{ vaultId: '0b8f3c2e-9a1d-4f6b-8e7c-2d5a4b3c1e0f', vkId: i.vkId, vk: i.vk }],
    } as const;
    const sealed = crypto.sealKeyset({ ...keysetContext, keyset });
    expect(isZero(calls.find((c) => c.method === 'kdfDeriveFromKey')?.result)).toBe(true);
    expect(isZero(calls.find((c) => c.method === 'aeadEncrypt')?.args[0])).toBe(true); // keyset JSON bytes

    calls.length = 0;
    crypto.openKeyset({ ...keysetContext, envelope: sealed });
    expect(isZero(calls.find((c) => c.method === 'kdfDeriveFromKey')?.result)).toBe(true);
    expect(isZero(calls.find((c) => c.method === 'aeadDecrypt')?.result)).toBe(true);
  });

  it('wipes intermediates when a later step fails', async () => {
    const { crypto, calls } = await setup();
    const i = inputs();
    const keysetContext = {
      accountKey: i.accountKey,
      accountKeyId: i.accountKeyId,
      accountId: i.accountId,
      keysetVersion: 1,
    };
    expect(() =>
      crypto.openKeyset({ ...keysetContext, envelope: new Uint8Array(200).fill(0x52) }),
    ).toThrow();
    expect(isZero(calls.find((c) => c.method === 'kdfDeriveFromKey')?.result)).toBe(true);
  });

  it('wipes a library output of the wrong length before failing', () => {
    const wrong = new Uint8Array(31).fill(7);
    const { raw } = recordingPrimitives({
      ...recordingPrimitives().raw,
      kdfDeriveFromKey: () => wrong,
    });
    expect(() => guardPrimitives(raw).kdf(32, 1, 'rvkeyst1', pattern(1, 32))).toThrow(
      expect.objectContaining({ code: 'library_failure', reason: 'unexpected_output' }),
    );
    expect(isZero(wrong)).toBe(true);
  });
});
