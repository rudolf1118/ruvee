// The API's pending-login seal (src/login-state-seal.ts, authentication.md §4.1). The derivation,
// the AAD encoding and the envelope are rebuilt here from the specification with @noble/*, so a
// change to any of them fails these tests; agreement with one independent implementation is the
// evidence, not proof (cryptographic-design §8).

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { loadLibsodiumPrimitives } from '../src/libsodium.js';
import {
  buildLoginStateSealOperations,
  LOGIN_STATE_SEAL_MAX_BYTES,
  LOGIN_STATE_SEAL_MIN_BYTES,
  type LoginStateContext,
  type LoginStateSealOperations,
} from '../src/login-state-seal.js';
import { RuveeCryptoError } from '../src/errors.js';
import { guardPrimitives } from '../src/primitives.js';
import { cat, hex, pattern } from './support/bytes.js';
import { recordingPrimitives } from './support/recording.js';

const enc = (text: string) => new TextEncoder().encode(text);
const u32 = (n: number) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
const lp = (b: Uint8Array) => cat(u32(b.length), b);
function u64(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n));
  return out;
}

const setup = pattern(1, 128);
const loginId = pattern(2, 16);
const challenge = pattern(3, 32);
const state = enc('s'.repeat(171));
const context: LoginStateContext = {
  idHash: pattern(4, 32),
  purpose: 'reauth',
  loginSubject: pattern(5, 32),
  accountId: pattern(6, 16),
  deviceId: null,
  platform: 'web',
  sessionId: pattern(7, 16),
  reopenCodeId: null,
  expiresAtMs: 1_793_000_000_123,
};

function referenceAad(c: LoginStateContext): Uint8Array {
  const id = (v: Uint8Array | null) => lp(v ?? new Uint8Array(0));
  return cat(
    enc('ruvee/v1/login-state'),
    lp(c.idHash),
    lp(enc(c.purpose)),
    lp(c.loginSubject),
    id(c.accountId),
    id(c.deviceId),
    lp(enc(c.platform)),
    id(c.sessionId),
    id(c.reopenCodeId),
    u64(c.expiresAtMs),
  );
}

function referenceStateKey(setupBytes: Uint8Array, id: Uint8Array): Uint8Array {
  const inner = blake2b(setupBytes, { dkLen: 32 });
  const seal = blake2b(enc('ruvee/v1/login-state-seal'), { key: inner, dkLen: 32 });
  return blake2b(id, { key: seal, dkLen: 32 });
}

let ops: LoginStateSealOperations;
let sealKey: Uint8Array;

beforeAll(async () => {
  ops = buildLoginStateSealOperations(guardPrimitives(await loadLibsodiumPrimitives()));
  sealKey = ops.deriveLoginStateSealKey(setup);
});

const seal = () =>
  ops.sealLoginState({ sealKey, loginId, context, challenge, serverLoginState: state });

describe('login-state seal: specification', () => {
  it('derives K_seal and K_state exactly as specified, and the envelope opens with noble', () => {
    const inner = blake2b(setup, { dkLen: 32 });
    expect(hex(sealKey)).toBe(
      hex(blake2b(enc('ruvee/v1/login-state-seal'), { key: inner, dkLen: 32 })),
    );
    const sealed = seal();
    expect(sealed[0]).toBe(0x02);
    expect(sealed.length).toBe(1 + 24 + 32 + state.length + 16);
    const plain = xchacha20poly1305(
      referenceStateKey(setup, loginId),
      sealed.subarray(1, 25),
      referenceAad(context),
    ).decrypt(sealed.subarray(25));
    expect(hex(plain)).toBe(hex(cat(challenge, state)));
  });

  it('opens a seal made by noble from the specification', () => {
    const nonce = pattern(8, 24);
    const sealed = cat(
      [0x02],
      nonce,
      xchacha20poly1305(referenceStateKey(setup, loginId), nonce, referenceAad(context)).encrypt(
        cat(challenge, state),
      ),
    );
    const opened = ops.openLoginState({ sealKey, loginId, context, sealed });
    expect(opened && hex(opened.challenge)).toBe(hex(challenge));
    expect(opened && hex(opened.serverLoginState)).toBe(hex(state));
  });

  it('separates the seal key from the setup by its own domain', () => {
    expect(hex(sealKey)).not.toBe(hex(blake2b(setup, { dkLen: 32 })));
    expect(hex(sealKey)).not.toBe(hex(ops.deriveLoginStateSealKey(pattern(9, 128))));
  });

  it('encodes null and a UUID differently, and every field is length-prefixed', () => {
    const a = referenceAad({ ...context, deviceId: null, reopenCodeId: pattern(10, 16) });
    const b = referenceAad({ ...context, deviceId: pattern(10, 16), reopenCodeId: null });
    expect(hex(a)).not.toBe(hex(b));
  });

  it('bounds: the smallest and largest states, and nothing outside', () => {
    expect(LOGIN_STATE_SEAL_MIN_BYTES).toBe(74);
    expect(LOGIN_STATE_SEAL_MAX_BYTES).toBe(585);
    const make = (n: number) =>
      ops.sealLoginState({
        sealKey,
        loginId,
        context,
        challenge,
        serverLoginState: new Uint8Array(n).fill(65),
      });
    expect(make(1).length).toBe(LOGIN_STATE_SEAL_MIN_BYTES);
    expect(make(512).length).toBe(LOGIN_STATE_SEAL_MAX_BYTES);
    expect(() => make(0)).toThrow(RuveeCryptoError);
    expect(() => make(513)).toThrow(RuveeCryptoError);
  });
});

describe('login-state seal: nonces', () => {
  it('draws a fresh 24-byte nonce for every seal of the same input', () => {
    const nonces = new Set<string>();
    const bodies = new Set<string>();
    for (let i = 0; i < 2000; i++) {
      const sealed = seal();
      nonces.add(hex(sealed.subarray(1, 25)));
      bodies.add(hex(sealed.subarray(25)));
    }
    expect(nonces.size).toBe(2000);
    expect(bodies.size).toBe(2000);
  });

  it('takes the nonce from the CSPRNG and the key from the login id', () => {
    const { raw, calls } = recordingPrimitives();
    const fake = buildLoginStateSealOperations(guardPrimitives(raw));
    fake.sealLoginState({ sealKey, loginId, context, challenge, serverLoginState: state });
    expect(calls.map((c) => c.method)).toEqual(['genericHash', 'randombytesBuf', 'aeadEncrypt']);
    expect(calls[1]?.args).toEqual([24]);
    expect(hex(calls[0]?.args[1] as Uint8Array)).toBe(hex(loginId));
    expect(hex(calls[0]?.args[2] as Uint8Array)).toBe(hex(sealKey));
  });
});

describe('login-state seal: refusals', () => {
  const variants: [string, Partial<LoginStateContext>][] = [
    ['idHash', { idHash: pattern(20, 32) }],
    ['purpose', { purpose: 'login' }],
    ['loginSubject', { loginSubject: pattern(21, 32) }],
    ['accountId', { accountId: pattern(22, 16) }],
    ['accountId null', { accountId: null }],
    ['deviceId', { deviceId: pattern(23, 16) }],
    ['platform', { platform: 'extension' }],
    ['sessionId', { sessionId: pattern(24, 16) }],
    ['reopenCodeId', { reopenCodeId: pattern(25, 16) }],
    ['expiresAtMs', { expiresAtMs: context.expiresAtMs + 1 }],
  ];
  it.each(variants)('does not open when %s differs', (_name, change) => {
    expect(
      ops.openLoginState({ sealKey, loginId, context: { ...context, ...change }, sealed: seal() }),
    ).toBeNull();
  });

  it('does not open under another login id or another setup', () => {
    const sealed = seal();
    expect(ops.openLoginState({ sealKey, loginId: pattern(30, 16), context, sealed })).toBeNull();
    const other = ops.deriveLoginStateSealKey(pattern(31, 128));
    expect(ops.openLoginState({ sealKey: other, loginId, context, sealed })).toBeNull();
  });

  it('returns null, never throws, for malformed seals', () => {
    const sealed = seal();
    const flip = (i: number) => {
      const copy = sealed.slice();
      copy[i] = (copy[i] ?? 0) ^ 1;
      return copy;
    };
    const malformed = [
      flip(0),
      flip(5),
      flip(40),
      flip(sealed.length - 1),
      sealed.subarray(0, LOGIN_STATE_SEAL_MIN_BYTES - 1),
      sealed.subarray(0, sealed.length - 1),
      cat(sealed, [0]),
      new Uint8Array(LOGIN_STATE_SEAL_MAX_BYTES + 1).fill(2),
      new Uint8Array(0),
    ];
    for (const bad of malformed)
      expect(ops.openLoginState({ sealKey, loginId, context, sealed: bad })).toBeNull();
    for (const bad of ['x', null, undefined, [2, 3], new ArrayBuffer(100)])
      expect(ops.openLoginState({ sealKey, loginId, context, sealed: bad as never })).toBeNull();
  });

  it('refuses malformed keys, ids and contexts as programming errors', () => {
    const sealed = seal();
    expect(() => ops.openLoginState({ sealKey: pattern(1, 31), loginId, context, sealed })).toThrow(
      RuveeCryptoError,
    );
    expect(() => ops.openLoginState({ sealKey, loginId: pattern(1, 15), context, sealed })).toThrow(
      RuveeCryptoError,
    );
    expect(() =>
      ops.openLoginState({
        sealKey,
        loginId,
        context: { ...context, purpose: 'x' as never },
        sealed,
      }),
    ).toThrow(RuveeCryptoError);
    expect(() =>
      ops.openLoginState({
        sealKey,
        loginId,
        context: { ...context, accountId: pattern(1, 15) },
        sealed,
      }),
    ).toThrow(RuveeCryptoError);
    expect(() =>
      ops.openLoginState({ sealKey, loginId, context: { ...context, expiresAtMs: -1 }, sealed }),
    ).toThrow(RuveeCryptoError);
    expect(() => ops.deriveLoginStateSealKey(new Uint8Array(0))).toThrow(RuveeCryptoError);
  });
});

describe('login-state seal: buffer ownership', () => {
  it('leaves inputs untouched and returns buffers that alias nothing', () => {
    const inputs = [sealKey, loginId, challenge, state, context.idHash, context.loginSubject];
    const before = inputs.map(hex);
    const sealed = seal();
    const sealedBefore = hex(sealed);
    const opened = ops.openLoginState({ sealKey, loginId, context, sealed });
    expect(inputs.map(hex)).toEqual(before);
    expect(hex(sealed)).toBe(sealedBefore);
    opened?.challenge.fill(0);
    opened?.serverLoginState.fill(0);
    expect(ops.openLoginState({ sealKey, loginId, context, sealed })?.challenge).toEqual(challenge);
  });

  it('wipes K_state and the plaintext after sealing and opening, and the setup hash', async () => {
    const { raw, calls } = recordingPrimitives(await loadLibsodiumPrimitives());
    const recorded = buildLoginStateSealOperations(guardPrimitives(raw));
    const key = recorded.deriveLoginStateSealKey(setup);
    expect(hex(calls[0]?.result as Uint8Array)).toBe('00'.repeat(32));
    calls.length = 0;
    const sealed = recorded.sealLoginState({
      sealKey: key,
      loginId,
      context,
      challenge,
      serverLoginState: state,
    });
    const encrypt = calls.find((c) => c.method === 'aeadEncrypt');
    expect(hex(encrypt?.args[0] as Uint8Array)).toBe('00'.repeat(32 + state.length));
    expect(hex(encrypt?.args[3] as Uint8Array)).toBe('00'.repeat(32));
    calls.length = 0;
    expect(recorded.openLoginState({ sealKey: key, loginId, context, sealed })).not.toBeNull();
    const decrypt = calls.find((c) => c.method === 'aeadDecrypt');
    expect(hex(decrypt?.result as Uint8Array)).toBe('00'.repeat(32 + state.length));
    expect(hex(decrypt?.args[3] as Uint8Array)).toBe('00'.repeat(32));
  });
});
