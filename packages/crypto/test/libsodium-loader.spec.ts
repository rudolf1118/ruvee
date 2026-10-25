// The loader refuses a library that is not the pinned build. The real library is replaced here.

const state = vi.hoisted(() => ({ version: '1.0.22', fail: false, missing: false, alg: 2 }));

vi.mock('libsodium-wrappers-sumo', () => {
  const fn = () => new Uint8Array(32);
  return {
    default: {
      get ready() {
        return state.fail ? Promise.reject(new Error('wasm blocked')) : Promise.resolve();
      },
      sodium_version_string: () => state.version,
      get crypto_pwhash_ALG_ARGON2ID13() {
        return state.alg;
      },
      randombytes_buf: fn,
      get crypto_pwhash() {
        return state.missing ? undefined : fn;
      },
      crypto_generichash: fn,
      crypto_hash_sha256: fn,
      crypto_kdf_derive_from_key: fn,
      crypto_aead_xchacha20poly1305_ietf_encrypt: fn,
      crypto_aead_xchacha20poly1305_ietf_decrypt: fn,
    },
  };
});

async function load() {
  vi.resetModules();
  const { initRuveeCrypto } = await import('../src/index.js');
  return initRuveeCrypto();
}

describe('library loading', () => {
  beforeEach(() => {
    Object.assign(state, { version: '1.0.22', fail: false, missing: false, alg: 2 });
  });

  it('refuses another libsodium version', async () => {
    state.version = '1.0.23';
    await expect(load()).rejects.toMatchObject({
      code: 'library_failure',
      reason: 'version_mismatch',
    });
  });

  it('refuses a different Argon2id algorithm id', async () => {
    state.alg = 1;
    await expect(load()).rejects.toMatchObject({ reason: 'version_mismatch' });
  });

  it('refuses a build without a required function', async () => {
    state.missing = true;
    await expect(load()).rejects.toMatchObject({ reason: 'missing_function' });
  });

  it('reports a failed WebAssembly start without its message, and can retry', async () => {
    vi.resetModules();
    const { initRuveeCrypto } = await import('../src/index.js');
    state.fail = true;
    const error: unknown = await initRuveeCrypto().catch((e: unknown) => e);
    expect(error).toMatchObject({ code: 'library_failure', reason: 'initialization_failed' });
    expect(String(error)).not.toContain('wasm blocked');
    state.fail = false;
    await expect(initRuveeCrypto()).resolves.toBeDefined();
  });
});
