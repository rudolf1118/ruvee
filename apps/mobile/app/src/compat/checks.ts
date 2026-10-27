// The Stage 1 compatibility runner (development builds only; src/App.tsx loads it behind
// __DEV__). It runs on the device, in Hermes, with the real libraries:
//
// 1. the runtime facts the shared code depends on (WebAssembly, text codecs, randomness);
// 2. the app's crypto (native libsodium + noble, src/crypto/) through every portable check of
//    packages/crypto, unchanged: published XChaCha20-Poly1305 vectors, the committed provisional
//    protocol vectors (derivations, every envelope purpose, records, manifests, pairing), the
//    vault and pairing format checks, the boundary and negative checks;
// 3. native libsodium against libsodium.js 0.8.4 (the web's pinned build) on the same device;
// 4. OPAQUE (@serenity-kit/opaque 1.1.0, D-02 configuration);
// 5. the D-31 device-proof signatures through the app's crypto;
// 6. last, because it is slow: one profile-1 Argon2id in libsodium.js's pure-JS (wasm2js) build,
//    the only form libsodium.js can take on Hermes, as evidence for D-05.
//
// Every input is synthetic. Results carry pass/fail, timings and error names, never key material.

import sodium from 'libsodium-wrappers-sumo';
import { sha256 } from '@noble/hashes/sha2.js';
import { Platform } from 'react-native';
import { loadLibsodiumPrimitives } from '@ruvee/crypto-internal/libsodium';
import { uuidToBytes } from '@ruvee/crypto';
import {
  PORTABLE_CHECKS,
  type PortableEnv,
} from '../../../../../packages/crypto/test/portable/checks';
import {
  packageOutputs,
  type ProvisionalVectorFile,
} from '../../../../../packages/crypto/test/portable/provisional';
import { mobilePrimitives } from '../crypto/mobile-primitives';
import { nativeArgon2id, nativeSodium } from '../crypto/native-libsodium';
import { nativeOpaqueClient } from '../crypto/opaque-client';
import { mobileRuveeCrypto, selfTest } from '../crypto/ruvee-crypto';
import { randomSource } from '../platform/random';
import { secureStore } from '../platform/secure-store';
import { PROVISIONAL_VECTORS_JSON, VECTOR_FILES } from './generated/vector-files';

export interface CompatResult {
  readonly id: string;
  readonly group:
    | 'runtime'
    | 'app-crypto'
    | 'native-vs-libsodium.js'
    | 'opaque'
    | 'device-proof'
    | 'libsodium.js-wasm2js';
  readonly ok: boolean;
  readonly ms: number;
  readonly detail?: string;
  readonly error?: string;
}

type Step = () => Promise<string | undefined> | string | undefined;

const PROFILE_1 = { opslimit: 3, memlimit: 64 * 1024 * 1024 } as const;

const now = () => performance.now();

function errorText(e: unknown): string {
  return e instanceof Error ? `${e.name}: ${e.message}` : String(e);
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

function pattern(seed: number, length: number): Uint8Array {
  return Uint8Array.from({ length }, (_, i) => (seed * 31 + i * 7) & 0xff);
}

function fromB64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

/** `crypto.subtle.digest('SHA-256')` for the vector-file hash checks only, removed afterwards. */
async function withTestDigest<T>(run: () => Promise<T>): Promise<T> {
  const target = (globalThis as unknown as { crypto: Record<string, unknown> }).crypto;
  if (target.subtle !== undefined) return run();
  Object.defineProperty(target, 'subtle', {
    configurable: true,
    value: {
      digest: (algorithm: string, data: ArrayBuffer) => {
        if (algorithm !== 'SHA-256') throw new Error('test digest: SHA-256 only');
        return Promise.resolve(sha256(new Uint8Array(data)).buffer);
      },
    },
  });
  try {
    return await run();
  } finally {
    delete target.subtle;
  }
}

export async function runCompatChecks(
  onResult: (result: CompatResult) => void,
): Promise<CompatResult[]> {
  const results: CompatResult[] = [];
  const step = async (id: string, group: CompatResult['group'], run: Step) => {
    const start = now();
    let result: CompatResult;
    try {
      const detail = await run();
      result = {
        id,
        group,
        ok: true,
        ms: Math.round(now() - start),
        ...(detail ? { detail } : {}),
      };
    } catch (e) {
      result = { id, group, ok: false, ms: Math.round(now() - start), error: errorText(e) };
    }
    results.push(result);
    onResult(result);
    // Let the UI render between steps; Argon2id blocks the JS thread.
    await new Promise((resolve) => setTimeout(resolve, 0));
  };

  // ---- 1. Runtime ----
  const hermes = (
    globalThis as { HermesInternal?: { getRuntimeProperties?: () => Record<string, unknown> } }
  ).HermesInternal;
  await step('engine', 'runtime', () => {
    const props = hermes?.getRuntimeProperties?.() ?? {};
    const version = props['OSS Release Version'] ?? props.Build ?? 'unknown';
    return `hermes=${String(hermes !== undefined)} version=${String(version)} os=${Platform.OS} api=${String(Platform.Version)}`;
  });
  await step('webassembly', 'runtime', async () => {
    if (typeof WebAssembly === 'undefined') throw new Error('WebAssembly is not defined');
    // The empty module: magic and version only.
    await WebAssembly.instantiate(new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]));
    return 'WebAssembly.instantiate works';
  });
  await step('text-codecs', 'runtime', () => {
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    let rejected = false;
    try {
      decoder.decode(new Uint8Array([0xc3, 0x28]));
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error('fatal TextDecoder accepted invalid UTF-8');
    if (decoder.decode(new Uint8Array([0xef, 0xbb, 0xbf, 0x41])) !== '﻿A')
      throw new Error('ignoreBOM not honoured');
    if (new TextEncoder().encode('é').length !== 2) throw new Error('TextEncoder');
    return 'TextEncoder, TextDecoder(fatal, ignoreBOM)';
  });
  await step('random-source', 'runtime', () => {
    const a = new Uint8Array(32);
    const b = new Uint8Array(32);
    crypto.getRandomValues(a);
    crypto.getRandomValues(b);
    if (same(a, b) || a.every((v) => v === 0)) throw new Error('getRandomValues output repeated');
    let quota = false;
    try {
      crypto.getRandomValues(new Uint8Array(65_537));
    } catch {
      quota = true;
    }
    if (!quota) throw new Error('getRandomValues accepted more than 65,536 bytes');
    // Offset views are filled in place, and nothing outside the view is touched.
    const backing = new Uint8Array(48);
    crypto.getRandomValues(new Uint8Array(backing.buffer, 8, 32));
    if (
      !backing.subarray(0, 8).every((v) => v === 0) ||
      !backing.subarray(40).every((v) => v === 0)
    )
      throw new Error('getRandomValues wrote outside the view');
    return `source=${randomSource()}`;
  });

  // ---- 2. The app's crypto through packages/crypto's portable checks ----
  await step('known-answer-self-test', 'app-crypto', () => {
    selfTest(mobilePrimitives());
    mobileRuveeCrypto();
    return 'every primitive equals libsodium.js 1.0.22 output';
  });
  await step('libsodium.js-load-and-pin', 'libsodium.js-wasm2js', async () => {
    await sodium.ready;
    await loadLibsodiumPrimitives();
    return `version=${sodium.sodium_version_string()} (pure-JS build: no WebAssembly)`;
  });
  const env: PortableEnv = {
    raw: mobilePrimitives(),
    // Used only by the checks that test libsodium.js itself (V-15) or compare padding with it.
    sodium,
    readVector: (file) => {
      const data = VECTOR_FILES[file];
      if (data === undefined) return Promise.reject(new Error(`no embedded vector file ${file}`));
      return Promise.resolve(fromB64(data));
    },
    committedVectors: JSON.parse(PROVISIONAL_VECTORS_JSON) as ProvisionalVectorFile,
  };
  // The package's own check also recomputes every vector with the pure-JS noble reference
  // (eight 64 MiB Argon2id runs), which Hermes cannot do in useful time. The reference agreement
  // is established in Node and three browsers; here the package's outputs over the app's
  // primitives must equal the committed file those runs verified.
  await step('provisional-protocol-vectors (committed file)', 'app-crypto', () => {
    const outputs = packageOutputs(env.raw);
    if (JSON.stringify(outputs) !== JSON.stringify(env.committedVectors.outputs))
      throw new Error('package output over the app primitives differs from the committed vectors');
    const byLabel = new Map(outputs.passwords.map((p) => [p.label, p.result]));
    if (JSON.stringify(byLabel.get('nfc')) !== JSON.stringify(byLabel.get('nfd-same-as-nfc')))
      throw new Error('NFC and NFD inputs derive different keys');
    if (byLabel.get('lone-surrogate-rejected') !== 'rejected')
      throw new Error('lone surrogate accepted');
    return `${outputs.passwords.length} password cases and every format equal the committed vectors`;
  });
  await withTestDigest(async () => {
    for (const check of PORTABLE_CHECKS.filter((c) => c.id !== 'provisional-protocol-vectors'))
      await step(check.id, 'app-crypto', async () => {
        await check.run(env);
        return undefined;
      });
  });
  await step('argon2id-profile-1', 'app-crypto', () => {
    const start = now();
    env.raw.pwhashArgon2id13(
      32,
      pattern(1, 12),
      pattern(2, 16),
      PROFILE_1.opslimit,
      PROFILE_1.memlimit,
    );
    return `${Math.round(now() - start)} ms (native, 64 MiB, t = 3, p = 1)`;
  });
  await step('aead-1mib', 'app-crypto', () => {
    const key = pattern(19, 32);
    const nonce = pattern(20, 24);
    const aad = pattern(21, 60);
    const message = new Uint8Array(1024 * 1024).fill(7);
    let start = now();
    const sealed = env.raw.aeadEncrypt(message, aad, nonce, key);
    const sealMs = Math.round(now() - start);
    start = now();
    const opened = env.raw.aeadDecrypt(sealed, aad, nonce, key);
    const openMs = Math.round(now() - start);
    if (!opened || !same(opened, message)) throw new Error('1 MiB round trip failed');
    return `noble seal ${sealMs} ms, open ${openMs} ms for 1 MiB (the LOCAL_RECORD maximum)`;
  });

  // ---- 3. Native libsodium against libsodium.js on the same device ----
  const js = await loadLibsodiumPrimitives().catch(() => undefined);
  await step('hash-kdf-sign-box', 'native-vs-libsodium.js', () => {
    if (!js) throw new Error('libsodium.js did not load');
    for (const keyLength of [16, 32]) {
      const key = pattern(5 + keyLength, keyLength);
      const msg = pattern(6, 300);
      if (!same(nativeSodium.crypto_generichash(32, msg, key), js.genericHash(32, msg, key)))
        throw new Error(`keyed BLAKE2b (${keyLength}-byte key) differs`);
    }
    const master = pattern(7, 32);
    for (const ctx of ['rvkeyst1', 'rvlocal1', 'rvmanif1', 'rvakver1'])
      if (
        !same(
          nativeSodium.crypto_kdf_derive_from_key(32, 1, ctx, master),
          js.kdfDeriveFromKey(32, 1, ctx, master),
        )
      )
        throw new Error(`crypto_kdf ${ctx} differs`);
    const seed = pattern(8, 32);
    const a = nativeSodium.crypto_sign_seed_keypair(seed);
    const b = js.signSeedKeypair(seed);
    if (!same(a.publicKey, b.publicKey)) throw new Error('Ed25519 seed key pair differs');
    const message = pattern(9, 151);
    const sig = nativeSodium.crypto_sign_detached(message, a.privateKey);
    if (!same(sig, js.signDetached(message, b.privateKey)))
      throw new Error('Ed25519 signature differs');
    const recipient = js.boxKeypair();
    const plain = pattern(10, 200);
    const fromNative = js.boxSealOpen(
      nativeSodium.crypto_box_seal(plain, recipient.publicKey),
      recipient.publicKey,
      recipient.privateKey,
    );
    if (!fromNative || !same(fromNative, plain))
      throw new Error('libsodium.js cannot open a native sealed box');
    const fromJs = nativeSodium.crypto_box_seal_open(
      js.boxSeal(plain, recipient.publicKey),
      recipient.publicKey,
      recipient.privateKey,
    );
    if (!same(fromJs, plain)) throw new Error('native cannot open a libsodium.js sealed box');
    return 'keyed BLAKE2b (16/32), crypto_kdf (4 contexts), Ed25519, sealed boxes both ways';
  });
  await step('native-aead-binary-aad', 'native-vs-libsodium.js', () => {
    if (!js) throw new Error('libsodium.js did not load');
    const key = pattern(11, 32);
    const nonce = pattern(12, 24);
    const message = pattern(13, 64);
    const textAad = 'ruvee';
    const native = nativeSodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
      message,
      textAad,
      null,
      nonce,
      key,
    );
    if (!same(native, js.aeadEncrypt(message, new TextEncoder().encode(textAad), nonce, key)))
      throw new Error('native AEAD with text AAD differs from libsodium.js');
    try {
      nativeSodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
        message,
        pattern(14, 40) as unknown as string,
        null,
        nonce,
        key,
      );
    } catch (e) {
      return `expected limitation, so AEAD uses noble: binary AAD refused (${errorText(e)})`;
    }
    throw new Error('binding accepted binary AAD; re-evaluate the AEAD choice');
  });

  // ---- 4. OPAQUE (D-02) ----
  await step('serenity-kit-opaque-on-hermes', 'opaque', async () => {
    // Required here, not at the top: the module touches WebAssembly when it loads.
    const opaque = require('@serenity-kit/opaque') as typeof import('@serenity-kit/opaque');
    await opaque.ready;
    return '@serenity-kit/opaque 1.1.0 loaded';
  });

  await step('native-opaque-binding', 'opaque', () => {
    const client = nativeOpaqueClient();
    const reg = client.startRegistration('synthetic compat lantern \u{1f511}');
    const login = client.startLogin('synthetic compat lantern \u{1f511}');
    const bytes = (text: string) => fromB64(text.replace(/-/g, '+').replace(/_/g, '/')).length;
    // ristretto255: a blinded element (32 bytes); KE1 adds a 32-byte nonce and a 32-byte key.
    if (bytes(reg.registrationRequest) !== 32) throw new Error('registration request size');
    if (bytes(login.startLoginRequest) !== 96) throw new Error('credential request size');
    if (login.clientLoginState === client.startLogin('x').clientLoginState)
      throw new Error('state reused');
    let refused = false;
    try {
      client.finishLogin(login.clientLoginState, '!!', 'x');
    } catch {
      refused = true;
    }
    if (!refused) throw new Error('malformed login response accepted');
    return 'opaque-ke 4.0.1 binding loaded; message sizes match; malformed input refused (full login: E2E)';
  });

  // ---- Keystore-backed secure storage (docs/mobile/storage-policy.md) ----
  await step('keystore-round-trip-and-level', 'runtime', async () => {
    const name = 'compat-probe';
    const value = crypto.getRandomValues(new Uint8Array(32));
    await secureStore.setBytes(name, value);
    const back = await secureStore.getBytes(name);
    await secureStore.remove(name);
    const gone = await secureStore.getBytes(name);
    if (!back || !same(back, value)) throw new Error('value did not round-trip');
    if (gone !== undefined) throw new Error('value survived removal');
    return `AES-GCM key in AndroidKeyStore; platform reports ${await secureStore.securityLevel()}`;
  });

  // ---- 5. D-31 device proof through the app's crypto ----
  await step('device-proof-sign-verify', 'device-proof', () => {
    const crypto = mobileRuveeCrypto();
    const key = crypto.generateDeviceKey();
    const input = {
      operation: 'login' as const,
      accountId: uuidToBytes('0b8f3c2e-9a1d-4f6b-8e7c-2d5a4b3c1e0f'),
      deviceId: uuidToBytes('1c9f4d3f-0b2e-4a7c-9f8d-3e6b5c4d2f10'),
      binding: crypto.loginBinding(pattern(15, 16)),
      nonce: pattern(16, 32),
      payload: crypto.proofPayload('login', [pattern(17, 96)]),
    };
    const signature = crypto.signDeviceProof({ ...input, secretKey: key.secretKey });
    key.secretKey.fill(0);
    if (!crypto.verifyDeviceProof({ ...input, publicKey: key.publicKey, signature }))
      throw new Error('own signature does not verify');
    if (
      crypto.verifyDeviceProof({
        ...input,
        nonce: pattern(18, 32),
        publicKey: key.publicKey,
        signature,
      })
    )
      throw new Error('signature verified for another nonce');
    return 'DSI signature verifies; a changed nonce does not';
  });

  // ---- 6. Evidence for D-05: Argon2id in libsodium.js's pure-JS build on Hermes ----
  await step('argon2id-profile-1-pure-js', 'libsodium.js-wasm2js', () => {
    if (!js) throw new Error('libsodium.js did not load');
    const password = pattern(3, 20);
    const salt = pattern(4, 16);
    let start = now();
    const ours = nativeArgon2id(32, password, salt, PROFILE_1.opslimit, PROFILE_1.memlimit);
    const nativeMs = Math.round(now() - start);
    start = now();
    const theirs = js.pwhashArgon2id13(32, password, salt, PROFILE_1.opslimit, PROFILE_1.memlimit);
    const jsMs = Math.round(now() - start);
    if (!same(ours, theirs)) throw new Error('native Argon2id differs from libsodium.js');
    return `pure JS ${jsMs} ms vs native ${nativeMs} ms; outputs equal`;
  });

  return results;
}
