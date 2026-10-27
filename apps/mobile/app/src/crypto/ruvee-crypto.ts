import type { RuveeCrypto } from '@ruvee/crypto';
import { buildRuveeCrypto, randomNonces } from '@ruvee/crypto-internal/operations';
import { guardPrimitives, type RawPrimitives } from '@ruvee/crypto-internal/primitives';
import { mobilePrimitives } from './mobile-primitives';

/**
 * The mobile `RuveeCrypto`: packages/crypto's own operations and size guard over the app's
 * primitives (./mobile-primitives.ts), built the way `initRuveeCrypto` builds them over
 * libsodium.js. `initRuveeCrypto` itself loads the WebAssembly build, which Hermes cannot run
 * (docs/mobile/native-compatibility.md); exporting a builder from @ruvee/crypto is shared-change
 * request SC-2.
 *
 * Before the operations are returned, a known-answer test runs every primitive once and compares
 * it with values computed by the web's pinned libsodium.js 1.0.22 (scripts in
 * docs/mobile/native-compatibility.md). Any difference fails closed: the vault never opens with
 * primitives that disagree with the web.
 */

// Inputs: byte i of pattern(seed, n) is (seed * 31 + i * 7) mod 256.
const KAT = {
  blake2bKeyed32: '86953358dc8a4eed70fef73dbdd998e0ac442146e4c70fa09481e02c34cc16af',
  blake2bKeyed16: 'd9cd4e44d12fad1385da480c76923c8f7e7d829312741a1c9dd142c2cbf85660',
  blake2bUnkeyed: 'ef3fbd413275f93836eeca5817b0443ad9bef781490d4ff4fab619eec2db0e4a',
  kdfKeyset: '26dabf53c32a2cdc7156597cd3f8a3073cb703d1da0c96c5e85926f207a29a20',
  ed25519Public: '9f55b018cebf0c9a11b0aa05c47003b7823bd1ec080d2f8f3a17e0319b1b22c5',
  ed25519Signature:
    '2651d60c3e74c11f621bdc62462bb3e2f50995f0decac41ff270e88cdb27c04672144ecfd0e9a58d028a2ff23546d02659c5859ba92bcd7a7434994c39a0eb0d',
  aeadSealed:
    'c24c7039cfe0244bb1c70db3da717e29ab510f07c1b48ca75c3c6f46389075d60d30367066bd0b3592931123a2466d7637c92adf6cccdc1b6757c2d599e0626c1f3d8062ce5c44cf13986b3f25193276f93f61c17a770f023b929dfa1a9bd084301a2832315befe69d2ca8060e4284104d18d837',
  boxPublic: '1db81de4a97ab8c7e402d0fdd6ea62c58ff46894d4c325c441ccd3528ebb2d7d',
  boxPrivate: 'c8aa15c6d0c0f82547e5fb94393a784b99e9036ca50e7ca23de8b36dfeb6b88f',
  boxSealed:
    '2569b2384c428e6436d47a2462b729abf89dc836a2a7630c312d85e75aaa9a44507d9bc6ab8a1f11141994ac76bf39e0e50d6861b4e2a5da4ec6ede84a2afde7f627b3ea5c07d51aed241116c1ba05c9181a7eb6dcc73063',
  boxPlain: 'd9e0e7eef5fc030a11181f262d343b424950575e656c737a81888f969da4abb2b9c0c7ced5dce3ea',
  sha256: '5b3d1dc4d1ca41a68d5e0f83d3af3d7ca7772c9d5505c77c0947b113ee641c0f',
  /** Argon2id v1.3, t = 2, m = 8 MiB, p = 1: small enough to run at every start. */
  argon2idSmall: 'de850e908b5cfa75c49dad05dd0fa2b99f08064f05ca5cd9e68de3dd6861fc23',
} as const;

const pattern = (seed: number, n: number) =>
  Uint8Array.from({ length: n }, (_, i) => (seed * 31 + i * 7) & 0xff);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const unhex = (h: string) =>
  Uint8Array.from({ length: h.length / 2 }, (_, i) => parseInt(h.slice(i * 2, i * 2 + 2), 16));

export class CryptoSelfTestError extends Error {
  constructor(readonly check: string) {
    super(`crypto self-test failed: ${check}`);
    this.name = 'CryptoSelfTestError';
  }
}

/** Runs the known-answer test against raw primitives; throws on the first mismatch. */
export function selfTest(raw: RawPrimitives): void {
  const expect = (check: keyof typeof KAT, actual: Uint8Array | null) => {
    if (actual === null || hex(actual) !== KAT[check]) throw new CryptoSelfTestError(check);
  };
  const key = pattern(1, 32);
  const msg = pattern(2, 100);
  const aad = pattern(3, 61);
  const nonce = pattern(4, 24);
  expect('blake2bKeyed32', raw.genericHash(32, msg, key));
  expect('blake2bKeyed16', raw.genericHash(32, msg, key.subarray(0, 16)));
  expect('blake2bUnkeyed', raw.genericHash(32, msg, null));
  expect('kdfKeyset', raw.kdfDeriveFromKey(32, 1, 'rvkeyst1', key));
  const signer = raw.signSeedKeypair(pattern(5, 32));
  expect('ed25519Public', signer.publicKey);
  const signature = raw.signDetached(msg, signer.privateKey);
  expect('ed25519Signature', signature);
  if (!raw.signVerifyDetached(signature, msg, signer.publicKey))
    throw new CryptoSelfTestError('ed25519Verify');
  const tampered = signature.slice();
  tampered[0] = (tampered[0] ?? 0) ^ 1;
  if (raw.signVerifyDetached(tampered, msg, signer.publicKey))
    throw new CryptoSelfTestError('ed25519Reject');
  expect('aeadSealed', raw.aeadEncrypt(msg, aad, nonce, key));
  const opened = raw.aeadDecrypt(unhex(KAT.aeadSealed), aad, nonce, key);
  if (!opened || hex(opened) !== hex(msg)) throw new CryptoSelfTestError('aeadOpen');
  if (raw.aeadDecrypt(unhex(KAT.aeadSealed), aad.subarray(1), nonce, key) !== null)
    throw new CryptoSelfTestError('aeadRejectAad');
  expect(
    'boxPlain',
    raw.boxSealOpen(unhex(KAT.boxSealed), unhex(KAT.boxPublic), unhex(KAT.boxPrivate)),
  );
  expect('sha256', raw.sha256(key));
  expect('argon2idSmall', raw.pwhashArgon2id13(32, pattern(8, 12), pattern(9, 16), 2, 8192 * 1024));
  if (!raw.memcmp(key, key.slice()) || raw.memcmp(key, msg.subarray(0, 32)))
    throw new CryptoSelfTestError('memcmp');
  const a = raw.randombytesBuf(32);
  const b = raw.randombytesBuf(32);
  if (hex(a) === hex(b)) throw new CryptoSelfTestError('random');
}

let built: RuveeCrypto | undefined;

/** The app's crypto operations, after the self-test. Built once per process. */
export function mobileRuveeCrypto(): RuveeCrypto {
  if (built) return built;
  const raw = mobilePrimitives();
  selfTest(raw);
  const p = guardPrimitives(raw);
  built = buildRuveeCrypto(p, randomNonces(p));
  return built;
}
