import { base64urlDecodeExact, base64urlEncode } from './base64url.js';
import {
  ascii,
  concat,
  isBytes,
  publicBytesEqual,
  requireBytes,
  requireU32,
  requireU64,
  u8,
} from './bytes.js';
import { crockfordDecodeExact, crockfordEncode, crockfordNormalize } from './crockford.js';
import { RuveeCryptoError } from './errors.js';
import { UUID_BYTES, UUID_TEXT } from './ids.js';
import {
  HASH_BYTES,
  KEY_BYTES,
  MAC_BYTES,
  SIGN_PUBLIC_KEY_BYTES,
  type Primitives,
} from './primitives.js';
import { utf8DecodeStrict, utf8Encode } from './utf8.js';

/**
 * Device pairing (device-enrollment.md §3, architecture-validation.md §4), approved by the owner
 * for development on 2026-10-25 (D-21). A Ruvee-specific composition of keyed BLAKE2b and
 * `crypto_box_seal`; its whole margin is the 128 bits of `S`, and it needs independent review
 * before real data. `K_pair` and the ephemeral private key never leave this module's callers'
 * ownership as anything but opaque bytes.
 */

export const PAIRING_SECRET_BYTES = 16;
export const PAIRING_ID_BYTES = 16;
const CHECK_BYTES = 2;
const PREFIX = 'PC1';
const SYMBOLS = 29;
const DOMAINS = {
  check: ascii('ruvee/v1/pc-check'),
  id: ascii('ruvee/v1/pairing-id'),
  mac: ascii('ruvee/v1/pairing-mac'),
  /** Version 2 also covers B's device public key `dpk_B` (device-proof.md §8). */
  request: ascii('ruvee/v1/pair-req-2'),
  response: ascii('ruvee/v1/pair-resp'),
} as const;

/**
 * `u8(platform)` in the request MAC. device-enrollment.md names the field but not its values;
 * this numbering is the package's interpretation, to be confirmed in the format review.
 */
export const PLATFORM_CODES = { web: 1, extension: 2, ios: 3, android: 4 } as const;
export type PairingPlatform = keyof typeof PLATFORM_CODES;

/** What the approving device sends inside the sealed box (§3.2 step 8). */
export interface PairingPayload {
  readonly accountId: string;
  readonly deviceId: string;
  /** `SK`, 32 bytes. */
  readonly secretKey: Uint8Array;
  readonly checkpoint: {
    readonly vaultId: string;
    readonly seq: number;
    readonly manifestHash: Uint8Array;
    readonly keysetVersion: number;
  };
}

interface Transcript {
  readonly secret: Uint8Array;
  readonly accountId: Uint8Array;
  readonly pairingId: Uint8Array;
  readonly deviceId: Uint8Array;
  readonly ephemeralPublicKey: Uint8Array;
}

export interface PairingOperations {
  /** `S`, 16 bytes from the CSPRNG; a new one for every attempt. */
  generatePairingSecret(): Uint8Array;
  /** `PC1-` and 29 Crockford symbols in groups of five. */
  formatPairingCode(secret: Uint8Array): string;
  /** Lenient like the Recovery Key; a bad checksum is refused before any request. */
  parsePairingCode(text: string): Uint8Array;
  /** `pairing_id = MAC(S, "ruvee/v1/pairing-id")[0..16]`, the only value the server learns. */
  pairingId(secret: Uint8Array): Uint8Array;
  /**
   * Device B: an ephemeral key pair and `req_mac` over its id, platform, ephemeral public key
   * and device public key `dpk_B`, so A approves exactly that device key.
   */
  createPairingRequest(input: {
    secret: Uint8Array;
    accountId: Uint8Array;
    deviceId: Uint8Array;
    platform: PairingPlatform;
    devicePublicKey: Uint8Array;
  }): {
    pairingId: Uint8Array;
    ephemeralPublicKey: Uint8Array;
    ephemeralPrivateKey: Uint8Array;
    mac: Uint8Array;
  };
  /** Device A: constant-time check of `req_mac` (§3.2 step 6). */
  verifyPairingRequest(
    input: Transcript & { platform: PairingPlatform; devicePublicKey: Uint8Array; mac: Uint8Array },
  ): boolean;
  /** Device A: seals the payload to B's ephemeral key and MACs the reply. */
  createPairingResponse(input: Transcript & { payload: PairingPayload }): {
    ciphertext: Uint8Array;
    mac: Uint8Array;
  };
  /**
   * Device B: verifies `resp_mac`, opens the box and checks that the payload names this
   * account and device. Any failure is `integrity_failure`; nothing is returned partially.
   */
  openPairingResponse(
    input: Transcript & {
      ephemeralPrivateKey: Uint8Array;
      ciphertext: Uint8Array;
      mac: Uint8Array;
    },
  ): PairingPayload;
}

function input(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null)
    throw new RuveeCryptoError('invalid_argument', { field: 'input' });
  return value as Record<string, unknown>;
}

function platformCode(value: unknown): number {
  if (typeof value !== 'string' || !Object.hasOwn(PLATFORM_CODES, value))
    throw new RuveeCryptoError('invalid_argument', { field: 'platform' });
  return PLATFORM_CODES[value as PairingPlatform];
}

function uuidText(bytes: Uint8Array): string {
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function encodePayload(payload: unknown): Uint8Array {
  const p = input(payload);
  const checkpoint = input(p.checkpoint);
  for (const [field, value] of [
    ['accountId', p.accountId],
    ['deviceId', p.deviceId],
    ['checkpoint.vaultId', checkpoint.vaultId],
  ] as const)
    if (typeof value !== 'string' || !UUID_TEXT.test(value))
      throw new RuveeCryptoError('invalid_argument', { field });
  return utf8Encode(
    JSON.stringify({
      v: 1,
      accountId: p.accountId,
      deviceId: p.deviceId,
      secretKey: base64urlEncode(requireBytes(p.secretKey, 'secretKey', KEY_BYTES)),
      checkpoint: {
        vaultId: checkpoint.vaultId,
        seq: requireU64(checkpoint.seq, 'checkpoint.seq'),
        manifestHash: base64urlEncode(
          requireBytes(checkpoint.manifestHash, 'checkpoint.manifestHash', HASH_BYTES),
        ),
        keysetVersion: requireU32(checkpoint.keysetVersion, 'checkpoint.keysetVersion'),
      },
    }),
  );
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((k) => Object.hasOwn(value, k));
}

/** Strict: exactly the fields above, `v` = 1, canonical encodings. */
function decodePayload(bytes: Uint8Array): PairingPayload {
  const fail = (): never => {
    throw new RuveeCryptoError('malformed_plaintext');
  };
  const text = utf8DecodeStrict(bytes);
  if (text === undefined) return fail();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return fail();
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return fail();
  const p = parsed as Record<string, unknown>;
  if (!hasExactKeys(p, ['v', 'accountId', 'deviceId', 'secretKey', 'checkpoint']) || p.v !== 1)
    return fail();
  const c = p.checkpoint as Record<string, unknown> | null;
  if (
    typeof c !== 'object' ||
    c === null ||
    !hasExactKeys(c, ['vaultId', 'seq', 'manifestHash', 'keysetVersion'])
  )
    return fail();
  const ok = (v: unknown): v is string => typeof v === 'string' && UUID_TEXT.test(v);
  if (!ok(p.accountId) || !ok(p.deviceId) || !ok(c.vaultId)) return fail();
  const secretKey =
    typeof p.secretKey === 'string' ? base64urlDecodeExact(p.secretKey, KEY_BYTES) : undefined;
  const manifestHash =
    typeof c.manifestHash === 'string'
      ? base64urlDecodeExact(c.manifestHash, HASH_BYTES)
      : undefined;
  const seq = c.seq;
  const keysetVersion = c.keysetVersion;
  if (
    !secretKey ||
    !manifestHash ||
    typeof seq !== 'number' ||
    !Number.isSafeInteger(seq) ||
    seq < 0 ||
    typeof keysetVersion !== 'number' ||
    !Number.isInteger(keysetVersion) ||
    keysetVersion < 0 ||
    keysetVersion > 0xffff_ffff
  ) {
    secretKey?.fill(0);
    return fail();
  }
  return {
    accountId: p.accountId,
    deviceId: p.deviceId,
    secretKey,
    checkpoint: { vaultId: c.vaultId, seq, manifestHash, keysetVersion },
  };
}

export function buildPairingOperations(p: Primitives): PairingOperations {
  const check = (secret: Uint8Array) => p.hash(concat(DOMAINS.check, secret)).slice(0, CHECK_BYTES);
  const derivedId = (secret: Uint8Array) =>
    p.mac(MAC_BYTES, DOMAINS.id, secret).slice(0, PAIRING_ID_BYTES);

  const transcript = (i: Record<string, unknown>) => ({
    secret: requireBytes(i.secret, 'secret', PAIRING_SECRET_BYTES),
    accountId: requireBytes(i.accountId, 'accountId', UUID_BYTES),
    pairingId: requireBytes(i.pairingId, 'pairingId', PAIRING_ID_BYTES),
    deviceId: requireBytes(i.deviceId, 'deviceId', UUID_BYTES),
    ephemeralPublicKey: requireBytes(i.ephemeralPublicKey, 'ephemeralPublicKey', KEY_BYTES),
  });

  /** `K_pair = MAC(S, "ruvee/v1/pairing-mac" ‖ account_id)`, wiped after each use. */
  const withPairKey = <T>(
    secret: Uint8Array,
    accountId: Uint8Array,
    use: (key: Uint8Array) => T,
  ): T => {
    const key = p.mac(MAC_BYTES, concat(DOMAINS.mac, accountId), secret);
    try {
      return use(key);
    } finally {
      key.fill(0);
    }
  };

  const requestMac = (
    t: ReturnType<typeof transcript>,
    platform: number,
    devicePublicKey: Uint8Array,
  ) =>
    withPairKey(t.secret, t.accountId, (key) =>
      p.mac(
        MAC_BYTES,
        concat(
          DOMAINS.request,
          t.pairingId,
          t.deviceId,
          u8(platform),
          t.ephemeralPublicKey,
          requireBytes(devicePublicKey, 'devicePublicKey', SIGN_PUBLIC_KEY_BYTES),
        ),
        key,
      ),
    );
  const responseMac = (t: ReturnType<typeof transcript>, ciphertext: Uint8Array) =>
    withPairKey(t.secret, t.accountId, (key) =>
      p.mac(
        MAC_BYTES,
        concat(DOMAINS.response, t.pairingId, t.deviceId, t.ephemeralPublicKey, ciphertext),
        key,
      ),
    );

  return Object.freeze({
    generatePairingSecret: () => p.randomBytes(PAIRING_SECRET_BYTES),

    formatPairingCode(secret: Uint8Array): string {
      const s = requireBytes(secret, 'secret', PAIRING_SECRET_BYTES);
      const payload = concat(s, check(s));
      const symbols = crockfordEncode(payload);
      payload.fill(0);
      return [PREFIX, ...(symbols.match(/.{1,5}/g) ?? [])].join('-');
    },

    parsePairingCode(text: string): Uint8Array {
      const fail = (): never => {
        throw new RuveeCryptoError('invalid_pairing_code');
      };
      if (typeof text !== 'string' || text.length > 128) return fail();
      const normalized = crockfordNormalize(text);
      if (!normalized.startsWith(PREFIX) || normalized.length !== PREFIX.length + SYMBOLS)
        return fail();
      const payload = crockfordDecodeExact(
        normalized.slice(PREFIX.length),
        PAIRING_SECRET_BYTES + CHECK_BYTES,
      );
      if (!payload) return fail();
      const secret = payload.slice(0, PAIRING_SECRET_BYTES);
      const expected = check(secret);
      const matches =
        expected[0] === payload[PAIRING_SECRET_BYTES] &&
        expected[1] === payload[PAIRING_SECRET_BYTES + 1];
      payload.fill(0);
      if (!matches) {
        secret.fill(0);
        return fail();
      }
      return secret;
    },

    pairingId: (secret: Uint8Array) =>
      derivedId(requireBytes(secret, 'secret', PAIRING_SECRET_BYTES)),

    createPairingRequest(value) {
      const i = input(value);
      const secret = requireBytes(i.secret, 'secret', PAIRING_SECRET_BYTES);
      const platform = platformCode(i.platform);
      const pairingId = derivedId(secret);
      const pair = p.boxKeypair();
      const t = transcript({ ...i, pairingId, ephemeralPublicKey: pair.publicKey });
      return {
        pairingId,
        ephemeralPublicKey: pair.publicKey,
        ephemeralPrivateKey: pair.privateKey,
        mac: requestMac(t, platform, i.devicePublicKey as Uint8Array),
      };
    },

    verifyPairingRequest(value): boolean {
      const i = input(value);
      const t = transcript(i);
      const platform = platformCode(i.platform);
      const mac = requireBytes(i.mac, 'mac', MAC_BYTES);
      // pairing_id is public; only the MAC comparison needs to be constant-time.
      const idOk = publicBytesEqual(derivedId(t.secret), t.pairingId);
      return p.macEqual(requestMac(t, platform, i.devicePublicKey as Uint8Array), mac) && idOk;
    },

    createPairingResponse(value) {
      const i = input(value);
      const t = transcript(i);
      const plaintext = encodePayload(i.payload);
      try {
        const ciphertext = p.boxSeal(plaintext, t.ephemeralPublicKey);
        return { ciphertext, mac: responseMac(t, ciphertext) };
      } finally {
        plaintext.fill(0);
      }
    },

    openPairingResponse(value): PairingPayload {
      const i = input(value);
      const t = transcript(i);
      const privateKey = requireBytes(i.ephemeralPrivateKey, 'ephemeralPrivateKey', KEY_BYTES);
      const ciphertext = i.ciphertext;
      if (!isBytes(ciphertext))
        throw new RuveeCryptoError('invalid_argument', { field: 'ciphertext' });
      const mac = requireBytes(i.mac, 'mac', MAC_BYTES);
      // The MAC is checked before the box is opened (§3.2 step 9).
      if (!p.macEqual(responseMac(t, ciphertext), mac))
        throw new RuveeCryptoError('integrity_failure');
      const plaintext = p.boxSealOpen(ciphertext, t.ephemeralPublicKey, privateKey);
      if (plaintext === null) throw new RuveeCryptoError('integrity_failure');
      try {
        const payload = decodePayload(plaintext);
        if (
          payload.accountId !== uuidText(t.accountId) ||
          payload.deviceId !== uuidText(t.deviceId)
        ) {
          payload.secretKey.fill(0);
          throw new RuveeCryptoError('integrity_failure');
        }
        return payload;
      } finally {
        plaintext.fill(0);
      }
    },
  } satisfies PairingOperations);
}
