import { base64urlDecodeExact, base64urlEncode } from './base64url.js';
import { isBytes } from './bytes.js';
import { RuveeCryptoError } from './errors.js';
import { PURPOSES } from './envelope.js';
import { KEY_BYTES } from './primitives.js';
import { utf8DecodeStrict, utf8Encode } from './utf8.js';

export const KEYSET_FORMAT_VERSION = 1;
const VAULT_KEY_ID_BYTES = 16;
/** Canonical RFC 9562 text form, lowercase as RFC 9562 recommends for output. */
const UUID_TEXT = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export interface KeysetVault {
  readonly vaultId: string;
  /** `vk_id`, 16 bytes. */
  readonly vkId: Uint8Array;
  /** `VK`, 32 bytes. */
  readonly vk: Uint8Array;
}

/** Keyset plaintext (cryptographic-design §5.1). V1 has exactly one vault. */
export interface Keyset {
  /** `SK`, 32 bytes. */
  readonly secretKey: Uint8Array;
  readonly vaults: readonly [KeysetVault];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const own = Object.keys(value);
  return own.length === keys.length && keys.every((k) => Object.hasOwn(value, k));
}

function invalidKeyset(field: string): never {
  throw new RuveeCryptoError('invalid_argument', { field });
}

/**
 * Serializes compactly with the key order of §5.1. Decoders do not depend on whitespace or key
 * order; this fixed form only makes the provisional vectors reproducible. The JSON text holds
 * `SK` and `VK` in base64url strings, which cannot be erased; only the byte copy is wiped by the
 * caller.
 */
export function encodeKeyset(keyset: unknown): Uint8Array {
  if (!isRecord(keyset)) invalidKeyset('keyset');
  const { secretKey, vaults } = keyset;
  if (!isBytes(secretKey) || secretKey.length !== KEY_BYTES) invalidKeyset('keyset.secretKey');
  if (!Array.isArray(vaults) || vaults.length !== 1) invalidKeyset('keyset.vaults');
  const vault: unknown = vaults[0];
  if (!isRecord(vault)) invalidKeyset('keyset.vaults');
  const { vaultId, vkId, vk } = vault;
  if (typeof vaultId !== 'string' || !UUID_TEXT.test(vaultId)) invalidKeyset('keyset.vaultId');
  if (!isBytes(vkId) || vkId.length !== VAULT_KEY_ID_BYTES) invalidKeyset('keyset.vkId');
  if (!isBytes(vk) || vk.length !== KEY_BYTES) invalidKeyset('keyset.vk');

  const bytes = utf8Encode(
    JSON.stringify({
      v: KEYSET_FORMAT_VERSION,
      secretKey: base64urlEncode(secretKey),
      vaults: [{ vaultId, vkId: base64urlEncode(vkId), vk: base64urlEncode(vk) }],
    }),
  );
  if (bytes.length > PURPOSES.KEYSET.plaintextMaxBytes) {
    bytes.fill(0);
    invalidKeyset('keyset');
  }
  return bytes;
}

/**
 * Strict decoding: exactly the fields of §5.1, `v` = 1, one vault, canonical base64url with the
 * exact byte lengths, and lowercase canonical UUID text. Anything else is `malformed_plaintext`.
 * Strictness beyond §5.1 (unknown fields, UUID case) is this package's interpretation, to be
 * confirmed by the format review.
 */
export function decodeKeyset(plaintext: Uint8Array): Keyset {
  const issued: Uint8Array[] = [];
  const fail = (): never => {
    for (const bytes of issued) bytes.fill(0);
    throw new RuveeCryptoError('malformed_plaintext');
  };
  const decode = (value: unknown, length: number): Uint8Array => {
    const bytes = typeof value === 'string' ? base64urlDecodeExact(value, length) : undefined;
    if (!bytes) return fail();
    issued.push(bytes);
    return bytes;
  };

  const text = utf8DecodeStrict(plaintext);
  if (text === undefined) return fail();
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return fail();
  }
  if (!isRecord(parsed) || !hasExactKeys(parsed, ['v', 'secretKey', 'vaults'])) return fail();
  if (parsed.v !== KEYSET_FORMAT_VERSION) return fail();
  const secretKey = decode(parsed.secretKey, KEY_BYTES);
  const vaults = parsed.vaults;
  if (!Array.isArray(vaults) || vaults.length !== 1) return fail();
  const vault: unknown = vaults[0];
  if (!isRecord(vault) || !hasExactKeys(vault, ['vaultId', 'vkId', 'vk'])) return fail();
  if (typeof vault.vaultId !== 'string' || !UUID_TEXT.test(vault.vaultId)) return fail();
  const vkId = decode(vault.vkId, VAULT_KEY_ID_BYTES);
  const vk = decode(vault.vk, KEY_BYTES);
  return { secretKey, vaults: [{ vaultId: vault.vaultId, vkId, vk }] };
}
