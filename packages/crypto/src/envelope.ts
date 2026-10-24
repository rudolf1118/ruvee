import { ascii, concat, isBytes, publicBytesEqual } from './bytes.js';
import { RuveeCryptoError } from './errors.js';
import { NONCE_BYTES, TAG_BYTES, type Primitives } from './primitives.js';

/** Envelope format version 1 (cryptographic-design §4). */
export const MAGIC = Uint8Array.of(0x52, 0x56);
export const FORMAT_VERSION = 0x01;
export const ALG_XCHACHA20POLY1305_IETF = 0x01;
export const KEY_ID_BYTES = 16;
export const HEADER_BYTES = 45;
export const ENVELOPE_MIN_BYTES = HEADER_BYTES + TAG_BYTES;
const AAD_PREFIX = ascii('ruvee/v1/aad');
const NONCE_OFFSET = 21;

/**
 * Purposes implemented in P2-03. `AK_WRAP_RECOVERY` (recovery), `ITEM_KEY`, `ITEM_BODY`,
 * `MANIFEST`, `LOCAL_RECORD` and `DEVICE_LABEL` are specified in §4.3 but belong to later
 * milestones; a decoder asked for an unregistered purpose cannot be constructed.
 */
export interface PurposeSpec {
  readonly name: string;
  readonly code: number;
  /** Which key encrypts this purpose; none may be `SK` alone (INV-17). */
  readonly keySource: 'AUK' | 'K_keyset';
  readonly plaintextMinBytes: number;
  readonly plaintextMaxBytes: number;
}

export const PURPOSES = Object.freeze({
  AK_WRAP_PASSWORD: Object.freeze({
    name: 'AK_WRAP_PASSWORD',
    code: 0x01,
    keySource: 'AUK',
    plaintextMinBytes: 32,
    plaintextMaxBytes: 32,
  }),
  KEYSET: Object.freeze({
    name: 'KEYSET',
    code: 0x03,
    keySource: 'K_keyset',
    plaintextMinBytes: 0,
    plaintextMaxBytes: 16_384,
  }),
} satisfies Record<string, PurposeSpec>);

export function envelopeMaxBytes(purpose: PurposeSpec): number {
  return ENVELOPE_MIN_BYTES + purpose.plaintextMaxBytes;
}

/** Exact size of an `AK_WRAP_PASSWORD` envelope: 93 bytes. */
export const ACCOUNT_KEY_WRAP_BYTES = envelopeMaxBytes(PURPOSES.AK_WRAP_PASSWORD);
/** Largest `KEYSET` envelope: 16,445 bytes. */
export const KEYSET_ENVELOPE_MAX_BYTES = envelopeMaxBytes(PURPOSES.KEYSET);

/** Supplies the 24-byte nonce for one encryption. Production draws it from the CSPRNG (INV-02). */
export type NonceSource = () => Uint8Array;

export interface SealRequest {
  readonly purpose: PurposeSpec;
  readonly key: Uint8Array;
  readonly keyId: Uint8Array;
  readonly context: Uint8Array;
  readonly plaintext: Uint8Array;
}

export interface OpenRequest {
  readonly purpose: PurposeSpec;
  readonly key: Uint8Array;
  readonly expectedKeyId: Uint8Array;
  readonly context: Uint8Array;
  readonly envelope: unknown;
}

function additionalData(header: Uint8Array, context: Uint8Array): Uint8Array {
  return concat(AAD_PREFIX, header, context);
}

export function sealEnvelope(
  p: Primitives,
  nextNonce: NonceSource,
  request: SealRequest,
): Uint8Array {
  const { purpose, key, keyId, context, plaintext } = request;
  if (plaintext.length < purpose.plaintextMinBytes || plaintext.length > purpose.plaintextMaxBytes)
    throw new RuveeCryptoError('invalid_argument', { field: 'plaintext' });
  if (keyId.length !== KEY_ID_BYTES)
    throw new RuveeCryptoError('invalid_argument', { field: 'keyId' });
  const nonce = nextNonce();
  if (!isBytes(nonce) || nonce.length !== NONCE_BYTES)
    throw new RuveeCryptoError('library_failure', { reason: 'unexpected_output' });
  const header = concat(
    MAGIC,
    Uint8Array.of(FORMAT_VERSION, ALG_XCHACHA20POLY1305_IETF, purpose.code),
    keyId,
    nonce,
  );
  const ciphertext = p.aeadEncrypt(plaintext, additionalData(header, context), nonce, key);
  return concat(header, ciphertext);
}

/**
 * Parses and decrypts in the order of §4.4, failing closed with one typed error and never
 * returning partial plaintext. The AAD is rebuilt from the caller's expected context; only the
 * header bytes come from the envelope, and the AEAD authenticates them.
 */
export function openEnvelope(p: Primitives, request: OpenRequest): Uint8Array {
  const { purpose, key, expectedKeyId, context, envelope } = request;
  if (!isBytes(envelope)) throw new RuveeCryptoError('invalid_argument', { field: 'envelope' });

  if (
    envelope.length < ENVELOPE_MIN_BYTES + purpose.plaintextMinBytes ||
    envelope.length > envelopeMaxBytes(purpose)
  )
    throw new RuveeCryptoError('malformed_envelope');
  if (
    envelope[0] !== MAGIC[0] ||
    envelope[1] !== MAGIC[1] ||
    envelope[2] !== FORMAT_VERSION ||
    envelope[3] !== ALG_XCHACHA20POLY1305_IETF
  )
    throw new RuveeCryptoError('unsupported_format');
  if (envelope[4] !== purpose.code) throw new RuveeCryptoError('wrong_purpose');
  if (!publicBytesEqual(envelope.subarray(5, NONCE_OFFSET), expectedKeyId))
    throw new RuveeCryptoError('wrong_key');

  const header = envelope.subarray(0, HEADER_BYTES);
  const nonce = envelope.subarray(NONCE_OFFSET, HEADER_BYTES);
  const plaintext = p.aeadDecrypt(
    envelope.subarray(HEADER_BYTES),
    additionalData(header, context),
    nonce,
    key,
  );
  if (plaintext === null) throw new RuveeCryptoError('integrity_failure');
  if (
    plaintext.length < purpose.plaintextMinBytes ||
    plaintext.length > purpose.plaintextMaxBytes
  ) {
    plaintext.fill(0);
    throw new RuveeCryptoError('malformed_plaintext');
  }
  return plaintext;
}
