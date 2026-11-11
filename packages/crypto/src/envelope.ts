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
 * Purposes implemented so far (cryptographic-design §4.3). `DEVICE_LABEL` waits for its plaintext
 * rule; a decoder asked for an unregistered purpose cannot be constructed.
 */
export interface PurposeSpec {
  readonly name: string;
  readonly code: number;
  /** Which key encrypts this purpose; none may be `SK` alone (INV-17). */
  readonly keySource: 'AUK' | 'RWK' | 'K_keyset' | 'VK' | 'IK' | 'K_manifest' | 'K_local';
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
  AK_WRAP_RECOVERY: Object.freeze({
    name: 'AK_WRAP_RECOVERY',
    code: 0x02,
    keySource: 'RWK',
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
  ITEM_KEY: Object.freeze({
    name: 'ITEM_KEY',
    code: 0x04,
    keySource: 'VK',
    plaintextMinBytes: 32,
    plaintextMaxBytes: 32,
  }),
  // Padded item JSON: at least one 256-byte block, at most 65,536 bytes (§5.2).
  ITEM_BODY: Object.freeze({
    name: 'ITEM_BODY',
    code: 0x05,
    keySource: 'IK',
    plaintextMinBytes: 256,
    plaintextMaxBytes: 65_536,
  }),
  MANIFEST: Object.freeze({
    name: 'MANIFEST',
    code: 0x06,
    keySource: 'K_manifest',
    plaintextMinBytes: 137,
    plaintextMaxBytes: 137,
  }),
  LOCAL_RECORD: Object.freeze({
    name: 'LOCAL_RECORD',
    code: 0x07,
    keySource: 'K_local',
    plaintextMinBytes: 0,
    plaintextMaxBytes: 1_048_576,
  }),
} satisfies Record<string, PurposeSpec>);

export function envelopeMaxBytes(purpose: PurposeSpec): number {
  return ENVELOPE_MIN_BYTES + purpose.plaintextMaxBytes;
}

/** Exact size of an `AK_WRAP_PASSWORD` envelope: 93 bytes. */
export const ACCOUNT_KEY_WRAP_BYTES = envelopeMaxBytes(PURPOSES.AK_WRAP_PASSWORD);
/** Largest `KEYSET` envelope: 16,445 bytes. */
export const KEYSET_ENVELOPE_MAX_BYTES = envelopeMaxBytes(PURPOSES.KEYSET);
/** Exact size of an `ITEM_KEY` envelope: 93 bytes. */
export const ITEM_KEY_ENVELOPE_BYTES = envelopeMaxBytes(PURPOSES.ITEM_KEY);
/** Largest `ITEM_BODY` envelope: 65,597 bytes. */
export const ITEM_BODY_ENVELOPE_MAX_BYTES = envelopeMaxBytes(PURPOSES.ITEM_BODY);
/** Exact size of a `MANIFEST` envelope: 198 bytes. */
export const MANIFEST_ENVELOPE_BYTES = envelopeMaxBytes(PURPOSES.MANIFEST);
/** Largest `LOCAL_RECORD` envelope: 1,048,637 bytes. */
export const LOCAL_RECORD_ENVELOPE_MAX_BYTES = envelopeMaxBytes(PURPOSES.LOCAL_RECORD);

/**
 * The checks of §4.4 steps 1 to 3 that need no key: length bounds, magic, version, algorithm
 * and purpose. The server uses this for its structural checks (sync-protocol §4.2); it proves
 * nothing about the contents. Returns the reason for the first failure, or undefined.
 */
export function envelopeStructureProblem(
  envelope: Uint8Array,
  purpose: PurposeSpec,
): 'length' | 'format' | 'purpose' | undefined {
  if (
    envelope.length < ENVELOPE_MIN_BYTES + purpose.plaintextMinBytes ||
    envelope.length > envelopeMaxBytes(purpose)
  )
    return 'length';
  if (
    envelope[0] !== MAGIC[0] ||
    envelope[1] !== MAGIC[1] ||
    envelope[2] !== FORMAT_VERSION ||
    envelope[3] !== ALG_XCHACHA20POLY1305_IETF
  )
    return 'format';
  if (envelope[4] !== purpose.code) return 'purpose';
  return undefined;
}

/** The public `key_id` of a structurally valid envelope (bytes 5..20). */
export function envelopeKeyId(envelope: Uint8Array): Uint8Array {
  return envelope.slice(5, NONCE_OFFSET);
}

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

  const problem = envelopeStructureProblem(envelope, purpose);
  if (problem === 'length') throw new RuveeCryptoError('malformed_envelope');
  if (problem === 'format') throw new RuveeCryptoError('unsupported_format');
  if (problem === 'purpose') throw new RuveeCryptoError('wrong_purpose');
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
