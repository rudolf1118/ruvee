import {
  ascii,
  concat,
  isBytes,
  lengthPrefixed,
  requireBytes,
  requireU32,
  requireU64,
  u32be,
  u64be,
  u8,
} from './bytes.js';
import { RuveeCryptoError } from './errors.js';
import {
  HASH_BYTES,
  KDF_CONTEXTS,
  KDF_SUBKEY_BYTES,
  KDF_SUBKEY_ID,
  KEY_BYTES,
  SIGN_PUBLIC_KEY_BYTES,
  SIGN_SECRET_KEY_BYTES,
  SIGNATURE_BYTES,
  type Primitives,
} from './primitives.js';
import { utf8Encode } from './utf8.js';

/**
 * Device proof of possession (device-proof.md, D-31 option A, development direction; not
 * reviewed). One module for the clients and the API, so both encode the signed bytes the same
 * way. A valid signature proves possession of a key for one exact payload; it never proves that
 * an envelope in that payload is correct or decrypts (§3).
 */

/** device-proof.md §4: one code per operation, inside every signed input. */
export const PROOF_OPERATIONS = {
  login: 1,
  session_proof: 2,
  register: 3,
  password_change: 4,
  secret_key_rotate: 5,
  recovery_key_rotate: 6,
  device_revoke: 7,
  pairing_approve: 8,
  recovery_complete: 9,
  reopen_login: 10,
  reopen_complete: 11,
} as const;
export type ProofOperation = keyof typeof PROOF_OPERATIONS;

const VERSION = 1;
const ID_BYTES = 16;
const DOMAINS = {
  device: ascii('ruvee/v1/device-proof'),
  account: ascii('ruvee/v1/ak-proof'),
  payload: ascii('ruvee/v1/proof-payload'),
  login: ascii('ruvee/v1/login-ref'),
  setup: ascii('ruvee/v1/setup-ref'),
  session: ascii('ruvee/v1/session-ref'),
} as const;

/**
 * One payload field (§4): raw bytes, an integer in its fixed encoding, UTF-8 text, or `null` for
 * an absent optional field (`LP` of zero bytes).
 */
export type ProofField =
  | Uint8Array
  | { readonly u8: number }
  | { readonly u32: number }
  | { readonly u64: number }
  | { readonly text: string }
  | null;

/** The fields every signed input shares. */
export interface ProofContext {
  readonly operation: ProofOperation;
  /** `account_id`, 16 bytes. */
  readonly accountId: Uint8Array;
  /** `binding`, 32 bytes: a login, setup or session reference. */
  readonly binding: Uint8Array;
  /** The login challenge or server nonce, 32 bytes (zeros for first setup). */
  readonly nonce: Uint8Array;
  /** `proofPayload(...)`, 32 bytes. */
  readonly payload: Uint8Array;
}

export interface DeviceProofInput extends ProofContext {
  /** `device_id`, 16 bytes. */
  readonly deviceId: Uint8Array;
}

export interface AccountProofInput extends ProofContext {
  /** `ak_id`, 16 bytes. */
  readonly accountKeyId: Uint8Array;
  readonly accountKeyEpoch: number;
}

export interface DeviceKeyPair {
  /** `DPK`, 32 bytes. */
  readonly publicKey: Uint8Array;
  /** `DSK` in libsodium's 64-byte form; the caller seals it under `K_local` and wipes it. */
  readonly secretKey: Uint8Array;
}

export interface DeviceProofOperations {
  /** A new device key pair from `crypto_sign_keypair`. */
  generateDeviceKey(): DeviceKeyPair;
  /** `payload = H("ruvee/v1/proof-payload" ‖ u8(op) ‖ LP(f₁) ‖ … ‖ LP(fₙ))`. */
  proofPayload(operation: ProofOperation, fields: readonly ProofField[]): Uint8Array;
  /** `H("ruvee/v1/login-ref" ‖ login_id)`. */
  loginBinding(loginId: Uint8Array): Uint8Array;
  /** `H("ruvee/v1/setup-ref" ‖ bootstrap_token)`. */
  setupBinding(bootstrapToken: Uint8Array): Uint8Array;
  /** `session_ref = H("ruvee/v1/session-ref" ‖ session_id)`. */
  sessionRef(sessionId: Uint8Array): Uint8Array;
  /** `crypto_sign_detached(DSI, DSK)`. */
  signDeviceProof(input: DeviceProofInput & { readonly secretKey: Uint8Array }): Uint8Array;
  verifyDeviceProof(
    input: DeviceProofInput & { readonly publicKey: Uint8Array; readonly signature: Uint8Array },
  ): boolean;
  /** `AVPK` of `AK`. The secret half is derived and wiped inside the call. */
  accountProofPublicKey(accountKey: Uint8Array): Uint8Array;
  /** `crypto_sign_detached(AKSI, AVSK)`, with `AVSK` derived from `AK` and wiped afterwards. */
  signAccountProof(input: AccountProofInput & { readonly accountKey: Uint8Array }): Uint8Array;
  verifyAccountProof(
    input: AccountProofInput & { readonly publicKey: Uint8Array; readonly signature: Uint8Array },
  ): boolean;
}

function invalid(field: string): never {
  throw new RuveeCryptoError('invalid_argument', { field });
}

function operationCode(value: unknown): number {
  if (typeof value !== 'string' || !Object.hasOwn(PROOF_OPERATIONS, value)) invalid('operation');
  return PROOF_OPERATIONS[value as ProofOperation];
}

function encodeField(field: ProofField, index: number): Uint8Array {
  const name = `fields[${String(index)}]`;
  if (field === null) return lengthPrefixed(new Uint8Array(0));
  if (isBytes(field)) return lengthPrefixed(field);
  if (typeof field !== 'object') invalid(name);
  if ('u8' in field) {
    if (!Number.isInteger(field.u8) || field.u8 < 0 || field.u8 > 0xff) invalid(name);
    return lengthPrefixed(u8(field.u8));
  }
  if ('u32' in field) return lengthPrefixed(u32be(requireU32(field.u32, name)));
  if ('u64' in field) return lengthPrefixed(u64be(requireU64(field.u64, name)));
  if ('text' in field && typeof field.text === 'string')
    return lengthPrefixed(utf8Encode(field.text));
  return invalid(name);
}

function context(i: ProofContext): Uint8Array {
  return concat(u8(operationCode(i.operation)), requireBytes(i.accountId, 'accountId', ID_BYTES));
}

function tail(i: ProofContext): Uint8Array {
  return concat(
    requireBytes(i.binding, 'binding', HASH_BYTES),
    requireBytes(i.nonce, 'nonce', HASH_BYTES),
    requireBytes(i.payload, 'payload', HASH_BYTES),
  );
}

/** `DSI` (§4): 21 + 1 + 1 + 16 + 16 + 3 × 32 = 151 bytes. */
function deviceInput(i: DeviceProofInput): Uint8Array {
  return concat(
    DOMAINS.device,
    u8(VERSION),
    context(i),
    requireBytes(i.deviceId, 'deviceId', ID_BYTES),
    tail(i),
  );
}

/** `AKSI` (§4): 17 + 1 + 1 + 16 + 16 + 4 + 3 × 32 = 151 bytes. */
function accountInput(i: AccountProofInput): Uint8Array {
  return concat(
    DOMAINS.account,
    u8(VERSION),
    context(i),
    requireBytes(i.accountKeyId, 'accountKeyId', ID_BYTES),
    u32be(requireU32(i.accountKeyEpoch, 'accountKeyEpoch')),
    tail(i),
  );
}

export function buildDeviceProofOperations(p: Primitives): DeviceProofOperations {
  const accountKeyPair = (accountKey: Uint8Array) => {
    requireBytes(accountKey, 'accountKey', KEY_BYTES);
    const seed = p.kdf(KDF_SUBKEY_BYTES, KDF_SUBKEY_ID, KDF_CONTEXTS.accountProof, accountKey);
    try {
      return p.signSeedKeypair(seed);
    } finally {
      seed.fill(0);
    }
  };

  return Object.freeze({
    generateDeviceKey: () => {
      const pair = p.signKeypair();
      return { publicKey: pair.publicKey, secretKey: pair.privateKey };
    },

    proofPayload(operation: ProofOperation, fields: readonly ProofField[]): Uint8Array {
      if (!Array.isArray(fields)) invalid('fields');
      const encoded = (fields as readonly ProofField[]).map((f, i) => encodeField(f, i));
      return p.hash(concat(DOMAINS.payload, u8(operationCode(operation)), ...encoded));
    },

    loginBinding: (loginId: Uint8Array) =>
      p.hash(concat(DOMAINS.login, requireBytes(loginId, 'loginId', ID_BYTES))),
    setupBinding: (bootstrapToken: Uint8Array) =>
      p.hash(concat(DOMAINS.setup, requireBytes(bootstrapToken, 'bootstrapToken', KEY_BYTES))),
    sessionRef: (sessionId: Uint8Array) =>
      p.hash(concat(DOMAINS.session, requireBytes(sessionId, 'sessionId', ID_BYTES))),

    signDeviceProof(i) {
      return p.sign(deviceInput(i), requireBytes(i.secretKey, 'secretKey', SIGN_SECRET_KEY_BYTES));
    },

    verifyDeviceProof(i) {
      return p.verify(
        requireBytes(i.signature, 'signature', SIGNATURE_BYTES),
        deviceInput(i),
        requireBytes(i.publicKey, 'publicKey', SIGN_PUBLIC_KEY_BYTES),
      );
    },

    accountProofPublicKey(accountKey: Uint8Array): Uint8Array {
      const pair = accountKeyPair(accountKey);
      pair.privateKey.fill(0);
      return pair.publicKey;
    },

    signAccountProof(i) {
      const message = accountInput(i);
      const pair = accountKeyPair(i.accountKey);
      try {
        return p.sign(message, pair.privateKey);
      } finally {
        pair.privateKey.fill(0);
      }
    },

    verifyAccountProof(i) {
      return p.verify(
        requireBytes(i.signature, 'signature', SIGNATURE_BYTES),
        accountInput(i),
        requireBytes(i.publicKey, 'publicKey', SIGN_PUBLIC_KEY_BYTES),
      );
    },
  } satisfies DeviceProofOperations);
}
