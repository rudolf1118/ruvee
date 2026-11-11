import {
  ascii,
  concat,
  isBytes,
  lengthPrefixed,
  requireBytes,
  requireBytesWithin,
  requireU64,
  u64be,
} from './bytes.js';
import { RuveeCryptoError } from './errors.js';
import {
  HASH_BYTES,
  KEY_BYTES,
  MAC_BYTES,
  NONCE_BYTES,
  TAG_BYTES,
  type Primitives,
} from './primitives.js';

/**
 * The API's pending-login seal (authentication.md §4.1, owner decision of 2026-10-30 under
 * ADR-0002). Server state only: it protects an OPAQUE server login state and a device challenge
 * while they wait in the database for at most a few minutes. It is not a vault format, it uses no
 * vault key, and no client ever opens it.
 *
 *   K_seal  = MAC(H(setup), "ruvee/v1/login-state-seal")
 *   K_state = MAC(K_seal, login_id)
 *   sealed  = 0x02 ‖ nonce(24) ‖ XChaCha20-Poly1305(K_state, nonce, challenge ‖ state, AAD)
 *   AAD     = "ruvee/v1/login-state" ‖ LP(id_hash) ‖ LP(purpose) ‖ LP(subject) ‖ LP(account)
 *             ‖ LP(device) ‖ LP(platform) ‖ LP(session) ‖ LP(code) ‖ u64(expires_ms)
 *
 * `H` is BLAKE2b-256 and `MAC` keyed BLAKE2b-256 (cryptographic-design §2). `login_id` is the 16
 * random bytes the client holds; the database has only `SHA-256(login_id)`, so opening needs both
 * the setup file and the client's id. Every state has its own key, so the random nonce is never
 * the only thing keeping two seals apart.
 */

export const LOGIN_STATE_SEAL_VERSION = 0x02;
export const LOGIN_ID_BYTES = 16;
export const LOGIN_CHALLENGE_BYTES = 32;
/** A `@serenity-kit/opaque` 3.x server login state is 171 characters; anything longer is refused. */
export const LOGIN_STATE_MAX_BYTES = 512;
export const LOGIN_STATE_SEAL_MIN_BYTES = 1 + NONCE_BYTES + LOGIN_CHALLENGE_BYTES + 1 + TAG_BYTES;
export const LOGIN_STATE_SEAL_MAX_BYTES =
  1 + NONCE_BYTES + LOGIN_CHALLENGE_BYTES + LOGIN_STATE_MAX_BYTES + TAG_BYTES;
/** The serialized OPAQUE setup is 128 bytes; the bound only keeps the hash input sane. */
const SETUP_MAX_BYTES = 4096;
const UUID_BYTES = 16;

const SEAL_KEY_DOMAIN = ascii('ruvee/v1/login-state-seal');
const AAD_DOMAIN = ascii('ruvee/v1/login-state');
const PURPOSES = ['login', 'reauth', 'reopen'] as const;
const PLATFORMS = ['web', 'extension'] as const;

export type LoginStatePurpose = (typeof PURPOSES)[number];

/** What the sealed bytes are bound to: every column of the row except `sealed` itself. */
export interface LoginStateContext {
  /** `SHA-256(login_id)`, the row's key. */
  readonly idHash: Uint8Array;
  readonly purpose: LoginStatePurpose;
  /** `SHA-256("login\0" ‖ username)`, 32 bytes. */
  readonly loginSubject: Uint8Array;
  /** 16-byte UUIDs, or null where the row has none. */
  readonly accountId: Uint8Array | null;
  readonly deviceId: Uint8Array | null;
  readonly platform: 'web' | 'extension';
  readonly sessionId: Uint8Array | null;
  readonly reopenCodeId: Uint8Array | null;
  /** Expiry in milliseconds since the epoch, as stored. */
  readonly expiresAtMs: number;
}

export interface SealLoginStateInput {
  /** From `deriveLoginStateSealKey`; borrowed. */
  readonly sealKey: Uint8Array;
  readonly loginId: Uint8Array;
  readonly context: LoginStateContext;
  readonly challenge: Uint8Array;
  /** The library's server login state, UTF-8. */
  readonly serverLoginState: Uint8Array;
}

export interface OpenLoginStateInput {
  readonly sealKey: Uint8Array;
  readonly loginId: Uint8Array;
  readonly context: LoginStateContext;
  readonly sealed: Uint8Array;
}

export interface OpenedLoginState {
  readonly challenge: Uint8Array;
  readonly serverLoginState: Uint8Array;
}

export interface LoginStateSealOperations {
  /** `K_seal` of a serialized OPAQUE server setup. The caller owns it and wipes it. */
  deriveLoginStateSealKey(setup: Uint8Array): Uint8Array;
  sealLoginState(input: SealLoginStateInput): Uint8Array;
  /**
   * The challenge and state, as new buffers the caller owns; null when the seal does not open
   * under this key, id and context, or is malformed. Never throws for a malformed `sealed`.
   */
  openLoginState(input: OpenLoginStateInput): OpenedLoginState | null;
}

function input(value: unknown, field = 'input'): Record<string, unknown> {
  if (typeof value !== 'object' || value === null)
    throw new RuveeCryptoError('invalid_argument', { field });
  return value as Record<string, unknown>;
}

function optionalId(value: unknown, field: string): Uint8Array {
  if (value === null) return new Uint8Array(0);
  return requireBytes(value, field, UUID_BYTES);
}

function oneOf<T extends string>(value: unknown, allowed: readonly T[], field: string): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value))
    throw new RuveeCryptoError('invalid_argument', { field });
  return value as T;
}

/** The canonical AAD. Every field is length-prefixed, so null (empty) and a UUID never collide. */
export function loginStateAdditionalData(context: LoginStateContext): Uint8Array {
  const value = input(context, 'context');
  return concat(
    AAD_DOMAIN,
    lengthPrefixed(requireBytes(value.idHash, 'idHash', HASH_BYTES)),
    lengthPrefixed(ascii(oneOf(value.purpose, PURPOSES, 'purpose'))),
    lengthPrefixed(requireBytes(value.loginSubject, 'loginSubject', HASH_BYTES)),
    lengthPrefixed(optionalId(value.accountId, 'accountId')),
    lengthPrefixed(optionalId(value.deviceId, 'deviceId')),
    lengthPrefixed(ascii(oneOf(value.platform, PLATFORMS, 'platform'))),
    lengthPrefixed(optionalId(value.sessionId, 'sessionId')),
    lengthPrefixed(optionalId(value.reopenCodeId, 'reopenCodeId')),
    u64be(requireU64(value.expiresAtMs, 'expiresAtMs')),
  );
}

export function buildLoginStateSealOperations(p: Primitives): LoginStateSealOperations {
  const stateKey = (sealKey: unknown, loginId: unknown) =>
    p.mac(
      MAC_BYTES,
      requireBytes(loginId, 'loginId', LOGIN_ID_BYTES),
      requireBytes(sealKey, 'sealKey', KEY_BYTES),
    );

  return Object.freeze({
    deriveLoginStateSealKey(setup: Uint8Array): Uint8Array {
      const inner = p.hash(requireBytesWithin(setup, 'setup', 1, SETUP_MAX_BYTES));
      try {
        return p.mac(MAC_BYTES, SEAL_KEY_DOMAIN, inner);
      } finally {
        inner.fill(0);
      }
    },

    sealLoginState(request: SealLoginStateInput): Uint8Array {
      const value = input(request);
      const challenge = requireBytes(value.challenge, 'challenge', LOGIN_CHALLENGE_BYTES);
      const state = requireBytesWithin(
        value.serverLoginState,
        'serverLoginState',
        1,
        LOGIN_STATE_MAX_BYTES,
      );
      const additionalData = loginStateAdditionalData(value.context as LoginStateContext);
      const key = stateKey(value.sealKey, value.loginId);
      const plaintext = concat(challenge, state);
      try {
        const nonce = p.randomBytes(NONCE_BYTES);
        return concat(
          Uint8Array.of(LOGIN_STATE_SEAL_VERSION),
          nonce,
          p.aeadEncrypt(plaintext, additionalData, nonce, key),
        );
      } finally {
        key.fill(0);
        plaintext.fill(0);
      }
    },

    openLoginState(request: OpenLoginStateInput): OpenedLoginState | null {
      const value = input(request);
      const sealed = value.sealed;
      if (
        !isBytes(sealed) ||
        sealed.length < LOGIN_STATE_SEAL_MIN_BYTES ||
        sealed.length > LOGIN_STATE_SEAL_MAX_BYTES ||
        sealed[0] !== LOGIN_STATE_SEAL_VERSION
      )
        return null;
      const additionalData = loginStateAdditionalData(value.context as LoginStateContext);
      const key = stateKey(value.sealKey, value.loginId);
      let plaintext: Uint8Array | null = null;
      try {
        plaintext = p.aeadDecrypt(
          sealed.subarray(1 + NONCE_BYTES),
          additionalData,
          sealed.subarray(1, 1 + NONCE_BYTES),
          key,
        );
        if (plaintext === null) return null;
        return {
          challenge: plaintext.slice(0, LOGIN_CHALLENGE_BYTES),
          serverLoginState: plaintext.slice(LOGIN_CHALLENGE_BYTES),
        };
      } finally {
        key.fill(0);
        plaintext?.fill(0);
      }
    },
  });
}
