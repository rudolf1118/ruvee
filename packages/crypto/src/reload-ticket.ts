import { ascii, concat, requireBytes, requireBytesWithin } from './bytes.js';
import { RuveeCryptoError } from './errors.js';
import {
  KEY_ID_BYTES,
  openEnvelope,
  PURPOSES,
  sealEnvelope,
  type NonceSource,
} from './envelope.js';
import { KEY_BYTES, MAC_BYTES, type Primitives } from './primitives.js';

/**
 * The web reload ticket (D-34, docs/security/web-reload-unlock.md §5). `AK` is sealed under a key
 * that needs two random halves: one the tab keeps in `sessionStorage`, one the server recomputes
 * from its setup file for the live session that created the ticket.
 *
 *   K_srv    = MAC(H(setup), "ruvee/v1/reload-server")                       server, once
 *   H_srv    = MAC(K_srv, "ruvee/v1/reload-half" ‖ tid ‖ session_id ‖ device_id)   server
 *   K_reload = MAC(H_srv, "ruvee/v1/reload" ‖ H_tab ‖ tid)                    client
 *   envelope = RELOAD_TICKET (0x09) under K_reload, key id tid,
 *              context account_id ‖ device_id ‖ ak_id, plaintext AK
 *
 * `H` is BLAKE2b-256 and `MAC` keyed BLAKE2b-256 (cryptographic-design §2). The database keeps
 * only `SHA-256(tid)`, so neither the table, nor the tab's `sessionStorage`, nor both together
 * without the setup file give `H_srv`; the live server gives it once, to the session it belongs to.
 */

export const RELOAD_TICKET_ID_BYTES = KEY_ID_BYTES;
export const RELOAD_HALF_BYTES = 32;
const UUID_BYTES = 16;
/** The serialized OPAQUE setup is 128 bytes; the bound only keeps the hash input sane. */
const SETUP_MAX_BYTES = 4096;

const SERVER_KEY_DOMAIN = ascii('ruvee/v1/reload-server');
const SERVER_HALF_DOMAIN = ascii('ruvee/v1/reload-half');
const TICKET_KEY_DOMAIN = ascii('ruvee/v1/reload');

export interface ReloadServerHalfInput {
  /** `K_srv`, from `deriveReloadServerKey`; borrowed. */
  readonly serverKey: Uint8Array;
  /** `tid`, 16 random bytes the server drew. */
  readonly ticketId: Uint8Array;
  /** The 16 raw bytes of the session's UUID. */
  readonly sessionId: Uint8Array;
  /** The 16 raw bytes of the device's UUID. */
  readonly deviceId: Uint8Array;
}

/** What a ticket envelope is bound to, besides its two halves. */
export interface ReloadTicketContext {
  /** `H_srv`, 32 bytes. */
  readonly serverHalf: Uint8Array;
  /** `H_tab`, 32 bytes. */
  readonly tabHalf: Uint8Array;
  readonly ticketId: Uint8Array;
  /** `account_id`, `device_id`: 16 raw bytes each. */
  readonly accountId: Uint8Array;
  readonly deviceId: Uint8Array;
  /** `ak_id`, 16 bytes. */
  readonly accountKeyId: Uint8Array;
}

export interface ReloadTicketOperations {
  /** `K_srv` from the serialized OPAQUE setup (server only). */
  deriveReloadServerKey(setup: Uint8Array): Uint8Array;
  /** `H_srv` for one ticket (server only). */
  reloadServerHalf(input: ReloadServerHalfInput): Uint8Array;
  /** A new 32-byte `H_tab` from the CSPRNG (client). */
  generateReloadTabHalf(): Uint8Array;
  /** The `RELOAD_TICKET` envelope of `AK`, exactly 93 bytes (client). */
  sealReloadTicket(input: ReloadTicketContext & { readonly accountKey: Uint8Array }): Uint8Array;
  /** Returns `AK`; any wrong half, id or context is `integrity_failure` (client). */
  openReloadTicket(input: ReloadTicketContext & { readonly envelope: Uint8Array }): Uint8Array;
}

function input(value: unknown): Record<string, unknown> {
  if (typeof value !== 'object' || value === null)
    throw new RuveeCryptoError('invalid_argument', { field: 'input' });
  return value as Record<string, unknown>;
}

export function buildReloadTicketOperations(
  p: Primitives,
  nextNonce: NonceSource,
): ReloadTicketOperations {
  const ticketKey = (i: Record<string, unknown>) => {
    const serverHalf = requireBytes(i.serverHalf, 'serverHalf', RELOAD_HALF_BYTES);
    const tabHalf = requireBytes(i.tabHalf, 'tabHalf', RELOAD_HALF_BYTES);
    const ticketId = requireBytes(i.ticketId, 'ticketId', RELOAD_TICKET_ID_BYTES);
    const accountId = requireBytes(i.accountId, 'accountId', UUID_BYTES);
    const deviceId = requireBytes(i.deviceId, 'deviceId', UUID_BYTES);
    const accountKeyId = requireBytes(i.accountKeyId, 'accountKeyId', KEY_ID_BYTES);
    const message = concat(TICKET_KEY_DOMAIN, tabHalf, ticketId);
    try {
      return {
        key: p.mac(MAC_BYTES, message, serverHalf),
        keyId: ticketId,
        context: concat(accountId, deviceId, accountKeyId),
      };
    } finally {
      message.fill(0);
    }
  };

  return Object.freeze({
    deriveReloadServerKey(setup: Uint8Array): Uint8Array {
      const inner = p.hash(requireBytesWithin(setup, 'setup', 1, SETUP_MAX_BYTES));
      try {
        return p.mac(MAC_BYTES, SERVER_KEY_DOMAIN, inner);
      } finally {
        inner.fill(0);
      }
    },

    reloadServerHalf(value: ReloadServerHalfInput): Uint8Array {
      const i = input(value);
      const serverKey = requireBytes(i.serverKey, 'serverKey', KEY_BYTES);
      const message = concat(
        SERVER_HALF_DOMAIN,
        requireBytes(i.ticketId, 'ticketId', RELOAD_TICKET_ID_BYTES),
        requireBytes(i.sessionId, 'sessionId', UUID_BYTES),
        requireBytes(i.deviceId, 'deviceId', UUID_BYTES),
      );
      return p.mac(MAC_BYTES, message, serverKey);
    },

    generateReloadTabHalf: () => p.randomBytes(RELOAD_HALF_BYTES),

    sealReloadTicket(value: ReloadTicketContext & { readonly accountKey: Uint8Array }): Uint8Array {
      const i = input(value);
      const accountKey = requireBytes(i.accountKey, 'accountKey', KEY_BYTES);
      const { key, keyId, context } = ticketKey(i);
      try {
        return sealEnvelope(p, nextNonce, {
          purpose: PURPOSES.RELOAD_TICKET,
          key,
          keyId,
          context,
          plaintext: accountKey,
        });
      } finally {
        key.fill(0);
      }
    },

    openReloadTicket(value: ReloadTicketContext & { readonly envelope: Uint8Array }): Uint8Array {
      const i = input(value);
      const { key, keyId, context } = ticketKey(i);
      try {
        return openEnvelope(p, {
          purpose: PURPOSES.RELOAD_TICKET,
          key,
          expectedKeyId: keyId,
          context,
          envelope: i.envelope,
        });
      } finally {
        key.fill(0);
      }
    },
  });
}
