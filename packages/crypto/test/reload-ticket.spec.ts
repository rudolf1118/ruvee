// The web reload ticket (src/reload-ticket.ts, D-34, web-reload-unlock.md §5). The derivations
// and the envelope are rebuilt here from the specification with @noble/*, so a change to any of
// them fails these tests; agreement with one independent implementation is the evidence, not
// proof (cryptographic-design §8).

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { PURPOSES } from '../src/envelope.js';
import { RuveeCryptoError } from '../src/errors.js';
import { loadLibsodiumPrimitives } from '../src/libsodium.js';
import { buildRuveeCrypto, randomNonces, type RuveeCrypto } from '../src/operations.js';
import { guardPrimitives } from '../src/primitives.js';
import { cat, pattern } from './support/bytes.js';

const enc = (text: string) => new TextEncoder().encode(text);

const setup = pattern(1, 128);
const ticketId = pattern(2, 16);
const sessionId = pattern(3, 16);
const deviceId = pattern(4, 16);
const accountId = pattern(5, 16);
const accountKeyId = pattern(6, 16);
const tabHalf = pattern(7, 32);
const accountKey = pattern(8, 32);

function referenceServerHalf(): Uint8Array {
  const inner = blake2b(setup, { dkLen: 32 });
  const serverKey = blake2b(enc('ruvee/v1/reload-server'), { key: inner, dkLen: 32 });
  return blake2b(cat(enc('ruvee/v1/reload-half'), ticketId, sessionId, deviceId), {
    key: serverKey,
    dkLen: 32,
  });
}

function referenceTicketKey(serverHalf: Uint8Array): Uint8Array {
  return blake2b(cat(enc('ruvee/v1/reload'), tabHalf, ticketId), { key: serverHalf, dkLen: 32 });
}

let crypto: RuveeCrypto;
let serverHalf: Uint8Array;

beforeAll(async () => {
  const p = guardPrimitives(await loadLibsodiumPrimitives());
  crypto = buildRuveeCrypto(p, randomNonces(p));
  serverHalf = crypto.reloadServerHalf({
    serverKey: crypto.deriveReloadServerKey(setup),
    ticketId,
    sessionId,
    deviceId,
  });
});

const context = () => ({ serverHalf, tabHalf, ticketId, accountId, deviceId, accountKeyId });

function expectIntegrityFailure(run: () => unknown): void {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(RuveeCryptoError);
    expect((error as RuveeCryptoError).code).toBe('integrity_failure');
    return;
  }
  throw new Error('expected integrity_failure');
}

describe('reload ticket: specification', () => {
  it('derives H_srv exactly as specified', () => {
    expect(serverHalf).toEqual(referenceServerHalf());
  });

  it('seals AK in a 93-byte RELOAD_TICKET envelope that noble opens with K_reload', () => {
    const envelope = crypto.sealReloadTicket({ ...context(), accountKey });
    expect(envelope).toHaveLength(93);
    expect([...envelope.subarray(0, 5)]).toEqual([0x52, 0x56, 0x01, 0x01, 0x09]);
    expect(envelope.subarray(5, 21)).toEqual(ticketId);
    const header = envelope.subarray(0, 45);
    const aad = cat(enc('ruvee/v1/aad'), header, accountId, deviceId, accountKeyId);
    const opened = xchacha20poly1305(
      referenceTicketKey(serverHalf),
      envelope.subarray(21, 45),
      aad,
    ).decrypt(envelope.subarray(45));
    expect(opened).toEqual(accountKey);
    expect(crypto.openReloadTicket({ ...context(), envelope })).toEqual(accountKey);
  });

  it('registers purpose 0x09 keyed by K_reload, never by SK (INV-17)', () => {
    expect(PURPOSES.RELOAD_TICKET.code).toBe(0x09);
    expect(PURPOSES.RELOAD_TICKET.keySource).toBe('K_reload');
  });

  it('draws a fresh tab half and a fresh nonce each time (INV-02)', () => {
    expect(crypto.generateReloadTabHalf()).not.toEqual(crypto.generateReloadTabHalf());
    const a = crypto.sealReloadTicket({ ...context(), accountKey });
    const b = crypto.sealReloadTicket({ ...context(), accountKey });
    expect(a.subarray(21, 45)).not.toEqual(b.subarray(21, 45));
  });
});

describe('reload ticket: negative cases (INV-03, INV-04)', () => {
  const envelope = () => crypto.sealReloadTicket({ ...context(), accountKey });

  it.each([
    ['server half', { serverHalf: pattern(20, 32) }],
    ['tab half', { tabHalf: pattern(21, 32) }],
    ['account', { accountId: pattern(22, 16) }],
    ['device', { deviceId: pattern(23, 16) }],
    ['ak_id', { accountKeyId: pattern(24, 16) }],
  ])('a wrong %s fails closed', (_, change) => {
    const sealed = envelope();
    expectIntegrityFailure(() =>
      crypto.openReloadTicket({ ...context(), ...change, envelope: sealed }),
    );
  });

  it('a wrong ticket id fails closed', () => {
    const sealed = envelope();
    expect(() =>
      crypto.openReloadTicket({ ...context(), ticketId: pattern(25, 16), envelope: sealed }),
    ).toThrow(RuveeCryptoError);
  });

  it('H_srv changes with the session, the device, the ticket and the setup', () => {
    const serverKey = crypto.deriveReloadServerKey(setup);
    const half = (over: object) =>
      crypto.reloadServerHalf({ serverKey, ticketId, sessionId, deviceId, ...over });
    expect(half({ sessionId: pattern(30, 16) })).not.toEqual(serverHalf);
    expect(half({ deviceId: pattern(31, 16) })).not.toEqual(serverHalf);
    expect(half({ ticketId: pattern(32, 16) })).not.toEqual(serverHalf);
    expect(
      crypto.reloadServerHalf({
        serverKey: crypto.deriveReloadServerKey(pattern(33, 128)),
        ticketId,
        sessionId,
        deviceId,
      }),
    ).not.toEqual(serverHalf);
  });

  it('refuses inputs of the wrong length', () => {
    expect(() =>
      crypto.sealReloadTicket({ ...context(), tabHalf: pattern(40, 31), accountKey }),
    ).toThrow(RuveeCryptoError);
    expect(() => crypto.sealReloadTicket({ ...context(), accountKey: pattern(41, 16) })).toThrow(
      RuveeCryptoError,
    );
  });
});
