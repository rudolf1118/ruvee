import { createHash } from 'node:crypto';
import { uuidToBytes } from '@ruvee/crypto';
import {
  API_ERRORS,
  errorResponseSchema,
  reloadTicketCreateResponseSchema,
  reloadTicketRedeemResponseSchema,
} from '@ruvee/contracts';
import type request from 'supertest';
import { OpaqueServerService } from '../src/auth/opaque-server.service.js';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  WRITE_HEADERS,
  type Harness,
} from './support/api-harness.js';
import { loginDevice } from './support/device-proof.js';
import { syntheticAccount, type SyntheticAccount } from './support/synthetic-client.js';
import { query } from './support/temp-database.js';

/**
 * D-34 web reload tickets, server side (web-reload-unlock.md §5, INV-25), against a real
 * database: created only for a proven web cookie session, one per session; the server half is
 * recomputed and returned once to that session; heartbeats move the 3-minute limit and, when the
 * user was active, the idle limit; lock, logout and revocation end it. Synthetic accounts only.
 */

const sha256 = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest();
const raw = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

describe('D-34: web reload tickets (real database)', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let cookie: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-d34');
    cookie = await registerAccount(h, account);
  });

  afterAll(async () => {
    await (h as Harness | undefined)?.close();
  });

  const rows = <T extends Record<string, unknown>>(sql: string, params: unknown[] = []) =>
    query<T>(h.db.url, sql, params);

  const create = async (c = cookie, idleSeconds = 900) =>
    reloadTicketCreateResponseSchema.parse(
      (await h.post('/api/v1/reload-tickets', { idleSeconds }, c).expect(201)).body,
    );
  const redeem = (ticketId: string, c = cookie) =>
    h.post('/api/v1/reload-tickets/redeem', { ticketId }, c);
  const heartbeat = (ticketId: string, active: boolean, c = cookie) =>
    h.post('/api/v1/reload-tickets/heartbeat', { ticketId, active }, c);
  const sessionIdOf = async (c: string) => {
    const token = c.slice(c.indexOf('=') + 1);
    const [row] = await rows<{ id: string }>('SELECT id FROM sessions WHERE secret_hash = $1', [
      createHash('sha256').update(token, 'utf8').digest(),
    ]);
    if (!row) throw new Error('no session');
    return row.id;
  };
  /** A new login of the same device; it supersedes the earlier session (auth.service.ts). */
  const newSession = async () => {
    const res = await loginDevice(h, account);
    expect(res.status, res.text).toBe(200);
    cookie = sessionCookie(res);
    return cookie;
  };

  it('stores only SHA-256 of the ticket id; the server half is MAC(K_srv, tid ‖ session ‖ device)', async () => {
    const ticket = await create();
    const tid = raw(ticket.ticketId);
    expect(tid).toHaveLength(16);
    const stored = await rows<Record<string, unknown>>('SELECT * FROM reload_tickets');
    expect(stored).toHaveLength(1);
    expect(stored[0]?.id_hash).toEqual(sha256(tid));
    const dump = JSON.stringify(stored, (_, v: unknown) =>
      v instanceof Buffer ? v.toString('hex') : v,
    );
    expect(dump).not.toContain(Buffer.from(tid).toString('hex'));
    expect(dump).not.toContain(Buffer.from(raw(ticket.serverHalf)).toString('hex'));

    const setup = h.app.get(OpaqueServerService).setupBytes();
    const half = account.crypto.reloadServerHalf({
      serverKey: account.crypto.deriveReloadServerKey(setup),
      ticketId: tid,
      sessionId: uuidToBytes(await sessionIdOf(cookie)),
      deviceId: uuidToBytes(account.deviceId),
    });
    expect(Buffer.from(half).toString('base64url')).toBe(ticket.serverHalf);
    expect(stored[0]?.idle_seconds).toBe(900);
  });

  it('returns the server half once, then not_found; the row is gone (single use)', async () => {
    const ticket = await create();
    const first = reloadTicketRedeemResponseSchema.parse(
      (await redeem(ticket.ticketId).expect(200)).body,
    );
    expect(first.serverHalf).toBe(ticket.serverHalf);
    expectError(await redeem(ticket.ticketId), 'not_found');
    expect(await rows('SELECT 1 FROM reload_tickets')).toHaveLength(0);
  });

  it('gives one success to two concurrent redeems', async () => {
    const ticket = await create();
    const results = await Promise.all([redeem(ticket.ticketId), redeem(ticket.ticketId)]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 404]);
  });

  it('keeps one ticket per session: a new one replaces the earlier', async () => {
    const first = await create();
    const second = await create();
    expect(await rows('SELECT 1 FROM reload_tickets')).toHaveLength(1);
    expectError(await redeem(first.ticketId), 'not_found');
    await redeem(second.ticketId).expect(200);
  });

  it("never returns a ticket to another session, even the same device's next one", async () => {
    const before = cookie;
    const ticket = await create();
    await newSession();
    expectError(await redeem(ticket.ticketId), 'not_found');
    expectError(await heartbeat(ticket.ticketId, true), 'not_found');
    // The superseded session that created it cannot authenticate any more.
    expectError(await redeem(ticket.ticketId, before), 'unauthenticated');
    // Its row is pruned at the next ticket write.
    await create();
    const left = await rows<{ session_id: string }>('SELECT session_id FROM reload_tickets');
    expect(left.map((r) => r.session_id)).toEqual([await sessionIdOf(cookie)]);
  });

  it('refuses after 3 minutes without a heartbeat, and removes the row', async () => {
    const ticket = await create();
    await rows(
      `UPDATE reload_tickets SET created_at = now() - interval '10 minutes', expires_at = now() - interval '1 second'`,
    );
    expectError(await heartbeat(ticket.ticketId, true), 'not_found');
    expect(await rows('SELECT 1 FROM reload_tickets')).toHaveLength(0);
    const again = await create();
    await rows(
      `UPDATE reload_tickets SET created_at = now() - interval '10 minutes', expires_at = now() - interval '1 second'`,
    );
    expectError(await redeem(again.ticketId), 'not_found');
  });

  it('refuses after the auto-lock period without activity, even with heartbeats', async () => {
    const ticket = await create();
    await rows(
      `UPDATE reload_tickets SET created_at = now() - interval '20 minutes', idle_expires_at = now() - interval '1 second'`,
    );
    expectError(await redeem(ticket.ticketId), 'not_found');
  });

  it('a heartbeat moves the 3-minute limit, and the idle limit only when active', async () => {
    const ticket = await create(cookie, 60);
    const read = async () =>
      (
        await rows<{ e: number; i: number }>(
          `SELECT extract(epoch FROM expires_at - now())::float AS e,
                  extract(epoch FROM idle_expires_at - now())::float AS i FROM reload_tickets`,
        )
      )[0];
    await rows(
      `UPDATE reload_tickets SET expires_at = now() + interval '10 seconds',
                                 idle_expires_at = now() + interval '20 seconds'`,
    );
    await heartbeat(ticket.ticketId, false).expect(204);
    const passive = await read();
    expect(passive?.e).toBeGreaterThan(170);
    expect(passive?.i).toBeLessThan(21);
    await heartbeat(ticket.ticketId, true).expect(204);
    const active = await read();
    expect(active?.i).toBeGreaterThan(55);
    expect(active?.i).toBeLessThanOrEqual(60);
    await redeem(ticket.ticketId).expect(200);
  });

  it('lock (DELETE) removes the ticket, and succeeds when there is none', async () => {
    const ticket = await create();
    await h
      .http()
      .delete('/api/v1/reload-tickets')
      .set(WRITE_HEADERS)
      .set('Cookie', cookie)
      .expect(204);
    expectError(await redeem(ticket.ticketId), 'not_found');
    await h
      .http()
      .delete('/api/v1/reload-tickets')
      .set(WRITE_HEADERS)
      .set('Cookie', cookie)
      .expect(204);
  });

  it('logout deletes the ticket at once', async () => {
    await create();
    expect(await rows('SELECT 1 FROM reload_tickets')).toHaveLength(1);
    await h.post('/api/v1/auth/logout', {}, cookie).expect(204);
    expect(await rows('SELECT 1 FROM reload_tickets')).toHaveLength(0);
    await newSession();
  });

  it('a session revoked elsewhere cannot redeem; its row is pruned at the next ticket write', async () => {
    const ticket = await create();
    await rows(`UPDATE sessions SET revoked_at = now(), revoke_reason = 'user' WHERE id = $1`, [
      await sessionIdOf(cookie),
    ]);
    expectError(await redeem(ticket.ticketId), 'unauthenticated');
    await newSession();
    await create();
    const left = await rows<{ session_id: string }>('SELECT session_id FROM reload_tickets');
    expect(left.map((r) => r.session_id)).toEqual([await sessionIdOf(cookie)]);
  });

  it('a pre-proof session gets none (INV-24)', async () => {
    const res = await loginDevice(h, account, { prove: false });
    expect(res.status, res.text).toBe(200);
    expectError(
      await h.post('/api/v1/reload-tickets', { idleSeconds: 900 }, sessionCookie(res)),
      'device_proof_required',
    );
    await newSession();
  });

  it('only a web device gets one', async () => {
    await rows(`UPDATE devices SET platform = 'extension' WHERE id = $1`, [account.deviceId]);
    try {
      expectError(
        await h.post('/api/v1/reload-tickets', { idleSeconds: 900 }, cookie),
        'forbidden',
      );
    } finally {
      await rows(`UPDATE devices SET platform = 'web' WHERE id = $1`, [account.deviceId]);
    }
  });

  it('accepts an idle period of 1 minute to 8 hours only (D-10)', async () => {
    for (const idleSeconds of [59, 28_801, 1.5])
      expectError(
        await h.post('/api/v1/reload-tickets', { idleSeconds }, cookie),
        'invalid_request',
      );
    await create(cookie, 60);
    await create(cookie, 28_800);
  });

  it('needs a session', async () => {
    expectError(await h.post('/api/v1/reload-tickets', { idleSeconds: 900 }), 'unauthenticated');
    expectError(
      await h.post('/api/v1/reload-tickets/redeem', { ticketId: 'A'.repeat(21) + 'A' }),
      'unauthenticated',
    );
  });

  it('never logs a ticket id or a server half (INV-12)', async () => {
    const ticket = await create();
    await heartbeat(ticket.ticketId, true).expect(204);
    await redeem(ticket.ticketId).expect(200);
    const logs = h.logs.join('\n');
    expect(logs).not.toContain(ticket.ticketId);
    expect(logs).not.toContain(ticket.serverHalf);
  });
});
