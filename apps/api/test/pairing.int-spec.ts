import { uuidToBytes } from '@ruvee/crypto';
import {
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  pairingStateResponseSchema,
  sessionResponseSchema,
} from '@ruvee/contracts';
import type request from 'supertest';
import { ThrottleService } from '../src/auth/throttle.service.js';
import {
  registerAccount,
  sessionCookie,
  startHarness,
  type Harness,
} from './support/api-harness.js';
import {
  finishLogin,
  startLogin,
  syntheticAccount,
  type SyntheticAccount,
} from './support/synthetic-client.js';
import { query } from './support/temp-database.js';

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

describe('pairing relay (device-enrollment §3, real database)', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let cookieA: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-pairing-owner');
    cookieA = await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  beforeEach(() => {
    h.app.get(ThrottleService).clearIpWindows();
  });

  /** A new browser logs in and becomes a pending device. */
  async function pendingDevice(): Promise<{ cookie: string; deviceId: string }> {
    const client = startLogin();
    const start = await h
      .post('/api/v1/auth/login/start', {
        username: account.username,
        startLoginRequest: client.startLoginRequest,
        platform: 'web',
      })
      .expect(200);
    const finished = finishLogin(
      client.clientLoginState,
      loginStartResponseSchema.parse(start.body).loginResponse,
    );
    const res = await h
      .post('/api/v1/auth/login/finish', {
        loginId: loginStartResponseSchema.parse(start.body).loginId,
        finishLoginRequest: finished?.finishLoginRequest,
      })
      .expect(200);
    const session = sessionResponseSchema.parse(res.body);
    expect(session.device.status).toBe('pending');
    return { cookie: sessionCookie(res), deviceId: session.device.id };
  }

  it('relays one enrollment end to end, and B ends up with the right SK', async () => {
    const { crypto } = account;
    const b = await pendingDevice();
    // A shows the code; B types it.
    const secret = crypto.generatePairingSecret();
    const code = crypto.formatPairingCode(secret);
    const pairingId = b64(crypto.pairingId(secret));
    expect((await h.post('/api/v1/pairings', { pairingId }, cookieA)).status).toBe(201);

    const typed = crypto.parsePairingCode(code);
    const req = crypto.createPairingRequest({
      secret: typed,
      accountId: uuidToBytes(account.accountId),
      deviceId: uuidToBytes(b.deviceId),
      platform: 'web',
    });
    const join = { epk: b64(req.ephemeralPublicKey), platform: 'web', mac: b64(req.mac) };
    expect((await h.post(`/api/v1/pairings/${pairingId}/request`, join, b.cookie)).status).toBe(
      204,
    );
    // Exactly one request per pairing (V-09).
    expectError(
      await h.post(`/api/v1/pairings/${pairingId}/request`, join, b.cookie),
      'pairing_state',
    );

    // A reads the request; device_id_B came from B's session.
    const seen = pairingStateResponseSchema.parse(
      (await h.get(`/api/v1/pairings/${pairingId}`, cookieA).expect(200)).body,
    );
    expect(seen.request?.requesterDeviceId).toBe(b.deviceId);
    const transcript = {
      secret,
      accountId: uuidToBytes(account.accountId),
      pairingId: unb64(pairingId),
      deviceId: uuidToBytes(b.deviceId),
      ephemeralPublicKey: unb64(seen.request?.epk ?? ''),
    };
    expect(
      crypto.verifyPairingRequest({
        ...transcript,
        platform: 'web',
        mac: unb64(seen.request?.mac ?? ''),
      }),
    ).toBe(true);

    // B sees nothing useful before approval, and cannot read encrypted data while pending.
    const before = pairingStateResponseSchema.parse(
      (await h.get(`/api/v1/pairings/${pairingId}`, b.cookie)).body,
    );
    expect(before.response).toBeUndefined();
    expectError(await h.get('/api/v1/account/keys', b.cookie), 'device_not_enrolled');

    const reply = crypto.createPairingResponse({
      ...transcript,
      payload: {
        accountId: account.accountId,
        deviceId: b.deviceId,
        secretKey: account.secretKey,
        checkpoint: {
          vaultId: account.vaultId,
          seq: 0,
          manifestHash: new Uint8Array(32),
          keysetVersion: 1,
        },
      },
    });
    const approve = { ciphertext: b64(reply.ciphertext), mac: b64(reply.mac) };
    expect((await h.post(`/api/v1/pairings/${pairingId}/approve`, approve, cookieA)).status).toBe(
      204,
    );

    const after = pairingStateResponseSchema.parse(
      (await h.get(`/api/v1/pairings/${pairingId}`, b.cookie)).body,
    );
    const payload = crypto.openPairingResponse({
      ...transcript,
      ephemeralPrivateKey: req.ephemeralPrivateKey,
      ciphertext: unb64(after.response?.ciphertext ?? ''),
      mac: unb64(after.response?.mac ?? ''),
    });
    expect(b64(payload.secretKey)).toBe(b64(account.secretKey));
    // B is enrolled now and can fetch the key material it unlocks with.
    await h.get('/api/v1/account/keys', b.cookie).expect(200);
    expect((await h.post(`/api/v1/pairings/${pairingId}/complete`, {}, b.cookie)).status).toBe(204);
    expectError(await h.get(`/api/v1/pairings/${pairingId}`, cookieA), 'not_found');
    const events = await query<{ type: string }>(
      h.db.url,
      `SELECT type FROM security_events ORDER BY created_at`,
    );
    expect(events.map((e) => e.type)).toEqual(
      expect.arrayContaining(['device_pairing_requested', 'device_enrolled']),
    );
  });

  it('fails at device A when the server substitutes its own key, and burns the pairing', async () => {
    const { crypto } = account;
    const b = await pendingDevice();
    const secret = crypto.generatePairingSecret();
    const pairingId = b64(crypto.pairingId(secret));
    await h.post('/api/v1/pairings', { pairingId }, cookieA).expect(201);
    const req = crypto.createPairingRequest({
      secret,
      accountId: uuidToBytes(account.accountId),
      deviceId: uuidToBytes(b.deviceId),
      platform: 'web',
    });
    await h
      .post(
        `/api/v1/pairings/${pairingId}/request`,
        { epk: b64(req.ephemeralPublicKey), platform: 'web', mac: b64(req.mac) },
        b.cookie,
      )
      .expect(204);
    // A malicious server replaces epk_B with a key it controls (§3.3, first row).
    await query(h.db.url, `UPDATE pairings SET request_epk = $1`, [Buffer.alloc(32, 7)]);
    const seen = pairingStateResponseSchema.parse(
      (await h.get(`/api/v1/pairings/${pairingId}`, cookieA)).body,
    );
    expect(
      crypto.verifyPairingRequest({
        secret,
        accountId: uuidToBytes(account.accountId),
        pairingId: unb64(pairingId),
        deviceId: uuidToBytes(seen.request?.requesterDeviceId ?? ''),
        ephemeralPublicKey: unb64(seen.request?.epk ?? ''),
        platform: 'web',
        mac: unb64(seen.request?.mac ?? ''),
      }),
    ).toBe(false);
    const cancel = await h
      .http()
      .delete(`/api/v1/pairings/${pairingId}`)
      .set({ Origin: 'http://127.0.0.1:3100', 'X-Ruvee-Request': '1' })
      .set('Cookie', cookieA)
      .send({ reason: 'mac_failed' });
    expect(cancel.status).toBe(204);
    expectError(await h.get(`/api/v1/pairings/${pairingId}`, b.cookie), 'not_found');
    const events = await query<{ type: string }>(
      h.db.url,
      `SELECT type FROM security_events WHERE type = 'pairing_mac_failed'`,
    );
    expect(events).toHaveLength(1);
  });

  it('refuses requests from enrolled devices, expired pairings and too many open pairings', async () => {
    const { crypto } = account;
    const secret = crypto.generatePairingSecret();
    const pairingId = b64(crypto.pairingId(secret));
    await h.post('/api/v1/pairings', { pairingId }, cookieA).expect(201);
    const join = {
      epk: b64(new Uint8Array(32).fill(1)),
      platform: 'web',
      mac: b64(new Uint8Array(32).fill(2)),
    };
    expectError(await h.post(`/api/v1/pairings/${pairingId}/request`, join, cookieA), 'forbidden');
    // The same pairing id twice is refused.
    expectError(await h.post('/api/v1/pairings', { pairingId }, cookieA), 'pairing_state');
    const b = await pendingDevice();
    await query(h.db.url, `UPDATE pairings SET expires_at = now() - interval '1 second'`);
    expectError(await h.post(`/api/v1/pairings/${pairingId}/request`, join, b.cookie), 'not_found');
    // At most 3 open pairings per account.
    for (let i = 0; i < 3; i++)
      await h
        .post(
          '/api/v1/pairings',
          { pairingId: b64(crypto.pairingId(crypto.generatePairingSecret())) },
          cookieA,
        )
        .expect(201);
    const fourth = await h.post(
      '/api/v1/pairings',
      { pairingId: b64(crypto.pairingId(crypto.generatePairingSecret())) },
      cookieA,
    );
    expectError(fourth, 'rate_limited');
    expectError(await h.post('/api/v1/pairings', { pairingId }, b.cookie), 'device_not_enrolled');
    expectError(await h.get(`/api/v1/pairings/${'A'.repeat(22)}`, cookieA), 'not_found');
    expectError(await h.get('/api/v1/pairings/not-an-id', cookieA), 'invalid_request');
  });
});
