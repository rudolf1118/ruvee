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
import { SessionService } from '../src/sessions/session.service.js';
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
import { proofNonce, signOperation } from './support/device-proof.js';
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

  beforeEach(async () => {
    h.app.get(ThrottleService).clearIpWindows();
    // Each test starts with no open pairings and a fresh hourly pairing window.
    await query(h.db.url, 'DELETE FROM pairings');
    await query(h.db.url, `DELETE FROM auth_throttle WHERE scope = 'pairing'`);
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
    // B's device key exists before B holds AK; req_mac binds it (device-proof.md §8).
    const keyB = crypto.generateDeviceKey();
    const req = crypto.createPairingRequest({
      secret: typed,
      accountId: uuidToBytes(account.accountId),
      deviceId: uuidToBytes(b.deviceId),
      platform: 'web',
      devicePublicKey: keyB.publicKey,
    });
    const join = {
      epk: b64(req.ephemeralPublicKey),
      platform: 'web',
      devicePublicKey: b64(keyB.publicKey),
      mac: b64(req.mac),
    };
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
    expect(seen.request?.devicePublicKey).toBe(b64(keyB.publicKey));
    expect(
      crypto.verifyPairingRequest({
        ...transcript,
        platform: 'web',
        devicePublicKey: unb64(seen.request?.devicePublicKey ?? ''),
        mac: unb64(seen.request?.mac ?? ''),
      }),
    ).toBe(true);

    // B sees nothing useful before approval, and cannot read encrypted data while pending.
    const before = pairingStateResponseSchema.parse(
      (await h.get(`/api/v1/pairings/${pairingId}`, b.cookie)).body,
    );
    expect(before.response).toBeUndefined();
    expectError(await h.get('/api/v1/account/keys', b.cookie), 'device_not_enrolled');

    // Follow-up review F-10: B logged in long before A approves. Its 10 minutes to prove its key
    // start when its device becomes active, not when it logged in.
    await query(
      h.db.url,
      `UPDATE sessions SET created_at = now() - interval '30 minutes' WHERE device_id = $1`,
      [b.deviceId],
    );
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
    // A signs exactly what it verified: B's id and key, the reply, no label (op 8).
    const approval = signOperation(
      account,
      'pairing_approve',
      await proofNonce(h, cookieA, 'pairing_approve'),
      [
        unb64(pairingId),
        uuidToBytes(b.deviceId),
        keyB.publicKey,
        reply.ciphertext,
        reply.mac,
        null,
      ],
    );
    const approve = { ciphertext: b64(reply.ciphertext), mac: b64(reply.mac), ...approval };
    expect((await h.post(`/api/v1/pairings/${pairingId}/approve`, approve, cookieA)).status).toBe(
      204,
    );
    // The approval's nonce is single-use.
    expectError(
      await h.post(`/api/v1/pairings/${pairingId}/approve`, approve, cookieA),
      'pairing_state',
    );
    const [enrolled] = await query<{ public_key: Buffer }>(
      h.db.url,
      'SELECT public_key FROM devices WHERE id = $1',
      [b.deviceId],
    );
    expect(b64(enrolled?.public_key ?? new Uint8Array())).toBe(b64(keyB.publicKey));

    // B is active now, but its session is a pre-proof one: it proves the key it already holds
    // in memory before it reads anything else (device-proof.md §8).
    expectError(await h.get(`/api/v1/pairings/${pairingId}`, b.cookie), 'device_proof_required');
    const proofB = signOperation(
      account,
      'session_proof',
      await proofNonce(h, b.cookie, 'session_proof'),
      [],
      {
        deviceKey: keyB,
        deviceId: b.deviceId,
      },
    );
    expect((await h.post('/api/v1/auth/session-proof', proofB, b.cookie)).status).toBe(204);
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
    // B is enrolled and proven: it fetches the key material it unlocks with, then completes.
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

  // A race seen in CI (WebKit): B's poll was authenticated while B was still pending, A's
  // approval committed, and the handler then returned the approved reply. B never proved its key
  // and every later request was refused. Approval activates the device in the same transaction,
  // so an approved pairing always means an active device: the reply needs a proven session.
  it('an approval that commits between authentication and the read still requires the proof first', async () => {
    const { crypto } = account;
    const b = await pendingDevice();
    const secret = crypto.generatePairingSecret();
    const pairingId = b64(crypto.pairingId(secret));
    expect((await h.post('/api/v1/pairings', { pairingId }, cookieA)).status).toBe(201);
    const keyB = crypto.generateDeviceKey();
    const req = crypto.createPairingRequest({
      secret,
      accountId: uuidToBytes(account.accountId),
      deviceId: uuidToBytes(b.deviceId),
      platform: 'web',
      devicePublicKey: keyB.publicKey,
    });
    const join = {
      epk: b64(req.ephemeralPublicKey),
      platform: 'web',
      devicePublicKey: b64(keyB.publicKey),
      mac: b64(req.mac),
    };
    expect((await h.post(`/api/v1/pairings/${pairingId}/request`, join, b.cookie)).status).toBe(
      204,
    );
    const reply = crypto.createPairingResponse({
      secret,
      accountId: uuidToBytes(account.accountId),
      pairingId: unb64(pairingId),
      deviceId: uuidToBytes(b.deviceId),
      ephemeralPublicKey: req.ephemeralPublicKey,
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
    const approval = signOperation(
      account,
      'pairing_approve',
      await proofNonce(h, cookieA, 'pairing_approve'),
      [
        unb64(pairingId),
        uuidToBytes(b.deviceId),
        keyB.publicKey,
        reply.ciphertext,
        reply.mac,
        null,
      ],
    );
    expect(
      (
        await h.post(
          `/api/v1/pairings/${pairingId}/approve`,
          { ciphertext: b64(reply.ciphertext), mac: b64(reply.mac), ...approval },
          cookieA,
        )
      ).status,
    ).toBe(204);
    // B's next request is authenticated as it was just before the approval committed.
    const sessions = h.app.get(SessionService);
    const authenticate = sessions.authenticate.bind(sessions);
    const stale = vi.spyOn(sessions, 'authenticate').mockImplementationOnce(async (...args) => ({
      ...(await authenticate(...args)),
      deviceStatus: 'pending',
      proven: false,
    }));
    try {
      expectError(await h.get(`/api/v1/pairings/${pairingId}`, b.cookie), 'device_proof_required');
      expect(stale).toHaveBeenCalledTimes(1);
    } finally {
      stale.mockRestore();
    }
  });

  it('fails at device A when the server substitutes its own key, and burns the pairing', async () => {
    const { crypto } = account;
    const b = await pendingDevice();
    const secret = crypto.generatePairingSecret();
    const pairingId = b64(crypto.pairingId(secret));
    await h.post('/api/v1/pairings', { pairingId }, cookieA).expect(201);
    const keyB = crypto.generateDeviceKey();
    const req = crypto.createPairingRequest({
      secret,
      accountId: uuidToBytes(account.accountId),
      deviceId: uuidToBytes(b.deviceId),
      platform: 'web',
      devicePublicKey: keyB.publicKey,
    });
    await h
      .post(
        `/api/v1/pairings/${pairingId}/request`,
        {
          epk: b64(req.ephemeralPublicKey),
          platform: 'web',
          devicePublicKey: b64(keyB.publicKey),
          mac: b64(req.mac),
        },
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
        devicePublicKey: unb64(seen.request?.devicePublicKey ?? ''),
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
      devicePublicKey: b64(new Uint8Array(32).fill(3)),
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

  it('enrolls only the device key A verified: a key swapped after A read the request fails', async () => {
    const { crypto } = account;
    const b = await pendingDevice();
    const secret = crypto.generatePairingSecret();
    const pairingId = b64(crypto.pairingId(secret));
    await h.post('/api/v1/pairings', { pairingId }, cookieA).expect(201);
    const keyB = crypto.generateDeviceKey();
    const req = crypto.createPairingRequest({
      secret,
      accountId: uuidToBytes(account.accountId),
      deviceId: uuidToBytes(b.deviceId),
      platform: 'web',
      devicePublicKey: keyB.publicKey,
    });
    await h
      .post(
        `/api/v1/pairings/${pairingId}/request`,
        {
          epk: b64(req.ephemeralPublicKey),
          platform: 'web',
          devicePublicKey: b64(keyB.publicKey),
          mac: b64(req.mac),
        },
        b.cookie,
      )
      .expect(204);
    // A verified B's key and signs its approval over it; then the stored key is replaced.
    const approval = signOperation(
      account,
      'pairing_approve',
      await proofNonce(h, cookieA, 'pairing_approve'),
      [
        unb64(pairingId),
        uuidToBytes(b.deviceId),
        keyB.publicKey,
        new Uint8Array(49),
        new Uint8Array(32),
        null,
      ],
    );
    const attackerKey = crypto.generateDeviceKey();
    await query(h.db.url, 'UPDATE pairings SET request_device_public_key = $1', [
      Buffer.from(attackerKey.publicKey),
    ]);
    expectError(
      await h.post(
        `/api/v1/pairings/${pairingId}/approve`,
        { ciphertext: b64(new Uint8Array(49)), mac: b64(new Uint8Array(32)), ...approval },
        cookieA,
      ),
      'device_proof_failed',
    );
    const [device] = await query<{ status: string; public_key: Buffer | null }>(
      h.db.url,
      'SELECT status, public_key FROM devices WHERE id = $1',
      [b.deviceId],
    );
    expect(device).toEqual({ status: 'pending', public_key: null });
  });
});
