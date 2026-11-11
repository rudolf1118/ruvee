import { createHash } from 'node:crypto';
import {
  API_ERRORS,
  errorResponseSchema,
  loginStartResponseSchema,
  sessionResponseSchema,
  tokenPairSchema,
  type TokenPair,
} from '@ruvee/contracts';
import type request from 'supertest';
import { ThrottleService } from '../src/auth/throttle.service.js';
import { registerAccount, startHarness, type Harness } from './support/api-harness.js';
import {
  finishLogin,
  startLogin,
  SYNTHETIC_PASSWORD,
  syntheticAccount,
  type SyntheticAccount,
} from './support/synthetic-client.js';
import { query } from './support/temp-database.js';

const EXTENSION = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop';
const OTHER_EXTENSION = 'chrome-extension://ponmlkjihgfedcbaponmlkjihgfedcba';
const EXT_HEADERS = { Origin: EXTENSION, 'X-Ruvee-Request': '1' } as const;

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

describe('token sessions for the extension (authentication.md §5, real database)', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let webCookie: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-token-owner');
    webCookie = await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  beforeEach(async () => {
    await h.app.get(ThrottleService).clearIpWindows();
  });

  const extPost = (path: string, body: object, headers: Record<string, string> = EXT_HEADERS) =>
    h.http().post(path).set(headers).send(body);
  const bearer = (token: string) => ({ Authorization: `Bearer ${token}` });

  async function extensionLogin(deviceId?: string, headers?: Record<string, string>) {
    const client = startLogin(SYNTHETIC_PASSWORD);
    const start = await extPost(
      '/api/v1/auth/login/start',
      {
        username: account.username,
        startLoginRequest: client.startLoginRequest,
        platform: 'extension',
        ...(deviceId ? { deviceId } : {}),
      },
      headers,
    );
    if (start.status !== 200) return start;
    const parsed = loginStartResponseSchema.parse(start.body);
    const finished = finishLogin(client.clientLoginState, parsed.loginResponse);
    if (!finished) throw new Error('login rejected');
    return extPost(
      '/api/v1/auth/login/finish',
      { loginId: parsed.loginId, finishLoginRequest: finished.finishLoginRequest },
      headers,
    );
  }

  async function tokens(): Promise<{ deviceId: string; tokens: TokenPair }> {
    const res = await extensionLogin();
    expect(res.status, res.text).toBe(200);
    const body = sessionResponseSchema.parse(res.body);
    if (!body.tokens) throw new Error('no tokens');
    return { deviceId: body.device.id, tokens: body.tokens };
  }

  it('logs an extension in with tokens and no cookie, as a pending extension device', async () => {
    const res = await extensionLogin();
    expect(res.status, res.text).toBe(200);
    expect(res.headers['set-cookie']).toBeUndefined();
    const body = sessionResponseSchema.parse(res.body);
    expect(body.device.status).toBe('pending');
    const access = body.tokens?.accessToken ?? '';
    const current = await h.http().get('/api/v1/devices/current').set(bearer(access));
    expect(current.status, current.text).toBe(200);
    expect(current.body).toMatchObject({ platform: 'extension', status: 'pending' });
    // A pending extension can read nothing encrypted (INV-06).
    expectError(
      await h.http().get('/api/v1/account/keys').set(bearer(access)),
      'device_not_enrolled',
    );
  });

  it('accepts a bearer token without CSRF headers, and refuses mixing or swapping credentials', async () => {
    const { tokens: t } = await tokens();
    // Bearer requests carry no ambient credential, so a write needs no Origin or custom header.
    expect((await h.http().post('/api/v1/auth/logout').set(bearer(t.accessToken))).status).toBe(
      204,
    );
    const { tokens: u } = await tokens();
    expectError(
      await h
        .http()
        .get('/api/v1/devices/current')
        .set(bearer(u.accessToken))
        .set('Cookie', webCookie),
      'invalid_request',
    );
    expectError(
      await h.http().get('/api/v1/devices/current').set({ Authorization: 'Bearer short' }),
      'unauthenticated',
    );
    expectError(
      await h
        .http()
        .get('/api/v1/devices/current')
        .set({ Authorization: `Basic ${u.accessToken}` }),
      'unauthenticated',
    );
    // A refresh token is not an access token, and a cookie value is not a bearer token.
    expectError(
      await h.http().get('/api/v1/devices/current').set(bearer(u.refreshToken)),
      'unauthenticated',
    );
    const cookieValue = webCookie.split('=')[1] ?? '';
    expectError(
      await h.http().get('/api/v1/devices/current').set(bearer(cookieValue)),
      'unauthenticated',
    );
    expectError(
      await h.http().get('/api/v1/recovery/material').set(bearer(u.accessToken)),
      'unauthenticated',
    );
  });

  it('rotates refresh tokens, and a reused one ends the whole session', async () => {
    const { tokens: first } = await tokens();
    const refreshed = await extPost('/api/v1/auth/refresh', { refreshToken: first.refreshToken });
    expect(refreshed.status, refreshed.text).toBe(200);
    const second = tokenPairSchema.parse(refreshed.body);
    expect(second.refreshToken).not.toBe(first.refreshToken);
    // The old access token was replaced; the new one works.
    expectError(
      await h.http().get('/api/v1/devices/current').set(bearer(first.accessToken)),
      'unauthenticated',
    );
    await h.http().get('/api/v1/devices/current').set(bearer(second.accessToken)).expect(200);

    // Presenting the rotated token again revokes the family, including the newest tokens.
    expectError(
      await extPost('/api/v1/auth/refresh', { refreshToken: first.refreshToken }),
      'unauthenticated',
    );
    expectError(
      await h.http().get('/api/v1/devices/current').set(bearer(second.accessToken)),
      'unauthenticated',
    );
    expectError(
      await extPost('/api/v1/auth/refresh', { refreshToken: second.refreshToken }),
      'unauthenticated',
    );
    const events = await query(
      h.db.url,
      `SELECT 1 FROM security_events WHERE type = 'refresh_reuse'`,
    );
    expect(events).toHaveLength(1);
  });

  it('expires access tokens after 10 minutes; a refresh brings a new one', async () => {
    const { tokens: t } = await tokens();
    await query(
      h.db.url,
      `UPDATE sessions SET access_expires_at = now() - interval '1 second' WHERE kind = 'token'`,
    );
    expectError(
      await h.http().get('/api/v1/devices/current').set(bearer(t.accessToken)),
      'session_expired',
    );
    const next = tokenPairSchema.parse(
      (await extPost('/api/v1/auth/refresh', { refreshToken: t.refreshToken }).expect(200)).body,
    );
    const left = Date.parse(next.accessExpiresAt) - Date.now();
    expect(left).toBeGreaterThan(9 * 60_000);
    expect(left).toBeLessThanOrEqual(10 * 60_000);
    // Past the idle limit, the refresh token no longer works.
    await query(
      h.db.url,
      `UPDATE sessions SET idle_expires_at = now() - interval '1 second' WHERE kind = 'token'`,
    );
    expectError(
      await extPost('/api/v1/auth/refresh', { refreshToken: next.refreshToken }),
      'session_expired',
    );
  });

  it('refuses a revoked extension device at refresh and on every request', async () => {
    const { deviceId, tokens: t } = await tokens();
    await query(
      h.db.url,
      `UPDATE devices SET status = 'revoked', revoked_at = now() WHERE id = $1`,
      [deviceId],
    );
    expectError(
      await h.http().get('/api/v1/devices/current').set(bearer(t.accessToken)),
      'device_revoked',
    );
    expectError(
      await extPost('/api/v1/auth/refresh', { refreshToken: t.refreshToken }),
      'device_revoked',
    );
  });

  it('lets only listed extension origins log in without a cookie', async () => {
    expectError(
      await extensionLogin(undefined, { Origin: OTHER_EXTENSION, 'X-Ruvee-Request': '1' }),
      'csrf_rejected',
    );
    expectError(await extensionLogin(undefined, { Origin: EXTENSION }), 'csrf_rejected');
    // A listed extension origin carrying a cookie is someone else's request.
    expectError(
      await h
        .http()
        .post('/api/v1/auth/refresh')
        .set(EXT_HEADERS)
        .set('Cookie', webCookie)
        .send({ refreshToken: 'A'.repeat(43) }),
      'csrf_rejected',
    );
    // Endpoints that need a session never accept the extension origin with a cookie either.
    expectError(
      await h.http().post('/api/v1/auth/logout').set(EXT_HEADERS).set('Cookie', webCookie),
      'csrf_rejected',
    );
    // The web device cannot log in as an extension.
    expectError(await extensionLogin(account.deviceId), 'invalid_request');
  });

  it('stores only hashes of access and refresh tokens (INV-13)', async () => {
    const { tokens: t } = await tokens();
    const sha = (text: string) => createHash('sha256').update(text).digest('hex');
    const rows = await query<{ row: string }>(
      h.db.url,
      `SELECT row_to_json(t)::text AS row FROM sessions t
       UNION ALL SELECT row_to_json(t)::text FROM refresh_tokens t`,
    );
    const dump = rows.map((r) => r.row).join('\n');
    for (const token of [t.accessToken, t.refreshToken]) {
      expect(dump).not.toContain(token);
      expect(dump).not.toContain(Buffer.from(token, 'base64url').toString('hex'));
      expect(dump).toContain(sha(token));
    }
  });
});
