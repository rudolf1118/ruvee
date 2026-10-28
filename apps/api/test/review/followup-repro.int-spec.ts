import { API_ERRORS, errorResponseSchema } from '@ruvee/contracts';
import type request from 'supertest';
import { registerAccount, startHarness, type Harness } from '../support/api-harness.js';
import { syntheticAccount, type SyntheticAccount } from '../support/synthetic-client.js';

/**
 * Follow-up review (docs/security/followup-review.md): reproductions of confirmed server
 * defects, against a real database. Both are fixed now and run as ordinary regressions.
 * Synthetic data only.
 */

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

function recoveryCookie(res: request.Response): string {
  const header = res.headers['set-cookie'] as unknown as string[] | undefined;
  const cookie = header?.find((c) => c.startsWith('__Host-ruvee_recovery='));
  if (!cookie) throw new Error('no recovery cookie');
  return cookie.split(';')[0] ?? '';
}

describe('FOLLOW-UP reproductions (real database)', () => {
  let h: Harness;
  let account: SyntheticAccount;
  let owner: string;

  beforeAll(async () => {
    h = await startHarness();
    account = await syntheticAccount('synthetic-followup-owner');
    owner = await registerAccount(h, account);
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  const startRecovery = () => {
    const keys = account.crypto.deriveRecoveryKeys(
      account.crypto.parseRecoveryKey(account.recoveryKeyText),
    );
    return h.post('/api/v1/recovery/start', {
      username: account.username,
      recoveryAuthKey: b64(keys.recoveryAuthKey),
      device: { id: account.crypto.generateUuid(), platform: 'web' },
    });
  };

  // F-1 (fixed): whoever holds a proven session (a stolen one, for example) can end every recovery the
  // owner starts, so the Recovery Kit cannot be used to lock them out.
  it('a normal session cannot end a recovery in progress', async () => {
    const started = await startRecovery();
    expect(started.status, started.text).toBe(200);
    const recovery = recoveryCookie(started);
    const listed = (await h.get('/api/v1/sessions', owner).expect(200)).body as {
      sessions: { id: string; kind: string }[];
    };
    const recoveries = listed.sessions.filter((x) => x.kind === 'recovery');
    expect(recoveries.length).toBeGreaterThan(0);
    for (const s of recoveries) {
      const res = await h
        .http()
        .delete(`/api/v1/sessions/${s.id}`)
        .set({ Origin: 'http://127.0.0.1:3100', 'X-Ruvee-Request': '1', Cookie: owner });
      expectError(res, 'forbidden');
    }
    // The owner's recovery must still be usable.
    expect((await h.get('/api/v1/recovery/material', recovery)).status).toBe(200);
  });

  // F-6 (fixed; the full matrix is f6-csrf-bearer.int-spec.ts): any bearer-shaped Authorization
  // header used to skip the CSRF checks of unauthenticated routes.
  it('an unauthenticated route refuses a request without Origin and X-Ruvee-Request', async () => {
    const res = await h
      .http()
      .post('/api/v1/recovery/start')
      .set('Authorization', `Bearer ${'A'.repeat(43)}`)
      .send({
        username: 'nobody-at-all',
        recoveryAuthKey: 'A'.repeat(43),
        device: { id: account.crypto.generateUuid(), platform: 'web' },
      });
    expectError(res, 'csrf_rejected');
  });
});
