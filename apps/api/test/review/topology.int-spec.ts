import { API_ERRORS, errorResponseSchema } from '@ruvee/contracts';
import type request from 'supertest';
import { startHarness, type Harness } from '../support/api-harness.js';
import { startLogin } from '../support/synthetic-client.js';

/**
 * The supported deployment topology (README, "Deployment topology"; authentication.md §7): exactly
 * one API process per database. Login states, per-address windows and per-session limits live
 * in that process's memory, so a second process is refused rather than splitting them.
 * Synthetic, empty databases only.
 */

function expectError(res: request.Response, code: keyof typeof API_ERRORS) {
  expect(res.status, res.text).toBe(API_ERRORS[code].status);
  expect(errorResponseSchema.parse(res.body).error).toBe(code);
}

describe('Deployment topology: one API process per database (V1)', () => {
  it('a second process on the same database serves nothing until the first one stops', async () => {
    // Each app reads DATABASE_URL when its modules load (as r14-gate-lifecycle does).
    vi.resetModules();
    const first = await startHarness();
    let second: Harness | undefined;
    let firstOpen = true;
    try {
      await first.get('/health/ready').expect(200);
      vi.resetModules();
      second = await startHarness({ database: first.db });
      const { InstanceLockService } = await import('../../src/database/instance-lock.service.js');
      expect(second.app.get(InstanceLockService).held).toBe(false);
      // Alive, never ready, and every route refused: its memory-held limits would be separate.
      await second.get('/health/live').expect(200);
      expect((await second.get('/health/ready')).status).toBe(503);
      expectError(
        await second.post('/api/v1/auth/login/start', {
          username: 'synthetic-anyone',
          startLoginRequest: startLogin().startLoginRequest,
          platform: 'web',
        }),
        'server_unavailable',
      );
      // The first one still serves.
      await first.get('/health/ready').expect(200);
      // When the first one stops, the second takes over (it retries every few seconds).
      await first.app.close();
      firstOpen = false;
      await expect
        .poll(() => second?.app.get(InstanceLockService).held, { timeout: 15_000, interval: 500 })
        .toBe(true);
      await second.get('/health/ready').expect(200);
    } finally {
      await second?.app.close();
      if (firstOpen) await first.close();
      else await first.db.drop();
    }
  }, 60_000);
});
