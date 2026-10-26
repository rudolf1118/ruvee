import { registerAccount, startHarness, type Harness } from './support/api-harness.js';
import { restoreSnapshot, takeSnapshot } from './support/backup-snapshot.js';
import { startRegistration, syntheticAccount } from './support/synthetic-client.js';
import { query } from './support/temp-database.js';

/** Characterization, input to D-28 (backup-restore.md §3.6, rule 3): its own file, its own server. */
describe('restoring a copy taken before the account existed (characterization)', () => {
  let h: Harness;

  beforeAll(async () => {
    h = await startHarness();
  }, 60_000);

  afterAll(async () => {
    await h.close();
  });

  it('reopens registration with the setup token that was unused at the time', async () => {
    const token = await h.bootstrapToken();
    await takeSnapshot(h.db.url);
    const account = await syntheticAccount('synthetic-restore-early');
    // registerAccount consumes a fresh token of its own; consume the snapshot's token as well.
    await registerAccount(h, account);
    await query(h.db.url, `UPDATE bootstrap_tokens SET used_at = now() WHERE used_at IS NULL`);
    await restoreSnapshot(h.db.url);
    const accounts = await query<{ n: string }>(h.db.url, 'SELECT count(*) AS n FROM accounts');
    expect(accounts[0]?.n).toBe('0');
    const reopened = await h.post('/api/v1/auth/register/start', {
      bootstrapToken: token,
      username: 'synthetic-restore-intruder',
      registrationRequest: startRegistration().registrationRequest,
    });
    // The restored server accepts the old token again: anyone holding it could register first.
    expect(reopened.status, reopened.text).toBe(200);
  });
});
