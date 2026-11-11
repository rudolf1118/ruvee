// Test-only: turns the account of one browser end-to-end database into an account from before
// D-31, as the development migration left those (docs/security/device-proof.md §9): no AVPK, no
// device key, no session. Reads the database name from an e2e-stack state file and refuses any
// database that e2e-stack did not create. Synthetic data only.
import { readFileSync } from 'node:fs';
import pg from 'pg';

const adminUrl = process.env.RUVEE_E2E_ADMIN_DATABASE_URL;
const statePath = process.argv[2];
if (!adminUrl || !statePath) {
  console.error('Usage: RUVEE_E2E_ADMIN_DATABASE_URL=… node e2e-make-legacy.mjs <state file>');
  process.exit(1);
}
const { database } = JSON.parse(readFileSync(statePath, 'utf8'));
if (!/^ruvee_e2e_[0-9a-f]{12}$/.test(database)) {
  console.error('Not an e2e-stack database.');
  process.exit(1);
}
const url = new URL(adminUrl);
url.pathname = `/${database}`;
const client = new pg.Client({ connectionString: url.toString() });
await client.connect();
try {
  await client.query('BEGIN');
  await client.query('UPDATE account_keys SET ak_verify_key = NULL');
  await client.query('UPDATE devices SET public_key = NULL');
  await client.query('DELETE FROM proof_nonces');
  await client.query(
    "UPDATE sessions SET revoked_at = now(), revoke_reason = 'expired' WHERE revoked_at IS NULL",
  );
  await client.query('COMMIT');
} finally {
  await client.end();
}
