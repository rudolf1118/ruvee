// Test-only: creates or drops one throwaway `ruvee_e2e_<hex>` database on the PostgreSQL server
// in RUVEE_E2E_ADMIN_DATABASE_URL, for the restore browser test (apps/web/e2e-restore). It
// refuses any other name. Synthetic data only.
import pg from 'pg';

const [action, name] = process.argv.slice(2);
const adminUrl = process.env.RUVEE_E2E_ADMIN_DATABASE_URL;
if (
  !adminUrl ||
  !['create', 'drop'].includes(action ?? '') ||
  !/^ruvee_e2e_[0-9a-f]{12}$/.test(name ?? '')
) {
  console.error(
    'usage: RUVEE_E2E_ADMIN_DATABASE_URL=… node e2e-db.mjs create|drop ruvee_e2e_<12 hex>',
  );
  process.exit(1);
}
const client = new pg.Client({ connectionString: adminUrl });
await client.connect();
try {
  await client.query(
    action === 'create'
      ? `CREATE DATABASE "${name}"`
      : `DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`,
  );
} finally {
  await client.end();
}
