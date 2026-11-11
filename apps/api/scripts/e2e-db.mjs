// Test-only: creates or drops one throwaway `ruvee_e2e_<hex>` database, with its own roles
// (e2e-roles.mjs), on the PostgreSQL server in RUVEE_E2E_ADMIN_DATABASE_URL, for the restore
// browser test (apps/web/e2e-restore). `create` prints the roles' names and URLs as JSON. It
// refuses any other name. Synthetic data only.
import { createDatabaseWithRoles, dropDatabaseWithRoles, E2E_DATABASE } from './e2e-roles.mjs';

const [action, name] = process.argv.slice(2);
const adminUrl = process.env.RUVEE_E2E_ADMIN_DATABASE_URL;
if (!adminUrl || !['create', 'drop'].includes(action ?? '') || !E2E_DATABASE.test(name ?? '')) {
  console.error(
    'usage: RUVEE_E2E_ADMIN_DATABASE_URL=… node e2e-db.mjs create|drop ruvee_e2e_<12 hex>',
  );
  process.exit(1);
}
if (action === 'create')
  process.stdout.write(`${JSON.stringify(await createDatabaseWithRoles(adminUrl, name))}\n`);
else await dropDatabaseWithRoles(adminUrl, name);
