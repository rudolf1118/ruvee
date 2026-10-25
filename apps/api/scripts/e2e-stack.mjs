// Test-only: an isolated API for the browser end-to-end tests. It creates its own database
// (`ruvee_e2e_<random>`) on the PostgreSQL server in RUVEE_E2E_ADMIN_DATABASE_URL, migrates it,
// writes a throwaway OPAQUE server setup and one bootstrap token, starts the built API, and on
// exit stops the API and drops the database and files it created. It never touches another
// database. Synthetic data only.
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import pg from 'pg';

const adminUrl = process.env.RUVEE_E2E_ADMIN_DATABASE_URL;
const statePath = process.env.RUVEE_E2E_STATE_FILE;
const apiPort = process.env.RUVEE_E2E_API_PORT ?? '4101';
const publicOrigin = process.env.RUVEE_E2E_PUBLIC_ORIGIN ?? 'http://127.0.0.1:3103';
if (!adminUrl || !statePath) {
  console.error('Set RUVEE_E2E_ADMIN_DATABASE_URL and RUVEE_E2E_STATE_FILE.');
  process.exit(1);
}

const apiRoot = new URL('../', import.meta.url).pathname;
const name = `ruvee_e2e_${randomBytes(6).toString('hex')}`;
const dir = join(tmpdir(), `${name}-files`);
const setupFile = join(dir, 'opaque-server-setup');
const dbUrl = (() => {
  const u = new URL(adminUrl);
  u.pathname = `/${name}`;
  return u.toString();
})();

async function admin(sql) {
  const client = new pg.Client({ connectionString: adminUrl });
  await client.connect();
  try {
    await client.query(sql);
  } finally {
    await client.end();
  }
}

let api;
let cleaning = false;
async function cleanup() {
  if (cleaning) return;
  cleaning = true;
  api?.kill('SIGTERM');
  await new Promise((resolve) => setTimeout(resolve, 300));
  await admin(`DROP DATABASE IF EXISTS "${name}" WITH (FORCE)`).catch(() => undefined);
  rmSync(dir, { recursive: true, force: true });
  rmSync(statePath, { force: true });
}
for (const signal of ['SIGINT', 'SIGTERM'])
  process.on(signal, () => {
    void cleanup().finally(() => process.exit(0));
  });

// Any failure after the database exists must still drop it.
process.on('uncaughtException', (error) => {
  console.error(error);
  void cleanup().finally(() => process.exit(1));
});
process.on('unhandledRejection', (error) => {
  console.error(error);
  void cleanup().finally(() => process.exit(1));
});

await admin(`CREATE DATABASE "${name}"`);
const env = { ...process.env, DATABASE_URL: dbUrl, PRISMA_HIDE_UPDATE_MESSAGE: '1' };
const migrated = spawnSync('node_modules/.bin/prisma', ['migrate', 'deploy'], {
  cwd: apiRoot,
  env,
  encoding: 'utf8',
});
if (migrated.status !== 0) {
  console.error(migrated.stdout, migrated.stderr);
  await cleanup();
  process.exit(1);
}
mkdirSync(dir, { recursive: true, mode: 0o700 });
const created = spawnSync('node', ['dist/admin/cli.js', 'opaque-setup', '--out', setupFile], {
  cwd: apiRoot,
  env,
  encoding: 'utf8',
});
if (created.status !== 0) {
  console.error(created.stderr);
  await cleanup();
  process.exit(1);
}
// The same row `ruvee-admin bootstrap-token` writes: only the hash is stored.
const token = randomBytes(32).toString('base64url');
const client = new pg.Client({ connectionString: dbUrl });
await client.connect();
await client.query(
  `INSERT INTO bootstrap_tokens (id, token_hash, expires_at) VALUES ($1, $2, now() + interval '60 minutes')`,
  [randomUUID(), createHash('sha256').update(Buffer.from(token, 'base64url')).digest()],
);
await client.end();
mkdirSync(dirname(statePath), { recursive: true });
writeFileSync(statePath, JSON.stringify({ bootstrapToken: token, database: name }), {
  mode: 0o600,
});

api = spawn('node', ['dist/main.js'], {
  cwd: apiRoot,
  env: {
    ...env,
    NODE_ENV: 'test',
    API_PORT: apiPort,
    API_HOST: '127.0.0.1',
    OPAQUE_SERVER_SETUP_FILE: setupFile,
    PUBLIC_ORIGIN: publicOrigin,
    SESSION_COOKIE_SECURE: 'false',
    EXTENSION_ORIGINS: process.env.RUVEE_E2E_EXTENSION_ORIGINS ?? '',
    LOG_LEVEL: 'warn',
  },
  stdio: 'inherit',
});
api.on('exit', (code) => {
  if (!cleaning) {
    console.error(`API exited with ${code}`);
    void cleanup().finally(() => process.exit(1));
  }
});
console.log(`e2e API on 127.0.0.1:${apiPort}, database ${name}`);
