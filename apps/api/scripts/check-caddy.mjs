// Test-only: checks real HTTP responses through the real deploy/Caddyfile (predeployment-review
// R1 and R10). It starts an isolated API with its own throwaway database (scripts/e2e-stack.mjs),
// puts that database in the `reopening` restore state, runs Caddy from RUVEE_CADDY_IMAGE in a
// task-owned container in front of it, and asserts headers, cache rules, error paths and path
// spellings. It also checks that Caddy refuses to start without the generated header snippet.
// Synthetic data only; everything it starts is stopped and removed by exact name.
//
//   RUVEE_E2E_ADMIN_DATABASE_URL=… RUVEE_CADDY_IMAGE=caddy:2.11-alpine node scripts/check-caddy.mjs
//
// Needs the built API (dist/) and web export (apps/web/out, apps/web/out-caddy).
import { spawn, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import pg from 'pg';

const image = process.env.RUVEE_CADDY_IMAGE;
const adminUrl = process.env.RUVEE_E2E_ADMIN_DATABASE_URL;
if (!image || !adminUrl) {
  console.error(
    'Set RUVEE_CADDY_IMAGE (for example caddy:2.11-alpine) and RUVEE_E2E_ADMIN_DATABASE_URL.',
  );
  process.exit(2);
}
const repo = new URL('../../../', import.meta.url).pathname;
const web = join(repo, 'apps/web');
const { STATIC_SECURITY_HEADERS, CACHE_HTML, CACHE_HASHED_STATIC } = await import(
  join(web, 'security-headers.ts')
);
const { productionCsp } = await import(join(web, 'scripts/csp-from-export.mjs'));
for (const needed of ['out/index.html', 'out-caddy/security-headers.caddy'])
  if (!existsSync(join(web, needed))) {
    console.error(`Missing apps/web/${needed}: run pnpm --filter @ruvee/web build first.`);
    process.exit(2);
  }

const id = randomBytes(4).toString('hex');
const apiPort = Number(process.env.RUVEE_CHECK_API_PORT ?? 4151);
const sitePort = Number(process.env.RUVEE_CHECK_SITE_PORT ?? 3151);
const caddyName = `ruvee-task-caddy-check-${id}`;
const stateDir = mkdtempSync(join(tmpdir(), 'ruvee-caddy-check-'));
const stateFile = join(stateDir, 'state.json');
const failures = [];
const check = (ok, label) => {
  if (ok) console.log(`ok    ${label}`);
  else {
    console.log(`FAIL  ${label}`);
    failures.push(label);
  }
};
const docker = (args) => spawnSync('docker', args, { encoding: 'utf8' });
// Linux (CI) has no host.docker.internal and the API listens on loopback only: there Caddy shares
// the host's network and listens on the site port itself. Docker Desktop reaches the host through
// host.docker.internal and publishes the container's port instead.
const hostNetwork = process.platform === 'linux';
const network = hostNetwork
  ? { run: ['--network', 'host'], site: `http://127.0.0.1:${String(sitePort)}`, api: '127.0.0.1' }
  : {
      run: ['-p', `127.0.0.1:${String(sitePort)}:8080`],
      site: ':8080',
      api: 'host.docker.internal',
    };
const caddyArgs = (name, webRoot, extra = []) => [
  'run',
  '--rm',
  '--name',
  name,
  ...extra,
  '-v',
  `${join(repo, 'deploy/Caddyfile')}:/etc/caddy/Caddyfile:ro`,
  '-v',
  `${webRoot}:/srv/web:ro`,
  '-e',
  'RUVEE_WEB_ROOT=/srv/web',
  '-e',
  `RUVEE_SITE_ADDRESS=${network.site}`,
  '-e',
  `RUVEE_API_UPSTREAM=${network.api}:${String(apiPort)}`,
  image,
];

let stack;
async function cleanup() {
  docker(['rm', '-f', caddyName]);
  if (stack && stack.exitCode === null) {
    await new Promise((resolve) => {
      stack.once('exit', resolve);
      stack.kill('SIGTERM');
    });
  }
  rmSync(stateDir, { recursive: true, force: true });
}

try {
  // ---- R10: no snippet, no Caddy ----
  const empty = mkdtempSync(join(tmpdir(), 'ruvee-caddy-empty-'));
  const refused = docker([
    ...caddyArgs(`${caddyName}-validate`, empty),
    'caddy',
    'validate',
    '--config',
    '/etc/caddy/Caddyfile',
  ]);
  rmSync(empty, { recursive: true, force: true });
  check(
    refused.status !== 0 && /File to import not found/.test(refused.stderr + refused.stdout),
    'Caddy refuses to start without the generated header snippet',
  );

  // ---- R10: the diagnostic (CSP probe) export never gets production headers ----
  const snippet = join(web, 'out-caddy/security-headers.caddy');
  const before = readFileSync(snippet);
  const probe = spawnSync('node', ['scripts/write-caddy-headers.mjs'], {
    cwd: web,
    env: { ...process.env, RUVEE_EXPORT_DIR: 'out-diagnostics' },
    encoding: 'utf8',
  });
  check(
    probe.status !== 0 &&
      /Only the production export/.test(probe.stderr) &&
      readFileSync(snippet).equals(before),
    'the header generator refuses the diagnostic export and leaves the snippet unchanged',
  );

  // ---- The API, in the reopening state ----
  stack = spawn('node', ['scripts/e2e-stack.mjs'], {
    cwd: join(repo, 'apps/api'),
    env: {
      ...process.env,
      RUVEE_E2E_STATE_FILE: stateFile,
      RUVEE_E2E_API_PORT: String(apiPort),
      RUVEE_E2E_PUBLIC_ORIGIN: `http://127.0.0.1:${String(sitePort)}`,
    },
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  for (let i = 0; i < 150 && !existsSync(stateFile); i++)
    await new Promise((r) => setTimeout(r, 200));
  for (let i = 0; i < 150; i++) {
    const ok = await fetch(`http://127.0.0.1:${String(apiPort)}/health/live`).then(
      (r) => r.ok,
      () => false,
    );
    if (ok) break;
    await new Promise((r) => setTimeout(r, 200));
  }
  const { database } = JSON.parse(readFileSync(stateFile, 'utf8'));
  const u = new URL(adminUrl);
  u.pathname = `/${database}`;
  const db = new pg.Client({ connectionString: u.toString() });
  await db.connect();
  await db.query('CREATE SCHEMA IF NOT EXISTS ruvee_control');
  await db.query(
    'CREATE TABLE ruvee_control.restore_guard (id smallint PRIMARY KEY, state text NOT NULL)',
  );
  await db.query(`INSERT INTO ruvee_control.restore_guard VALUES (1, 'reopening')`);
  // What a restore's PREPARE grants the API's runtime role (e2e-roles.mjs names it): the gate.
  await db.query(
    `GRANT SELECT (id, state) ON ruvee_control.restore_guard TO "${database}_runtime"`,
  );
  await db.end();

  // ---- Caddy in front of it ----
  const started = docker([...caddyArgs(caddyName, web, ['-d', ...network.run])]);
  check(started.status === 0, 'Caddy starts with the generated snippet');
  const base = `http://127.0.0.1:${String(sitePort)}`;
  let ready = false;
  for (let i = 0; i < 50 && !ready; i++) {
    ready = await fetch(`${base}/`).then(
      (r) => r.ok,
      () => false,
    );
    if (!ready) await new Promise((r) => setTimeout(r, 200));
  }
  if (!ready)
    throw new Error(`Caddy is not serving: ${docker(['logs', caddyName]).stderr.slice(-500)}`);
  const get = (path, init) => fetch(`${base}${path}`, { redirect: 'manual', ...init });

  // ---- R10: headers come from this build, on documents, payloads, errors and the API ----
  const csp = await productionCsp(join(web, 'out'));
  const staticHash = readdirSync(join(web, 'out/_next/static/chunks')).find((f) =>
    f.endsWith('.js'),
  );
  const payload = readdirSync(join(web, 'out')).find((f) => f.endsWith('.txt'));
  for (const [path, status, cache] of [
    ['/', 200, CACHE_HTML],
    ['/index.html', 200, CACHE_HTML],
    [`/${payload}`, 200, CACHE_HTML],
    ['/no-such-page', 404, CACHE_HTML],
    ['/no/such/../path.txt', 404, CACHE_HTML],
    [`/_next/static/chunks/${staticHash}`, 200, CACHE_HASHED_STATIC],
    ['/api/v1/account/keys', 503, CACHE_HTML],
  ]) {
    const res = await get(path);
    await res.arrayBuffer();
    check(res.status === status, `${path} → ${String(status)} (got ${String(res.status)})`);
    check(
      res.headers.get('content-security-policy') === csp,
      `${path}: CSP is this build's policy`,
    );
    check(
      res.headers.get('cache-control') === cache,
      `${path}: Cache-Control ${cache} (got ${String(res.headers.get('cache-control'))})`,
    );
    for (const [name, value] of Object.entries(STATIC_SECURITY_HEADERS))
      check(res.headers.get(name) === value, `${path}: ${name}`);
    check(res.headers.get('server') === null, `${path}: no Server header`);
  }
  const notFound = await (await get('/no-such-page')).text();
  check(notFound.includes('<html'), 'the 404 response is the export 404 page');

  // ---- R1 through the proxy: only the exact lower-case API path reaches a handler ----
  for (const path of [
    '/API/v1/account/keys',
    '/Api/v1/account/keys',
    '/aPI/v1/account/keys',
    '/api/V1/account/keys',
    '/api/v1/Account/keys',
    '/%61pi/v1/account/keys',
    '/%41PI/v1/account/keys',
    '/api/v1/account/keys/',
    '/api//v1/account/keys',
    '/api/v1/account/keys%2F',
    '/API',
  ]) {
    const res = await get(path);
    await res.arrayBuffer();
    check(res.status === 404, `${path} → 404 (got ${String(res.status)})`);
  }
  const login = await get('/API/v1/auth/login/start', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: base, 'x-ruvee-request': '1' },
    body: '{}',
  });
  await login.arrayBuffer();
  check(login.status === 404, `POST /API/v1/auth/login/start → 404 (got ${String(login.status)})`);
  const reopen = await get('/api/v1/reopen/login/start', {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: base, 'x-ruvee-request': '1' },
    body: '{}',
  });
  await reopen.arrayBuffer();
  check(
    reopen.status === 400,
    `the reopening route is served while reopening (400 for an empty body, got ${String(reopen.status)})`,
  );
} finally {
  await cleanup();
}

console.log(
  failures.length === 0
    ? '\nAll Caddy checks passed.'
    : `\n${String(failures.length)} check(s) failed.`,
);
process.exit(failures.length === 0 ? 0 : 1);
