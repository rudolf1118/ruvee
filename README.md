# Ruvee

Monorepo for Ruvee, a self-hosted password manager. **This is a development build of the first
functional web vault:** account setup with a Recovery Kit check, OPAQUE login, pairing a second
browser, offline unlock, logins and secure notes, and verified sync with explicit conflicts.
Recovery, revocation, password change, the extension and mobile are not built. Nothing has been
independently reviewed: use synthetic data only and never store real credentials. Current state,
commands and gaps: [docs/planning/status.md](docs/planning/status.md). Open security architecture decisions are tracked in
[docs/architecture/open-decisions.md](docs/architecture/open-decisions.md).

The Phase 0 security architecture is **proposed, not approved, and not independently reviewed**.
Start with [docs/architecture/system-overview.md](docs/architecture/system-overview.md). The
product specification is [docs/planning/master-engineering-prompt.md](docs/planning/master-engineering-prompt.md),
and the next steps are in [docs/planning/implementation-roadmap.md](docs/planning/implementation-roadmap.md).
A self-review of that architecture, with a library compatibility spike, is in
[docs/security/architecture-validation.md](docs/security/architecture-validation.md). It is not an
independent audit.

## What is here

| Path                      | Contents                                                                                                                                                                                           |
| ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/api`                | NestJS API: OPAQUE login, cookie and token sessions, sync, pairing, recovery, devices, key rotations, security events; Prisma/PostgreSQL                                                           |
| `apps/web`                | Next.js web vault (static export with a hash-based CSP): setup, items, sync, pairing, recovery, devices, security, activity. A separate test-only export (`out-diagnostics/`) holds the CSP probes |
| `apps/extension`          | Chromium MV3 extension, development build: pairing, unlock and exact-origin manual fill ([README](apps/extension/README.md))                                                                       |
| `deploy/Caddyfile`        | Production headers for `apps/web/out` and a same-origin `/api` proxy. Caddy is not required for local checks                                                                                       |
| `packages/contracts`      | Zod schemas for every implemented endpoint, shared by server and clients; `openapi.json` is generated from them                                                                                    |
| `packages/crypto`         | Ruvee's client-side format over libsodium.js: keys, wraps, envelopes, records, manifests, Recovery Key and pairing. Development only, not reviewed                                                 |
| `packages/vault`          | The vault engine shared by the web worker and the extension's service worker                                                                                                                       |
| `packages/eslint-config`  | Shared ESLint flat configs (`base`, `node`, `next`)                                                                                                                                                |
| `tsconfig.base.json`      | Shared strict TypeScript settings                                                                                                                                                                  |
| `docker-compose.yml`      | Local PostgreSQL 18 with a persistent volume and health check                                                                                                                                      |
| `docs/`                   | Architecture, security specifications, ADRs and planning (Phase 0, proposed)                                                                                                                       |
| `spikes/`                 | Disposable compatibility experiments; not workspace packages, synthetic data only                                                                                                                  |
| `tools/crypto-validation` | Primitive validation harness (P2-01) for the candidate crypto libraries; own lockfile, synthetic data only, not Ruvee's format ([README](tools/crypto-validation/README.md))                       |

## Requirements

- Node.js 24 (`.nvmrc`)
- pnpm 12 (`corepack enable` picks up the version from `package.json`)
- Docker, for the local database

## Local setup

```sh
cp .env.example .env      # local placeholders only; edit if you like
pnpm install
pnpm db:up                # starts PostgreSQL on 127.0.0.1:5433 and waits until healthy
pnpm dev                  # API on http://127.0.0.1:4000, web on http://127.0.0.1:3100
```

PostgreSQL is published on loopback port 5433 (not 5432) to avoid clashing with a locally
installed server. Change `POSTGRES_PORT` and `DATABASE_URL` together if you need another port.

### Inspecting it

- Web home page: <http://127.0.0.1:3100/>
- Interface preview (development only): <http://127.0.0.1:3100/preview>
- API liveness: `curl -i http://127.0.0.1:4000/health/live`
- API readiness: `curl -i http://127.0.0.1:4000/health/ready`. Returns `503` with
  `{"status":"unavailable","checks":{"database":"down"}}` while PostgreSQL is stopped
  (`docker compose stop postgres`).

Stop the database with `pnpm db:down`. Data persists in the `ruvee_postgres-data` volume; remove
it with `docker compose down -v`.

## The interface preview

`/preview` renders the vault shell from the supplied design with **synthetic** data:

- Fixtures live in `apps/web/src/preview/fixtures.ts`. All names are fictional, domains use the
  reserved `.example` TLD, and concealed fields hold only a mask. No fixture contains a password,
  card number or security code.
- Everything stays in memory. Nothing is sent to the API, written to storage or copied to the
  clipboard.
- Navigation, vault switching, search, category chips and tag filters work. Actions for features
  that are not built (add, edit, favorite, trash, reveal, copy, security, generator, settings,
  lock, sync) are visibly marked unavailable and do nothing.
- The route is a `page.dev.tsx` file. `next.config.ts` registers the `dev.tsx` extension only
  outside production, so `next build` never includes it. `pnpm --filter @ruvee/web build` then runs
  `scripts/assert-preview-excluded.mjs`, which fails if the route or the fixture marker appears
  in the build output.

Preview interactions are a design aid. They are not an implementation of vault features.

## Checks

```sh
pnpm format:check
pnpm lint
pnpm typecheck
pnpm test                 # unit and HTTP-level tests (no database needed)
pnpm test:integration     # API against a real PostgreSQL; needs DATABASE_URL (pnpm db:up)
pnpm build
pnpm test:e2e             # Playwright, desktop and mobile viewports, including an axe scan (`next dev`)
pnpm --filter @ruvee/web test:headers          # export headers and CSP in three engines (needs a prior web build; builds the diagnostics export)
pnpm --filter @ruvee/contracts openapi:write   # regenerate openapi.json after changing a contract
pnpm --filter @ruvee/crypto test:browsers      # crypto checks in Chromium, Firefox and WebKit, page and worker
pnpm --filter @ruvee/crypto vectors:write      # regenerate the provisional protocol vectors after a format change
```

The browser checks need Playwright's engines once
(`pnpm --filter @ruvee/crypto exec playwright-core install chromium firefox webkit`).

`pnpm test:integration` reads `DATABASE_URL` from the environment, e.g.
`set -a; . ./.env; set +a; pnpm test:integration` (open a new shell afterwards so
`NODE_ENV=development` does not leak into `next build`).
The restore tests (`restore*.int-spec.ts`) also run `pg_dump` and `pg_restore`, which must have
the server's major version (18). If the host's client is older, run them inside the database
container: `RUVEE_PG_TOOLS_PREFIX='["docker","exec","-i","-e","PGPASSWORD","<container>"]'
RUVEE_PG_TOOLS_HOST=127.0.0.1:5432` (the address as seen inside the container).

For end-to-end tests, either install Playwright's browser once
(`pnpm --filter @ruvee/web exec playwright install chromium`) or reuse a local Chrome with
`PLAYWRIGHT_CHANNEL=chrome pnpm test:e2e`.

The header tests serve the static export on `127.0.0.1:3101` (not the `next dev` port). They do
not start or stop the development server. After `pnpm --filter @ruvee/web build`,
`pnpm --filter @ruvee/web serve:export` is the local stand-in for Caddy.

CI (`.github/workflows/ci.yml`) runs all of the above on pushes and pull requests, with
PostgreSQL as a service container.

## API configuration

Validated at startup by `apps/api/src/config/env.ts`. Invalid values stop the process with a
message naming the variable but never printing its value.

| Variable                   | Default     | Notes                                                                                                 |
| -------------------------- | ----------- | ----------------------------------------------------------------------------------------------------- |
| `DATABASE_URL`             | (required)  | `postgres://` or `postgresql://` URL                                                                  |
| `NODE_ENV`                 | development | `development`, `test` or `production`                                                                 |
| `API_HOST`                 | 127.0.0.1   | Bind address                                                                                          |
| `API_PORT`                 | 4000        | 1–65535                                                                                               |
| `LOG_LEVEL`                | info        | pino level, or `silent`                                                                               |
| `READINESS_DB_TIMEOUT_MS`  | 2000        | Upper bound for the readiness database check                                                          |
| `OPAQUE_SERVER_SETUP_FILE` | (required)  | OPAQUE server setup, created by `ruvee-admin opaque-setup`; mode 0600 in production                   |
| `PUBLIC_ORIGIN`            | (required)  | Origin of the web app and API; state-changing requests must send it as `Origin`                       |
| `SESSION_COOKIE_SECURE`    | true        | `false` only for loopback HTTP development (cookie `ruvee_session` instead of `__Host-ruvee_session`) |
| `TRUSTED_PROXY_ADDRESS`    | (unset)     | Reverse proxy whose `X-Forwarded-For` is trusted for the client IP                                    |

The API reads `.env` from `apps/api` or the repository root.

## Design reference

The design export (`ruvee password manager.html`) is a large self-contained bundle and is kept
out of version control (see `.gitignore`).
