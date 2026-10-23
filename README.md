# Ruvee

Monorepo for Ruvee, a planned password manager. **This is the Phase 1 foundation only.** There is
no working vault, account system, encryption, sync or recovery. Do not use it to store real
credentials. Open security architecture decisions are tracked in
[docs/architecture/open-decisions.md](docs/architecture/open-decisions.md).

The Phase 0 security architecture is **proposed, not approved, and not independently reviewed**.
Start with [docs/architecture/system-overview.md](docs/architecture/system-overview.md). The
product specification is [docs/planning/master-engineering-prompt.md](docs/planning/master-engineering-prompt.md),
and the next steps are in [docs/planning/implementation-roadmap.md](docs/planning/implementation-roadmap.md).
A self-review of that architecture, with a library compatibility spike, is in
[docs/security/architecture-validation.md](docs/security/architecture-validation.md). It is not an
independent audit.

## What is here

| Path                      | Contents                                                                                                                                                                     |
| ------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `apps/api`                | NestJS API: validated config, Prisma/PostgreSQL, health endpoints, logging                                                                                                   |
| `apps/web`                | Next.js web app: design tokens, UI components, vault app shell, dev preview                                                                                                  |
| `packages/contracts`      | Zod schemas for the implemented API (health responses, errors, limits), shared by server and clients; the OpenAPI document `openapi.json` is generated from them             |
| `packages/eslint-config`  | Shared ESLint flat configs (`base`, `node`, `next`)                                                                                                                          |
| `tsconfig.base.json`      | Shared strict TypeScript settings                                                                                                                                            |
| `docker-compose.yml`      | Local PostgreSQL 18 with a persistent volume and health check                                                                                                                |
| `docs/`                   | Architecture, security specifications, ADRs and planning (Phase 0, proposed)                                                                                                 |
| `spikes/`                 | Disposable compatibility experiments; not workspace packages, synthetic data only                                                                                            |
| `tools/crypto-validation` | Primitive validation harness (P2-01) for the candidate crypto libraries; own lockfile, synthetic data only, not Ruvee's format ([README](tools/crypto-validation/README.md)) |

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
pnpm test:e2e             # Playwright, desktop and mobile viewports, including an axe scan
pnpm --filter @ruvee/contracts openapi:write   # regenerate openapi.json after changing a contract
```

`pnpm test:integration` reads `DATABASE_URL` from the environment, e.g.
`set -a; . ./.env; set +a; pnpm test:integration` (open a new shell afterwards so
`NODE_ENV=development` does not leak into `next build`).

For end-to-end tests, either install Playwright's browser once
(`pnpm --filter @ruvee/web exec playwright install chromium`) or reuse a local Chrome with
`PLAYWRIGHT_CHANNEL=chrome pnpm test:e2e`.

CI (`.github/workflows/ci.yml`) runs all of the above on pushes and pull requests, with
PostgreSQL as a service container.

## API configuration

Validated at startup by `apps/api/src/config/env.ts`. Invalid values stop the process with a
message naming the variable but never printing its value.

| Variable                  | Default     | Notes                                        |
| ------------------------- | ----------- | -------------------------------------------- |
| `DATABASE_URL`            | (required)  | `postgres://` or `postgresql://` URL         |
| `NODE_ENV`                | development | `development`, `test` or `production`        |
| `API_HOST`                | 127.0.0.1   | Bind address                                 |
| `API_PORT`                | 4000        | 1–65535                                      |
| `LOG_LEVEL`               | info        | pino level, or `silent`                      |
| `READINESS_DB_TIMEOUT_MS` | 2000        | Upper bound for the readiness database check |

The API reads `.env` from `apps/api` or the repository root.

## Design reference

The design export (`ruvee password manager.html`) is a large self-contained bundle and is kept
out of version control (see `.gitignore`).
