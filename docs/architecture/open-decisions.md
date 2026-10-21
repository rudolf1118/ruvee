# Open architecture decisions

Status as of the Phase 1 foundation milestone. Nothing in this repository implements
authentication, encryption, key management, vault persistence, sync, recovery or device
enrollment. Those features stay blocked until the decisions below are written down and approved.

## Phase 0 inputs that were not available

The repository contained no Phase 0 documentation and no copy of the master engineering prompt
when Phase 1 started. Only the UI design export was supplied. The following documents are
therefore missing and should be produced (or added, if they exist elsewhere) before any
security-sensitive feature work:

| Missing input               | Blocks                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------ |
| Threat model                | Every security feature; logging and retention rules                                  |
| Cryptographic design        | Key derivation, key hierarchy, item encryption format, algorithm and library choices |
| Authentication protocol     | Account creation, login, session model, server-side verifier storage                 |
| Account recovery policy     | Whether any recovery exists (the design says none does)                              |
| Device enrollment and trust | Adding devices, revoking devices, browser extension and mobile pairing               |
| Sync and conflict model     | Local storage, server storage, merge rules, offline behavior                         |
| Vault data model            | Prisma schema for accounts, vaults, items and keys                                   |
| Sharing model               | Multiple vaults such as "Household" in the design                                    |
| Import and export policy    | Accepted formats, readable (unencrypted) export, warnings                            |
| Deployment and hosting      | Production configuration, secrets management, TLS, backups                           |

## Decisions already made in Phase 1 (non-security)

- Monorepo: pnpm workspaces with Turborepo. Node 24, TypeScript 6.0 (strict).
- API: NestJS 12 (ESM), configuration validated with Zod at startup, Prisma 7 with the
  `@prisma/adapter-pg` driver adapter against PostgreSQL 18.
- The Prisma schema intentionally has **no models**.
- Health: `GET /health/live` (process only) and `GET /health/ready` (database reachable, 503 otherwise).
- Logging: pino through `nestjs-pino`, allow-listed request fields only (method, path without query
  string, request id, status). Headers, cookies and bodies are never logged.
- Web: Next.js 16 App Router, React 19, Tailwind CSS 4 with design tokens taken from the design.
- UI preview: development-only route with synthetic, secret-free fixtures (see the README).
- No Redis, no external cloud services.

## Conflicts between the design and the (undecided) architecture

The design is the visual source of truth, but several things it shows depend on decisions that
have not been made. Phase 1 implements the layout and leaves these behaviors unavailable.

1. **Security claims in copy.** The design says items are kept "in an encrypted vault on your
   devices" and shows "Synced · Encrypted". These are claims about an encryption and sync design
   that does not exist yet. The preview shows "Sync not set up" instead.
2. **Local-first storage.** Messages such as "Changes saved on this device" imply local
   persistence plus background sync. Where vault data lives, and how it is protected at rest on
   each platform, is part of the sync decision.
3. **No recovery.** The lock screen says Ruvee "can't reset or recover your master password".
   That is a recovery-policy decision for Phase 0, not a UI detail.
4. **Security findings.** Weak and reused password detection requires access to decrypted
   passwords. Where that runs (client only) and whether breach checks call an external service
   are open questions. The preview omits the Weak/Reused badges and the findings count.
5. **Password generator.** The prototype draws characters with `getRandomValues() % n`, which
   is biased. The real generator needs unbiased sampling and a reviewed word list. Not built.
6. **Clipboard and auto-lock.** Clearing the clipboard after a delay and locking after idle or
   sleep depend on platform capabilities and the session model. Not built.
7. **Readable export and import.** Plaintext export and CSV import need an explicit policy and
   warnings. Not built.
8. **Multiple vaults.** "Personal" and "Household" vaults suggest per-vault keys and possibly
   sharing. The preview treats vaults as labels only.
9. **Onboarding and unlock.** The design's master password creation and unlock screens depend on
   the authentication and key-derivation design. They were not implemented, and no fake login
   was added.

## Recommended order for resolving them

1. Threat model and cryptographic design, reviewed together.
2. Authentication protocol and recovery policy.
3. Vault data model and sync/conflict model; only then the first Prisma models and migrations.
4. Device enrollment, then the browser extension and mobile clients.
