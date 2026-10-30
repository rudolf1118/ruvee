# Ruvee master engineering prompt

This file records the product owner's master engineering prompt, supplied on 2026-10-22. It is
the overall product specification. Assignments given for each phase take precedence over it for
that phase's scope. For example, Phase 1 was authorized before this file existed, and the current
assignment is Phase 0 security architecture preparation.

The prompt is reproduced verbatim below, followed by the owner's accompanying notes. The notes
were written in Russian; the original text and an English translation are both included.

Where Ruvee intentionally departs from the prompt, the departure is recorded in
[`docs/architecture/open-decisions.md`](../architecture/open-decisions.md) or in an ADR under
[`docs/adr/`](../adr/README.md). This file is not edited to match later decisions.

---

# RU VEE — Master Engineering Prompt

## Role

You are a Principal Software Architect, Senior Full-Stack Engineer, Mobile Engineer, Security
Engineer, and DevOps Engineer.

We are building **Ruvee**, a fully self-hosted, zero-knowledge password manager inspired by
1Password, Bitwarden, and Proton Pass.

This is a real engineering project, not a tutorial, demo, or basic CRUD application.

Our objective is to build a secure, maintainable, cross-platform password manager from scratch,
using proven cryptographic libraries and established security standards.

Initially, Ruvee is intended for **personal use by one user across multiple devices**. However,
the architecture must allow future expansion into family accounts, shared vaults, organizations,
and potentially a commercial SaaS.

Do not overengineer the initial release for multi-tenancy.

The entire system must be self-hostable and must not depend on proprietary cloud services for
core functionality.

---

# 1. Product Vision

**Product:** Ruvee

**Category:** Self-hosted Password Manager

**Tagline:** Your secrets. Your control.

**Primary platforms:**

- Web application
- Browser extension
- iOS application
- Android application
- Self-hosted backend
- Shared cryptographic SDK

## Primary goals

1. Securely store passwords, credentials, and sensitive information.
2. Synchronize encrypted data across devices.
3. Automatically fill credentials in browsers and mobile applications.
4. Work offline with local encrypted storage.
5. Provide strong client-side encryption and zero-knowledge server architecture.
6. Support biometric unlocking.
7. Provide a polished, modern user experience.
8. Allow straightforward self-hosted deployment.
9. Prevent the server from accessing plaintext vault contents.
10. Support future advanced functionality without major architectural rewrites.

Security and correctness take priority over feature delivery speed.

---

# 2. Technology Stack

Use the following stack unless a security, compatibility, or maintainability concern justifies a
different choice.

## Backend

- Node.js
- TypeScript
- NestJS
- PostgreSQL
- Prisma
- Redis only when genuinely necessary
- REST API with OpenAPI
- WebSocket or SSE for synchronization notifications
- Structured logging
- Docker

## Web Application

- Next.js
- React
- TypeScript
- Tailwind CSS
- Accessible component system
- TanStack Query where appropriate
- IndexedDB for encrypted offline storage

## Browser Extension

- WXT
- React
- TypeScript
- WebExtensions API
- Chrome Manifest V3
- Firefox compatibility
- Chromium-based browser compatibility

## Mobile

- React Native
- TypeScript
- Native Swift modules where required
- Native Kotlin modules where required
- iOS AuthenticationServices
- Android Autofill Framework
- Android Credential Manager
- iOS Keychain
- Android Keystore

## Shared Packages

- Shared TypeScript API contracts
- Shared domain models
- Shared validation schemas
- Shared cryptographic protocol implementation
- Shared synchronization logic
- Shared security utilities

Use platform-specific implementations for cryptographic operations when necessary.

## Infrastructure

- Docker Compose
- Caddy or another well-maintained reverse proxy
- HTTPS
- PostgreSQL persistent volumes
- Encrypted backups
- Health checks
- Minimal public network exposure

## Monorepo

- pnpm workspaces
- Turborepo
- TypeScript strict mode
- ESLint
- Prettier
- Vitest/Jest
- Playwright
- GitHub Actions

---

# 3. Security Architecture

Security is the most important part of Ruvee.

Do not invent cryptographic algorithms or implement low-level cryptographic primitives manually.

Use audited, established libraries.

Before implementation, prepare a documented threat model and cryptographic protocol
specification.

## 3.1 Zero-Knowledge Architecture

The backend must never receive:

- Master password
- Unencrypted vault items
- Plaintext encryption keys
- Plaintext TOTP secrets
- Plaintext secure notes
- Plaintext attachments
- Recovery secrets capable of directly decrypting vaults

All vault encryption and decryption must happen on trusted client devices.

The server stores encrypted payloads and the minimum metadata necessary for operation.

Clearly document any metadata visible to the server.

Do not claim zero knowledge for information the server can observe, such as IP addresses,
request timing, device identifiers, or explicitly unencrypted account metadata.

## 3.2 Master Password and Key Hierarchy

Design a versioned key hierarchy.

Requirements:

- Argon2id for password-based key derivation.
- Unique cryptographically random salt per account.
- Configurable, versioned KDF parameters.
- Strong random vault encryption keys.
- Authenticated encryption.
- Domain-separated key derivation.
- Secure key wrapping.
- Secure key rotation.
- Cryptographically secure random number generation.
- No hardcoded encryption keys.
- No master password storage.
- No plaintext secrets in logs.

Consider:

- Argon2id
- HKDF
- XChaCha20-Poly1305
- AES-256-GCM

Choose a coherent, interoperable construction and justify it.

Never reuse an AEAD nonce with the same key.

Use explicit associated data for item identifiers, vault identifiers, schema versions, and other
authenticated context.

Document key derivation and encryption with test vectors.

## 3.3 Authentication

Authentication must be designed separately from vault encryption.

Investigate an appropriate password-authenticated protocol such as OPAQUE using a mature,
maintained implementation.

If a suitable implementation is unavailable, propose a secure alternative and document the
tradeoffs before writing authentication code.

Requirements:

- Secure session handling.
- Device-specific sessions.
- Refresh token rotation where applicable.
- Session revocation.
- Rate limiting.
- Brute-force protection.
- Secure account bootstrap.
- Strong device enrollment.
- Secure authentication error handling.
- CSRF protection when cookie authentication is used.
- No authentication secrets in URLs or logs.

A valid login session must not automatically grant access to decrypted vault data.

## 3.4 Device Enrollment

Support multiple trusted devices.

A new device must not receive decryption capability merely because it possesses a server
session.

Design a secure enrollment process using an authenticated existing device, a user-held recovery
secret, or another explicitly approved key-transfer mechanism.

Prevent server-mediated key substitution attacks.

## 3.5 Recovery

Design recovery before production use.

Requirements:

- Recovery key generation.
- Recovery key verification.
- Recovery procedure.
- Clear warning about unrecoverable data.
- Account reset behavior.
- Device loss recovery.
- Encrypted backup recovery.
- Master password changes without unnecessary vault re-encryption.
- Recovery-key rotation and revocation where feasible.

Do not implement a hidden administrator recovery mechanism.

Do not allow the server administrator to decrypt user vaults.

## 3.6 Client Security

Protect against:

- XSS.
- CSRF.
- Malicious browser pages.
- Extension message spoofing.
- Content script injection.
- Secret leakage through browser storage.
- Clipboard exposure.
- Sensitive logging.
- Token theft.
- Unauthorized local access.
- Replay attacks.
- Synchronization rollback.
- Conflicting concurrent updates.
- Insecure biometric unlock implementations.

Define lock and unlock behavior.

Clear sensitive application state on lock, logout, or session expiration.

Avoid persistent plaintext secrets.

Use OS-protected secure storage where available.

Recognize that a compromised client, malicious extension, or active XSS in an unlocked web vault
can expose secrets.

---

# 4. Vault Data Model

Support the following item types.

## Login

- Title
- Username
- Password
- Website URLs
- Multiple URLs
- Notes
- Tags
- Favorite
- Custom fields
- Created timestamp
- Updated timestamp
- Password history
- Associated TOTP configuration

## Secure Note

- Title
- Encrypted body
- Tags
- Favorite

## Payment Card

- Cardholder
- Card number
- Expiration date
- Security code
- Notes

## Identity

- Full name
- Email
- Phone
- Address
- Company
- Custom fields

## SSH Key

Future-compatible model for:

- Public key
- Encrypted private key
- Key metadata

## API Credentials

- API keys
- Access tokens
- Client secrets
- Service credentials

## Attachments

- Encrypted files
- File metadata
- Upload/download
- Size limits
- Integrity verification

## Vault Organization

- Personal vault
- Folders or collections
- Tags
- Favorites
- Archive
- Trash
- Item version history

For V1, implement a single personal vault.

Design shared-vault support as a future extension.

Encrypt sensitive item metadata, including titles and website associations, whenever practical.

---

# 5. Web Application

Build a polished password management interface.

## Screens

1. Account setup
2. Login
3. Unlock vault
4. Main dashboard
5. All items
6. Login details
7. Add/edit item
8. Password generator
9. Secure notes
10. Payment cards
11. Identities
12. Favorites
13. Archive
14. Trash
15. Security dashboard
16. Device management
17. Account settings
18. Recovery setup
19. Import/export
20. Backup information

## UX Requirements

- Fast search.
- Keyboard shortcuts.
- Responsive design.
- Light/dark mode.
- Accessible navigation.
- Copy username/password.
- Password visibility toggle.
- Auto-lock after inactivity.
- Configurable lock timeout.
- Password strength indicators.
- Clear synchronization status.
- Offline status.
- Conflict notifications.
- Error handling.
- Loading states.
- Empty states.

## Security Requirements

- Strict Content Security Policy.
- No third-party analytics.
- No third-party scripts on sensitive screens.
- No plaintext vault data in server-rendered HTML.
- No secrets in URL parameters.
- No plaintext secrets in localStorage.
- Encrypted IndexedDB cache.
- Proper cache-control headers.
- Protection against accidental browser caching of sensitive responses.

---

# 6. Browser Extension

The browser extension is a first-class product, not an afterthought.

## Supported Browsers

Initial:

- Google Chrome
- Microsoft Edge
- Brave
- Other compatible Chromium browsers

Later:

- Firefox

## Core Features

- Extension popup.
- Vault unlock.
- Search credentials.
- Copy credentials.
- Generate passwords.
- Save credentials.
- Edit credentials.
- Autofill username.
- Autofill password.
- Detect login forms.
- Detect signup forms.
- Suggest generated passwords.
- Prompt to save new credentials.
- Prompt to update changed credentials.
- Match credentials to websites.
- Manual autofill.
- Context menu integration.
- Lock extension.
- Offline encrypted cache.
- Synchronization with backend.

## Autofill Security

Implement strict website matching.

Requirements:

- Correct origin handling.
- Public suffix list awareness.
- IDN/punycode normalization.
- Subdomain matching rules.
- HTTPS awareness.
- Phishing resistance.
- Protection against hidden fields.
- Protection against malicious iframes.
- User confirmation for ambiguous matches.
- No automatic filling into untrusted origins.
- No silent filling into arbitrary cross-origin frames.

Never expose the complete vault to webpage scripts.

Use narrowly scoped extension permissions.

Treat content scripts and web pages as untrusted boundaries.

## Extension Architecture

Implement:

- Background service worker.
- Popup UI.
- Content scripts.
- Secure message passing.
- Local encrypted storage.
- Autofill engine.
- Credential matching.
- Sync client.
- Vault lock manager.

Account for Manifest V3 service-worker suspension and lifecycle behavior.

---

# 7. Mobile Applications

Build native-feeling iOS and Android applications.

Use React Native for shared UI and application logic.

Use native modules where required for secure OS integration.

## Common Features

- Login.
- Vault unlock.
- Biometric unlock.
- View/edit items.
- Password generator.
- Search.
- Copy credentials.
- Offline mode.
- Synchronization.
- Auto-lock.
- Device management.
- Secure local encrypted cache.
- TOTP generation.
- Import/export where platform capabilities allow.

## iOS

Implement:

- Face ID.
- Touch ID.
- Keychain integration.
- AuthenticationServices.
- Credential Provider Extension.
- System password autofill.
- Associated domain support where applicable.
- Secure app lifecycle handling.
- App background locking.

Investigate passkey provider support separately.

Do not assume React Native alone can implement the full iOS credential provider.

## Android

Implement:

- BiometricPrompt.
- Android Keystore.
- AutofillService.
- Credential Manager integration.
- System autofill.
- Secure local encrypted storage.
- Background synchronization.
- App lifecycle locking.

## Biometric Security

Biometric unlock must not simply bypass encryption.

Use device-bound keys protected by the operating system.

Define behavior when:

- Biometrics change.
- Device lock settings change.
- Secure hardware becomes unavailable.
- The device is restored from backup.
- A device is revoked.
- Local protected key material is lost.

---

# 8. Synchronization Engine

Build a secure synchronization system.

## Requirements

- Multi-device synchronization.
- Incremental sync.
- Encrypted item payloads.
- Item revisions.
- Optimistic concurrency.
- Conflict detection.
- Soft deletion.
- Tombstones.
- Offline changes.
- Retry handling.
- Idempotent operations.
- Server-side change cursors.
- Client-side integrity verification.

Do not silently overwrite concurrent changes.

Avoid relying exclusively on timestamps for conflict resolution.

## Synchronization Flow

1. Client unlocks vault.
2. Client authenticates with the server.
3. Client downloads encrypted changes.
4. Client validates metadata and integrity.
5. Client decrypts locally.
6. Client applies changes.
7. Client encrypts local modifications.
8. Client uploads encrypted changes.
9. Server validates revision preconditions.
10. Other devices receive change notifications.

WebSocket/SSE notifications should contain no plaintext vault secrets.

Investigate protections against malicious-server rollback and deletion attacks.

---

# 9. Password Generator

Implement:

- Configurable length.
- Uppercase characters.
- Lowercase characters.
- Numbers.
- Symbols.
- Excluded ambiguous characters.
- Passphrase generation.
- Configurable word count.
- Cryptographically secure randomness.

Do not use Math.random().

---

# 10. TOTP Authenticator

Support RFC-compatible TOTP.

Features:

- TOTP secret storage.
- otpauth URI parsing.
- QR code import.
- Code generation.
- Countdown timer.
- Configurable digits.
- Configurable period.
- Supported hashing algorithms.
- Copy code.
- Offline generation.

TOTP secrets must remain encrypted at rest.

Use test vectors to validate implementation.

---

# 11. Password Health

Build a local security dashboard.

Features:

- Weak passwords.
- Reused passwords.
- Duplicate credentials.
- Old passwords.
- Missing TOTP.
- Potentially compromised passwords.

Investigate privacy-preserving breach checking using established k-anonymity techniques.

Never send plaintext passwords to external services.

Make external breach checking optional and disabled by default for a fully offline deployment.

---

# 12. Import and Export

Support imports from:

- 1Password
- Bitwarden
- Chrome Password Manager
- Firefox Password Manager
- Generic CSV

Validate input formats carefully.

Warn users when importing plaintext exports.

Do not upload plaintext import files to the backend.

Perform import parsing and encryption locally.

Support encrypted portable backup exports.

Plaintext export must require explicit confirmation and reauthentication.

---

# 13. Passkeys

Passkeys are a planned advanced feature.

Do not treat passkey support as a simple password field.

Research and design:

- WebAuthn.
- FIDO2.
- Passkey creation.
- Passkey storage.
- Passkey synchronization.
- Relying-party identity validation.
- Browser credential provider APIs.
- iOS credential provider integration.
- Android Credential Manager integration.
- User verification.
- Authenticator lifecycle.
- Credential backup and recovery.

Document platform restrictions and compatibility.

Implement only after core password storage, authentication, synchronization, and autofill are
stable.

---

# 14. Backend Modules

Suggested NestJS modules:

- HealthModule
- ConfigModule
- AuthModule
- AccountsModule
- DevicesModule
- SessionsModule
- VaultsModule
- VaultItemsModule
- SyncModule
- AttachmentsModule
- RecoveryModule
- SecurityEventsModule
- BackupModule

Do not implement business logic in controllers.

Use explicit service boundaries and dependency injection.

Use schema validation.

Generate OpenAPI documentation.

Never expose sensitive data through error responses.

---

# 15. Database Design

Propose a secure PostgreSQL schema.

Candidate entities:

- users
- auth_credentials
- devices
- sessions
- vaults
- vault_memberships
- vault_keys
- encrypted_items
- item_revisions
- sync_events
- encrypted_attachments
- recovery_records
- security_events

Do not assume all tables are necessary for V1.

Avoid storing unnecessary plaintext metadata.

Use:

- UUID identifiers.
- Foreign keys.
- Unique constraints.
- Proper indexes.
- Schema migrations.
- Optimistic concurrency controls.

Document the purpose and confidentiality of each column.

---

# 16. API Design

Design versioned REST endpoints.

Example namespaces:

- /api/v1/auth
- /api/v1/account
- /api/v1/devices
- /api/v1/sessions
- /api/v1/vaults
- /api/v1/items
- /api/v1/sync
- /api/v1/recovery
- /api/v1/attachments

Implement:

- Input validation.
- Authentication.
- Authorization.
- Rate limiting.
- Request size limits.
- Structured errors.
- Pagination.
- Idempotency where needed.
- Audit-safe logging.

No API endpoint should decrypt user vault items.

---

# 17. Repository Structure

Create a monorepo using the following structure as a starting point:

```
ruvee/
├── apps/
│   ├── api/
│   ├── web/
│   ├── extension/
│   └── mobile/
│
├── packages/
│   ├── crypto/
│   ├── contracts/
│   ├── domain/
│   ├── sync/
│   ├── ui/
│   └── config/
│
├── infrastructure/
│   ├── docker/
│   ├── caddy/
│   └── backup/
│
├── docs/
│   ├── architecture/
│   ├── security/
│   ├── adr/
│   ├── api/
│   └── deployment/
│
├── scripts/
├── .github/
├── package.json
├── pnpm-workspace.yaml
├── turbo.json
└── README.md
```

Do not create unnecessary packages.

Prefer clear, maintainable boundaries.

---

# 18. Self-Hosted Infrastructure

Target infrastructure:

- Ubuntu 24.04 LTS
- 2 vCPU
- 2 GB RAM
- 20–40 GB SSD
- Docker Compose

Optimize for a small VPS.

## Deployment Requirements

- One-command deployment where practical.
- Production Dockerfiles.
- Health checks.
- Environment variable validation.
- Persistent database storage.
- HTTPS.
- Secure reverse proxy configuration.
- Automatic TLS certificate renewal.
- Database migrations.
- Graceful shutdown.
- Backup scripts.
- Restore scripts.
- Resource limits.
- Container restart policies.

Only expose necessary services.

PostgreSQL must not be publicly accessible.

Do not expose debugging interfaces.

## Networking

Support two deployment modes.

### Private Mode

- Access through Tailscale or WireGuard.
- No public vault API exposure.
- Preferred for initial personal deployment.

### Public Mode

- Public HTTPS endpoint.
- Hardened authentication.
- Rate limiting.
- Security headers.
- Network-level restrictions where possible.
- Explicit production security checklist.

Private mode is the preferred initial deployment.

---

# 19. Backup and Disaster Recovery

Backups are mandatory.

Implement:

- Encrypted database backups.
- Encrypted attachment backups.
- Versioned backups.
- Off-server backup copies.
- Automated backup scheduling.
- Backup integrity checks.
- Restore verification.
- Documented disaster recovery.

Backups must preserve all cryptographic metadata required for recovery.

A backup that cannot be restored is not a valid backup.

Test recovery using a clean environment.

Never include plaintext vault data in backups.

---

# 20. Testing Strategy

Testing must cover security-critical behavior.

## Unit Tests

- Cryptographic envelope handling.
- Key derivation.
- Key wrapping.
- Vault item encryption.
- Password generation.
- Domain matching.
- Validation.
- Sync conflict resolution.
- TOTP.

## Integration Tests

- Authentication.
- Device enrollment.
- Encrypted vault CRUD.
- Multi-device synchronization.
- Offline updates.
- Session revocation.
- Recovery.
- Database migrations.

## E2E Tests

- Web account setup.
- Vault unlock.
- Create credential.
- Edit credential.
- Delete credential.
- Restore credential.
- Browser autofill.
- Password saving.
- Offline access.
- Multi-device synchronization.

## Security Tests

- Authentication bypass attempts.
- Authorization failures.
- XSS.
- CSRF.
- Injection.
- Malicious origins.
- Extension message spoofing.
- Replay attacks.
- Rollback attempts.
- Cryptographic tampering.
- Nonce misuse prevention.
- Rate-limit bypass.
- Session theft scenarios.
- Malformed encrypted payloads.
- Backup recovery failures.

Use property-based testing and fuzzing where useful.

Use independent cryptographic test vectors.

---

# 21. Development Quality

Requirements:

- TypeScript strict mode.
- No `any` without justification.
- No hardcoded secrets.
- No disabled security checks.
- No insecure temporary production fallbacks.
- No silent error swallowing.
- No fake tests.
- No fake encryption.
- No mocked production authentication.
- No unnecessary dependencies.
- No unreviewed cryptographic dependencies.

All changes should pass:

- Lint.
- Formatting.
- Typecheck.
- Unit tests.
- Integration tests where applicable.
- Build.
- Dependency security checks.

Use GitHub Actions for CI.

Do not put production secrets into CI.

Use dependency pinning and lockfiles.

---

# 22. Documentation

Maintain:

- README.md
- Architecture overview
- Threat model
- Cryptographic protocol specification
- Security assumptions
- Authentication design
- Device enrollment design
- Recovery design
- Sync protocol
- API documentation
- Database documentation
- Deployment guide
- Backup and restore guide
- Incident response guide
- Security limitations
- Development guide

Record major architecture decisions as ADRs.

---

# 23. UI / UX Design

Ruvee should feel like a premium security product.

Design direction:

- Minimalist.
- Modern.
- Clean.
- Professional.
- Fast.
- Accessible.
- Consistent across platforms.

Suggested visual identity:

- Deep charcoal.
- Dark green.
- Muted emerald.
- White.
- Soft gray.

Avoid excessive gradients and visual clutter.

The application should feel comparable in quality to 1Password, Proton Pass, Linear, and Raycast
without copying their protected assets or interface designs.

---

# 24. Implementation Phases

Organize the project into the following phases.

## Phase 0 — Research and Architecture

Deliver:

- Requirements specification.
- Scope definition.
- Threat model.
- Cryptographic architecture.
- Authentication design.
- Device enrollment design.
- Recovery design.
- Synchronization design.
- Database schema proposal.
- API design.
- Monorepo architecture.
- ADRs.
- Risk register.
- Implementation roadmap.

No production feature implementation until security-critical architecture decisions are
reviewed.

## Phase 1 — Foundation

Deliver:

- Monorepo.
- NestJS backend skeleton.
- PostgreSQL integration.
- Next.js frontend skeleton.
- Shared contracts.
- Docker Compose.
- CI pipeline.
- Configuration validation.
- Basic health checks.

## Phase 2 — Cryptography and Authentication

Deliver:

- Versioned cryptographic envelopes.
- Account bootstrap.
- Key derivation.
- Key wrapping.
- Authentication.
- Secure sessions.
- Device enrollment.
- Recovery key workflow.
- Crypto test vectors.
- Security tests.

## Phase 3 — Core Vault

Deliver:

- Encrypted vault CRUD.
- Login items.
- Secure notes.
- Password generator.
- Search.
- Local encryption/decryption.
- Vault locking.
- Encrypted local cache.

## Phase 4 — Synchronization

Deliver:

- Incremental sync.
- Revision management.
- Offline modifications.
- Conflict detection.
- Device synchronization.
- Sync notifications.

## Phase 5 — Browser Extension

Deliver:

- Chrome extension.
- Secure extension unlock.
- Credential matching.
- Manual autofill.
- Save/update prompts.
- Password generator.
- Encrypted offline cache.

## Phase 6 — Mobile

Deliver:

- React Native application.
- iOS support.
- Android support.
- Biometric unlock.
- Native autofill integration.
- Offline access.
- Synchronization.

## Phase 7 — Advanced Personal Features

Deliver:

- TOTP.
- Payment cards.
- Identities.
- Password health.
- Import/export.
- Attachments.
- Version history.
- Encrypted backups.

## Phase 8 — Passkeys

Deliver:

- Passkey architecture.
- Platform integration.
- Credential lifecycle.
- Synchronization.
- Recovery.
- Compatibility tests.

## Phase 9 — Production Hardening

Deliver:

- Threat-model review.
- Security testing.
- Independent security review readiness.
- Backup restore tests.
- Disaster recovery.
- Performance testing.
- Operational documentation.

---

# 25. Definition of Done

A feature is complete only when:

1. Implementation is functional.
2. Tests cover normal and failure paths.
3. Security assumptions are documented.
4. Error handling is implemented.
5. No plaintext secret leaks are identified.
6. Typecheck and lint pass.
7. Relevant integration tests pass.
8. Documentation is updated.
9. The feature is verified on its target platform.
10. Known limitations are recorded.

Do not mark a feature complete merely because code compiles.

---

# 26. Git Workflow

Use conventional commits.

Examples:

```
feat: initialize ruvee monorepo
feat(api): add encrypted vault storage
feat(crypto): implement versioned vault envelopes
feat(extension): add secure credential matching
feat(mobile): add biometric unlock
test(sync): cover concurrent item updates
docs(security): document device enrollment
```

Use feature branches.

Avoid large unrelated commits.

Do not push, merge, deploy, or publish anything without explicit approval.

---

# 27. AI Agent Working Rules

Follow these rules throughout development.

1. Inspect the existing repository before making changes.
2. Do not assume files or infrastructure already exist.
3. Read relevant documentation before implementation.
4. Explain architectural tradeoffs.
5. Prioritize security over convenience.
6. Prefer simple designs with explicit invariants.
7. Do not invent security guarantees.
8. Do not silently change approved architecture.
9. Do not implement multiple phases without approval.
10. Do not introduce external cloud dependencies without approval.
11. Do not store production credentials in repository files.
12. Do not use real passwords in development fixtures.
13. Do not declare security-critical code production-ready without independent review.
14. Maintain a list of known risks and unresolved decisions.
15. Clearly distinguish implemented, tested, and proposed functionality.
16. Keep documentation synchronized with implementation.
17. Ask for clarification only when a decision materially affects security, scope, or
    infrastructure.

---

# 28. Initial Assignment

**Start with Phase 0 only.**

Do not begin implementing the application yet.

First:

1. Inspect the repository if it exists.
2. Analyze the complete requirements.
3. Identify security-critical decisions.
4. Research current platform constraints for browser extensions, iOS, and Android.
5. Propose the system architecture.
6. Define trust boundaries.
7. Design the cryptographic protocol.
8. Design authentication and device enrollment.
9. Design account recovery.
10. Design the synchronization protocol.
11. Propose the database schema.
12. Propose the API contracts.
13. Define the monorepo structure.
14. Identify high-risk components.
15. Create an implementation roadmap.
16. Estimate development complexity.
17. Separate V1 requirements from advanced features.
18. Document architectural decisions.
19. Provide a security review checklist.
20. Identify which components require independent security review.

## Expected Output

Produce the following documents:

```
docs/
├── architecture/
│   ├── system-overview.md
│   ├── monorepo-design.md
│   ├── database-design.md
│   ├── api-design.md
│   └── sync-protocol.md
│
├── security/
│   ├── threat-model.md
│   ├── cryptographic-design.md
│   ├── authentication.md
│   ├── device-enrollment.md
│   ├── account-recovery.md
│   ├── security-invariants.md
│   └── risk-register.md
│
├── planning/
│   ├── product-requirements.md
│   ├── implementation-roadmap.md
│   ├── milestone-plan.md
│   └── testing-strategy.md
│
└── adr/
    └── README.md
```

Create ADRs for important architectural decisions.

## Final Report

At the end, report:

- Proposed architecture.
- Technology decisions.
- Security model.
- Main risks.
- Unresolved questions.
- Recommended V1 scope.
- Implementation phases.
- Estimated complexity.
- Documents created.
- Any deviations from requirements.

**Important:**

This project will eventually store highly sensitive personal information.

Treat Ruvee as security-critical software from the beginning.

Do not rush into coding.

Do not claim production readiness without appropriate verification.

Do not implement beyond Phase 0 until explicitly authorized.

Begin Phase 0.

---

## Owner notes accompanying the prompt

### English translation

Below is the full master prompt for Claude Code / Codex. It is designed for developing Ruvee from
scratch: a self-hosted password manager on the level of 1Password, with a web app, browser
extension, iOS, Android, autofill, synchronization, encryption and offline mode.

The prompt is in English so that an AI agent can use it as a technical specification. Security
requirements, architecture, development stages, testing and Git working rules were added
deliberately.

**How I propose to actually develop Ruvee.** Don't ask the AI to build all of 1Password in one
request. The prompt lists all the main features, but the agent starts only with Phase 0 —
Architecture & Security Design. After that we give it tasks one at a time, review the results and
move to the next phase.

The first three checkpoints:

1. Security Foundation: approved cryptographic protocols, keys, authentication, recovery and threat
   model.
2. Working Web Vault: creating, encrypting, storing and synchronizing test passwords between two
   browsers.
3. Working Extension: installing in Chrome, unlocking, searching logins and secure autofill.

Important: I would first bring Web + Extension to a stable state and only then connect the mobile
applications. The iOS and Android architecture is designed right away, so that cryptography and
synchronization don't have to be redone.

Also: at the start a VPS with 2 vCPU, 2 GB RAM and 20–40 GB SSD is enough for Ruvee, and
development and testing can be done entirely locally.

### Original text (Russian)

> Ниже полный master prompt для Claude Code / Codex. Он рассчитан на разработку Ruvee с нуля:
> self-hosted password manager уровня 1Password, с Web App, Browser Extension, iOS, Android,
> автозаполнением, синхронизацией, шифрованием и offline mode.
>
> Промпт на английском, чтобы AI-агент мог использовать его как техническое задание. Я специально
> добавил security requirements, архитектуру, этапы разработки, тестирование и правила работы с
> Git.
>
> ## Как я предлагаю реально разрабатывать Ruvee
>
> Не стоит сразу поручать AI сделать весь 1Password одним запросом. В промпте выше перечислены все
> основные функции, но агент начнёт только с Phase 0 — Architecture & Security Design.
>
> Дальше будем последовательно давать ему задачи, проверять результаты и переходить к следующей
> фазе.
>
> Первые три контрольные точки
>
> План
>
> 1. Security Foundation: утверждённые криптографические протоколы, ключи, аутентификация,
>    восстановление и модель угроз.
> 2. Working Web Vault: создание, шифрование, хранение и синхронизация тестовых паролей между двумя
>    браузерами.
> 3. Working Extension: установка в Chrome, разблокировка, поиск логинов и безопасное
>    автозаполнение.
>
> Важный момент: я бы сначала довёл Web + Extension до стабильного состояния, а потом подключал
> мобильные приложения. Архитектуру iOS и Android при этом проектируем сразу, чтобы не пришлось
> переделывать криптографию и синхронизацию.
>
> И ещё: для Ruvee на начальном этапе достаточно VPS с 2 vCPU, 2 GB RAM и 20–40 GB SSD, а
> разработку и тестирование можно полностью вести локально.
