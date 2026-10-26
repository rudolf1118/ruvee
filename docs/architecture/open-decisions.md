# Open architecture decisions

Status as of P2-04 crypto-only (2026-10-24). `packages/crypto` implements the password rule,
`AUK`, the account-key password wrap and the keyset envelope for development
([cryptographic-design.md §10](../security/cryptographic-design.md#10-implementation-status-packagescrypto-p2-03)).
The web static export applies the production headers and loads that package in a worker
([api-design.md](api-design.md#what-p2-04-implemented)). Nothing implements
authentication, vault persistence, sync, recovery or device enrollment. OPAQUE is not present.

The Phase 0 specifications now exist and are all **Proposed**; start from the
[system overview](system-overview.md). They were checked by an
[architecture validation](../security/architecture-validation.md), which is a self-review, not an
independent audit. The decisions below need the owner's review. Each has a recommendation, which
is the agent's proposal and **not** an approval. Security-critical components also need
independent review ([roadmap](../planning/implementation-roadmap.md#independent-review)).

## Decisions

The [architecture validation](../security/architecture-validation.md) replaced the earlier list
of broad approval requests with the tables below. Technical decisions rest on engineering
evidence. Product preferences are the owner's call and need no engineering validation. "Next
task" means the bounded task proposed in the
[roadmap](../planning/implementation-roadmap.md#next-bounded-task): the remaining half of P2-04
(OPAQUE under the CSP, blocked by D-02) or P2-06 if the database design is approved.
Approving a row approves only that row.

### Technical decisions

| ID   | Decision                                 | Recommended option                                                                                                                                                                                      | User-visible consequence                                                                                                      | Supporting evidence                                                                                                                                                                                                                                 | Remaining uncertainty                                                                                                                                                                                          | Blocks next implementation task?                                                                     |
| ---- | ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------- |
| D-25 | Scope of P2-01                           | A primitive validation harness in `tools/crypto-validation/`, outside the pnpm workspace, with exactly pinned libsodium.js and `@noble/*`, run in Node and Playwright in CI. No Ruvee protocol vectors. | None                                                                                                                          | The spike ran the same checks in 6 runtimes ([validation §2.1](../security/architecture-validation.md#21-verified-by-running-code))                                                                                                                 | CI must download Playwright browsers. Safari can't run in CI and is checked by hand.                                                                                                                           | **Approved by the owner (2026-10-22)**; P2-01 [implemented](../../tools/crypto-validation/README.md) |
| D-01 | Primitive library                        | `libsodium-wrappers-sumo` 0.8.4 and `libsodium-sumo` 0.8.4, exactly pinned, for XChaCha20-Poly1305, Argon2id, BLAKE2b, `crypto_kdf` and sealed boxes                                                    | None directly. The web CSP and the extension manifest must allow `'wasm-unsafe-eval'`.                                        | 22 of 22 checks in Node, 4 browser engines and the MV3 service worker ([validation §6](../security/architecture-validation.md#6-library-validation)); the P2-01 [harness](../../tools/crypto-validation/README.md) in Node and 3 Playwright engines | `react-native-libsodium` untested. Audits are dated (R-02). V-15: an unreleased upstream fix for stale memory from `crypto_kdf` with invalid lengths; Ruvee must check lengths itself; `packages/crypto` does. | **Approved by the owner for development (2026-10-24)**; used by P2-03                                |
| D-20 | Password input rule                      | Reject strings that are not well-formed, then NFC, then 1 to 4,096 UTF-8 bytes. The same string goes to OPAQUE and Argon2id.                                                                            | A password containing an unpaired surrogate is refused. Normal typing cannot produce one.                                     | Spike LS-09c and OP-08: lone surrogates collide with U+FFFD in both libraries                                                                                                                                                                       | NFC on engines with different Unicode versions was not tested.                                                                                                                                                 | **Approved by the owner for development (2026-10-24)**; implemented in P2-03                         |
| D-04 | Two-secret key derivation and enrollment | Keep it: a new device needs pairing or the Recovery Key, never the password alone.                                                                                                                      | A password alone can't set up a new device.                                                                                   | [Validation §3](../security/architecture-validation.md#3-two-secret-design-and-authentication), with the claim narrowed (V-01)                                                                                                                      | None technical. The cost is user experience. The approval does not cover the pairing protocol (D-21).                                                                                                          | **Approved by the owner for development (2026-10-24)**; the derivation is implemented in P2-03       |
| D-03 | Argon2id profile 1                       | 64 MiB, t = 3, p = 1, **provisional**. The owner names the reference devices (D-26), and P2-02 measures them.                                                                                           | Unlock waits for one derivation: about 80 ms on the test machine, unknown on phones.                                          | [Validation §7](../security/architecture-validation.md#7-key-derivation-measurements) and the [P2-02 local benchmark](../security/kdf-calibration.md) (median 82 to 98 ms), one machine only                                                        | Phones, older laptops, Safari. The MV3 service worker is about 3.7 times slower. The 128 MiB budget needs a definition: Node's whole-process peak for profile 1 is 136 MiB.                                    | No (P2-02 produces its evidence)                                                                     |
| D-02 | OPAQUE library and configuration         | `@serenity-kit/opaque` 1.1.0, memory-constrained preset, username as client identity, **no server identity, no key pinning**, login state consumed once                                                 | None. If the server setup file is lost, logging in again needs the Recovery Kit.                                              | Spike OP-01 to OP-08; RFC 9807 §4 and §10.3; V-02 to V-04                                                                                                                                                                                           | No published vectors for this KSF. Audits predate the version. No mobile binding (D-05).                                                                                                                       | **Approved by the owner for development (2026-10-25)**; used by P2-08 and P2-09                      |
| D-24 | When `SK` is rotated                     | On revoking a device as lost, and offered at the end of recovery after device loss                                                                                                                      | One more confirmation in those two flows. Other devices pick up the new keyset on their next sync.                            | [Validation §3.4](../security/architecture-validation.md#34-the-narrowed-claim); R-17                                                                                                                                                               | None found                                                                                                                                                                                                     | **Approved by the owner for development (2026-10-25)**                                               |
| D-27 | Unlocked state in the MV3 extension      | Keep `AK` in `chrome.storage.session` (memory only, trusted contexts, cleared on lock and browser exit); read INV-16 as "never written to persistent storage"                                           | Without it the extension asks for the master password after any pause of about 30 seconds                                     | [extension-design.md §3](../security/extension-design.md#3-unlocked-state-across-service-worker-restarts-d-27)                                                                                                                                      | Chrome's handling of `storage.session` memory under swap or crash dumps is not documented                                                                                                                      | **Approved by the owner for development (2026-10-25)**                                               |
| D-28 | What restoring a server backup undoes    | End every session, delete open pairings, record `server_restored`, and require a one-time device review ([backup-restore.md §3.4](backup-restore.md#34-what-a-restore-must-undo-d-28-blocking-m1))      | After a restore every device signs in again; devices removed after the backup date are listed again and must be removed again | `apps/api/test/backup-restore.int-spec.ts`: a restored copy brings back a removed device and its session                                                                                                                                            | Whether the review should also force `SK` rotation                                                                                                                                                             | No (blocks M1, server backup)                                                                        |
| D-29 | Encrypting server dump files at rest     | The operator guide requires encrypted storage kept apart from the OPAQUE setup file; Ruvee does not encrypt dumps in M1                                                                                 | You choose and protect the storage; a dump stored with the setup file allows offline password guessing (V-01)                 | [backup-restore.md §3.2](backup-restore.md#32-secrets-needed-to-restore-and-who-holds-them)                                                                                                                                                         | None                                                                                                                                                                                                           | No (not blocking)                                                                                    |
| D-21 | Pairing protocol                         | Keep the 128-bit code with the rules in [validation §4](../security/architecture-validation.md#4-pairing-as-a-complete-protocol). Independent review before real data. No shorter code.                 | A 29-character code or a QR scan to add a device                                                                              | Analysis only; nothing was implemented                                                                                                                                                                                                              | A custom composition with no independent review. No usable PAKE implementation exists for a short code.                                                                                                        | **Approved by the owner for development (2026-10-25)**; independent review still required (D-19)     |
| D-22 | Recovery authentication                  | Keep `RAK` for V1, with the notice raised at recovery start. Revisit a second OPAQUE registration keyed by `RK` before any public-mode release.                                                         | None either way                                                                                                               | [Validation §5.5](../security/architecture-validation.md#55-rak-as-a-bearer-credential); R-08                                                                                                                                                       | The second-OPAQUE design is not written.                                                                                                                                                                       | **Approved by the owner for development (2026-10-25)**: keep `RAK`; revisit before public mode       |
| D-19 | Independent review                       | Review the crypto package, OPAQUE integration, pairing and recovery after Phase 2, before any real data                                                                                                 | None                                                                                                                          | R-15. This validation is a self-review.                                                                                                                                                                                                             | Who reviews, and when                                                                                                                                                                                          | No (blocks real data)                                                                                |

### Product preferences and risk acceptance

These need no engineering validation. Each has a recommendation, which is only a proposal.

| ID   | Decision                                          | Recommended option                                                                                                                           | User-visible consequence                                                                  | Blocks                                |
| ---- | ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------- | ------------------------------------- |
| D-17 | Account identifier                                | A username, not an email address: NFC, lowercase, 1 to 64 characters                                                                         | The server sees it. Nothing is sent by email.                                             | Approved for development (2026-10-25) |
| D-09 | Master-password policy                            | At least 12 characters after NFC, at most 4,096 bytes, reject common passwords, show a strength estimate, no composition rules or expiry     | What the setup screen accepts                                                             | Approved for development (2026-10-25) |
| D-06 | Recovery Kit experience                           | Kit verification required at setup, rotation required after use, the wording in account-recovery.md §8                                       | Setup can't finish without typing the key back                                            | Approved for development (2026-10-25) |
| D-08 | Session lifetimes                                 | Web: 12 h idle, 14 days absolute. Tokens: 10-minute access; refresh 30 days idle, 90 days absolute. Step-up 5 minutes.                       | How often the user logs in. Longer sessions widen what a stolen device gives away (R-18). | Approved for development (2026-10-25) |
| D-23 | Does locking also end the server session?         | No. Locking is local, so unlock stays offline-capable and costs one derivation. Accept R-18, mitigated by revocation.                        | With "yes", every unlock while online also logs in, which costs a second derivation.      | Approved for development (2026-10-25) |
| D-10 | Auto-lock                                         | Default 15 minutes, configurable from 1 minute to 8 hours. No "never" option on web.                                                         | How often the user types the password                                                     | Approved for development (2026-10-25) |
| D-07 | Web-client trust                                  | Accept for private mode, and say so in the product. Decide before any public-mode release whether the extension-hosted vault UI is required. | The security page explains it                                                             | Real data                             |
| D-26 | Reference devices for calibration (input to D-03) | The owner names the oldest laptop browser and phones Ruvee should support                                                                    | Defines who can use Ruvee comfortably                                                     | P2-02, remaining part                 |

### Later-phase decisions

Details are in the linked documents. D-16 was resolved for development by P2-04; the others are
unchanged from Phase 0.

| ID   | Decision                                                       | Recommendation                                                                                                                                                                                                                                                                                                               | Blocks                   |
| ---- | -------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------ |
| D-05 | OPAQUE on React Native                                         | Phase 6 spike: Hermes WebAssembly first, then a UniFFI binding. Not the client-hashed fallback.                                                                                                                                                                                                                              | Phase 6                  |
| D-11 | Mobile biometric unlock; password reset from an unlocked phone | Defer to Phase 6                                                                                                                                                                                                                                                                                                             | Phase 6                  |
| D-12 | Vault reset: may other devices export before wiping?           | Yes, an encrypted export if one exists by then                                                                                                                                                                                                                                                                               | Phase 3                  |
| D-13 | Portable encrypted export format                               | **Approved by the owner for development (2026-10-26): option A**, a container of existing envelopes opened only by the Recovery Kit typed at export time; no export passphrase ([backup-restore.md §4](backup-restore.md#4-portable-encrypted-export-milestone-m2)). Independent review of the format still required (D-19). | M2                       |
| D-14 | Checkpoint comparison between devices                          | Encrypted per-device checkpoint records in Phase 4                                                                                                                                                                                                                                                                           | Phase 4                  |
| D-15 | Security-event retention                                       | 365 days                                                                                                                                                                                                                                                                                                                     | P2-15                    |
| D-16 | CSP for Next.js inline scripts                                 | **Resolved for development (2026-10-24):** static export with build-time script hashes. Trusted Types omitted until Next.js can issue them without a default policy. Not an owner security approval.                                                                                                                         | P2-04 (crypto-only done) |
| D-18 | Single linear commit sequence per vault                        | Approve for V1                                                                                                                                                                                                                                                                                                               | Phase 3                  |

## Deviations from the master prompt

| Deviation                                                                                                                       | Reason                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Visual identity.** The master prompt suggests charcoal and green; the supplied design uses purple.                            | The owner made the design the visual source of truth for Phase 1. The design stays authoritative unless the owner decides otherwise.                                                                                                                                                                                                                                                                                                                          |
| **Phase 0 documents not created:** `monorepo-design.md`, `product-requirements.md`, `milestone-plan.md`, `testing-strategy.md`. | The Phase 0 assignment listed a narrower set of documents. Their content is covered as follows: the packages section of the [system overview](system-overview.md#planned-packages); the [master prompt](../planning/master-engineering-prompt.md) as the product specification; the [roadmap](../planning/implementation-roadmap.md) as the milestone plan; security tests in the roadmap and invariants. A full testing strategy should be written by P2-16. |
| **"Use OS-protected secure storage where available."** The web app stores `SK` in IndexedDB.                                    | No OS key store is available to web pages ([device-enrollment.md §5](../security/device-enrollment.md#5-where-sk-is-stored-on-each-platform), R-06).                                                                                                                                                                                                                                                                                                          |
| **HKDF and AES-256-GCM** were listed for consideration but are not used.                                                        | They are unavailable or unstable in the selected libraries ([ADR-0002](../adr/0002-libsodium-primitives.md)).                                                                                                                                                                                                                                                                                                                                                 |
| **Estimated complexity** is given per Phase 2 task only.                                                                        | Later phases depend on Phase 2 findings and on D-05.                                                                                                                                                                                                                                                                                                                                                                                                          |

## Prototype design conflicts and their status

These were recorded in Phase 1. Each now points to where it is resolved, or says that it is still
open.

| Phase 1 conflict                                | Status                                                                                                                                                                                           |
| ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| "Encrypted vault" and "Synced · Encrypted" copy | The UI keeps showing "Sync not set up" until Phase 3 and Phase 4 implement and test the design. Wording must follow [threat-model.md §4](../security/threat-model.md#4-what-the-server-can-see). |
| Local-first storage                             | Specified in [sync-protocol.md §12](sync-protocol.md#12-local-storage).                                                                                                                          |
| "No recovery" wording                           | Resolved by the proposed wording in [account-recovery.md §8](../security/account-recovery.md#8-user-facing-wording). It is pending D-06.                                                         |
| Weak and reused password findings               | They run on the client only. Breach checks against an external service are **not designed** and stay out of V1.                                                                                  |
| Biased password generator                       | Phase 3: unbiased sampling, using libsodium's `randombytes_uniform` on web, or rejection sampling over `randombytes_buf` on platforms that lack it, plus a reviewed word list.                   |
| Clipboard clearing and auto-lock                | [sync-protocol.md §Memory and lock](sync-protocol.md#memory-and-lock), D-10, and T-26.                                                                                                           |
| Readable export and import                      | Phase 7. Plaintext export requires step-up ([INV-14](../security/security-invariants.md)). The format is D-13.                                                                                   |
| Multiple vaults ("Personal" and "Household")    | V1 has one vault. The data model allows more than one vault per account later, but sharing is deferred. "Household" stays a preview-only label.                                                  |
| Onboarding and unlock screens                   | Phase 2: tasks P2-08 and P2-10.                                                                                                                                                                  |

## Decisions already made in Phase 1 (non-security)

- Monorepo: pnpm workspaces with Turborepo. Node 24, TypeScript 6.0 (strict).
- API: NestJS 12 (ESM), configuration validated with Zod at startup, Prisma 7 with the
  `@prisma/adapter-pg` driver adapter against PostgreSQL 18.
- The Prisma schema intentionally has **no models**. The first models come with P2-06.
- Health: `GET /health/live` (process only) and `GET /health/ready` (database reachable, 503 otherwise).
- Logging: pino through `nestjs-pino`, allow-listed request fields only (method, path without query
  string, request id, status). Headers, cookies and bodies are never logged.
- Web: Next.js 16 App Router, React 19, Tailwind CSS 4 with design tokens taken from the design.
- UI preview: development-only route with synthetic, secret-free fixtures (see the README).
- No Redis, no external cloud services.

## Changes after architecture validation

On 2026-10-22 the single list of 19 approval requests was replaced by the decision tables above.
Product preferences are separated from technical decisions. New decisions D-20 to D-26 come from
[architecture-validation.md](../security/architecture-validation.md). D-02 changed: no server
identifier, no key pinning, single-use login state. D-03 is now provisional pending device
measurements. Nothing is approved.

## Changes after the primitive validation harness (P2-01)

On 2026-10-22 the owner approved **D-25 only**, and P2-01 was implemented in
[`tools/crypto-validation/`](../../tools/crypto-validation/README.md). Every other decision,
including the protocol, pairing, authentication, recovery and the database schema, remains
Proposed. D-01's evidence now includes the harness and finding V-15. "Next task" now means
P2-02, which only D-26 blocks; D-03 no longer counts as blocking it, because P2-02 produces its
evidence.

## Changes after the Argon2id calibration (P2-02, local part)

On 2026-10-23 the benchmark was built and run on the available computer
([kdf-calibration.md](../security/kdf-calibration.md)). Nothing was approved or resolved. D-03
stays provisional, now with the local results and an open question about how the peak-memory
budget is measured. D-26 is still open and blocks only the remaining part of P2-02. "Next task"
now means P2-05, which no decision blocks.

## Changes after P2-05 (API contracts and conventions)

On 2026-10-23 P2-05 was implemented locally. It needed no decision and changed none. "Next task"
now means P2-03, which D-01, D-04 and D-20 block. Nothing was approved.

## Changes after P2-03 (`packages/crypto`)

On 2026-10-24 the owner approved **D-01, D-04 and D-20** for the P2-03 development milestone, as
implementation decisions. They are not a security audit and not approval to store real secrets.
D-04's approval does not cover the pairing protocol. ADR-0002 and ADR-0003 are now "Accepted for
development". P2-03 was implemented locally
([cryptographic-design.md §10](../security/cryptographic-design.md#10-implementation-status-packagescrypto-p2-03)).

Every other decision stays open, including D-03 (profile 1 remains provisional), D-26 (reference
devices), D-19 (independent review), D-21 (pairing), D-22 (recovery authentication) and D-06
(Recovery Kit). One new question came up: the plaintext rule for `DEVICE_LABEL` (normalization,
empty labels) must be settled before device labels are encrypted (P2-08, P2-11). "Next task" now
means P2-04.

## Changes after P2-04 (web headers, crypto-only)

On 2026-10-24 the crypto-only half of P2-04 was implemented locally. **D-16** is resolved for
development: static export with build-time script hashes. That is spike evidence, not an owner
security approval. **D-02 is unchanged and still Proposed.** Trusted Types from the documented
CSP were omitted (Next.js 16.4.2 has no named-policy hook on the static export). "Next task"
means the OPAQUE half of P2-04 if D-02 is approved, or P2-06 if the database design is approved.

## Changes after the owner's web-vault decisions (2026-10-25)

The owner approved, **for development only**, on 2026-10-25:

- **D-02:** OPAQUE as documented in ADR-0004 and authentication.md §2.2.
- **D-22:** the `RAK` verifier for V1, with the recovery notice at recovery start. The second
  OPAQUE registration is to be revisited before any public-mode release.
- **D-21:** pairing as documented in device-enrollment.md §3 and architecture-validation.md §4,
  with the 128-bit code. Independent review (D-19) is still required before real data.
- **Product defaults:** D-17 (username: NFC, lowercase, 1 to 64 characters), D-09 (at least 12
  characters after NFC, at most 4,096 bytes, strength hint; the common-password list is not
  implemented yet), D-06 (Recovery Kit verification required at setup, rotation after use), D-08
  (web: 12 h idle, 14 days absolute, step-up 5 minutes), D-10 (auto-lock 15 minutes, 1 minute to
  8 hours, no "never" on web) and D-23 (locking is local).

None of this is a security review or approval to store real secrets. ADR-0004, ADR-0005 and
ADR-0006 become "Accepted for development". Still open: D-03 and D-26 (profile 1 stays
provisional), D-19, D-07 and the later-phase decisions. D-24 (`SK` rotation on revoking a device as lost, and
offered after recovery) was approved for development the same day.
