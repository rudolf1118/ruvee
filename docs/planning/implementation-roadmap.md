# Implementation roadmap

Status: **Proposed (Phase 0).** Phase 2 must not start until the owner has reviewed the decisions
marked as blocking in [open-decisions.md](../architecture/open-decisions.md). This roadmap
follows the phase list in the [master prompt](master-engineering-prompt.md#24-implementation-phases).
It also serves as the milestone plan.

Size estimates: **S** is up to 2 days of focused work, **M** is 3 to 5 days, **L** is 1 to 2 weeks.
They assume one developer with AI assistance, and exclude review time.

## Phase 2: Cryptography and authentication (web only)

The goal is that a user can create an account on the web, log in, unlock, lock, change the
password, add a second browser by pairing, and recover with the Recovery Kit. The vault has no
items yet; those come in Phase 3. Each task ends with a local commit on a feature branch, and the
security tests listed for it must pass in CI.

| ID    | Task                                                                                                                                                                                                                                                                                                                     | Depends on                            | Size | Acceptance criteria                                                                                                                                                                                                                                                                                                         | Security tests                                                                                                                                                                                                                                                                                      |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------- | ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P2-01 | **Primitive validation harness** in `tools/crypto-validation` (see [first task](#first-bounded-task)). **Implemented locally 2026-10-22; remote CI not yet run.**                                                                                                                                                        | D-25 (approved)                       | M    | See below.                                                                                                                                                                                                                                                                                                                  | Published KATs and cross-implementation checks pass in Node and three browser engines.                                                                                                                                                                                                              |
| P2-02 | **Argon2id calibration spike.** A development-only harness runs `crypto_pwhash` with profile 1 in a dedicated Web Worker on Chrome, Firefox and Safari, on the reference devices. **Tooling and the local computer done 2026-10-23 ([report](../security/kdf-calibration.md)); reference devices and Safari pending.**   | D-26 (reference-device part only)     | S    | A results table (median, p95 and peak memory per browser and device) is added to [research-sources.md](../security/research-sources.md). Profile 1 is confirmed, or a decision is raised. Profile 1 is never weakened silently.                                                                                             | Not applicable (measurement).                                                                                                                                                                                                                                                                       |
| P2-03 | **`packages/crypto`**: envelope codec, derivations, wraps, keyset, padding, Recovery Key and pairing code formats, over an injected libsodium interface. Adds `libsodium-wrappers-sumo` and `libsodium-sumo` at exact versions.                                                                                          | P2-01, D-01, D-04, D-20               | L    | The P2-01 checks pass against it, and its provisional protocol vectors agree with a noble-based reference, in Node and in Chromium, Firefox and WebKit through Playwright. The public API matches [cryptographic-design.md](../security/cryptographic-design.md). There is no nonce parameter outside the test-only export. | INV-02 (nonce uniqueness, test-only export lint), INV-03 (negative vectors), INV-04 (fuzzing the decoder, typed errors), INV-05 (profile floor), INV-17, INV-22 (exact-version check in CI).                                                                                                        |
| P2-04 | **Web security headers and CSP spike.** Caddy and Next.js headers from [api-design.md](../architecture/api-design.md#web-app-security-headers). `packages/crypto` and `@serenity-kit/opaque` load in a worker under the CSP.                                                                                             | P2-03                                 | S    | D-16 is resolved with evidence. CSP has no `'unsafe-inline'` or `'unsafe-eval'` for scripts. Any deviation is recorded.                                                                                                                                                                                                     | An HTTP test asserting every header. A Playwright test that an injected inline script is blocked.                                                                                                                                                                                                   |
| P2-05 | **`packages/contracts` and API conventions**: error shape, base64url byte fields with length checks, body limits, route-template logging, `Origin` and `X-Ruvee-Request` guard, `no-store`. **Implemented locally 2026-10-23, except the `Origin` and `X-Ruvee-Request` guard (moved to P2-09); remote CI not yet run.** | none                                  | M    | Every rule in [api-design.md §Conventions](../architecture/api-design.md#conventions) has a test. Logs contain route templates only.                                                                                                                                                                                        | CSRF tests (T-17). A request with both cookie and bearer is rejected. The log-scan test is extended (INV-12).                                                                                                                                                                                       |
| P2-06 | **Phase 2 database schema and first migration**: the tables in [database-design.md §Phase 2](../architecture/database-design.md#phase-2-tables).                                                                                                                                                                         | Owner approval of the database design | S    | The migration applies to an empty database and rolls back in CI. Every column appears in the documented list.                                                                                                                                                                                                               | INV-10 column-list test.                                                                                                                                                                                                                                                                            |
| P2-07 | **Server secrets and admin CLI**: OPAQUE server setup loaded from a secret file, `instance_id`, and `ruvee-admin bootstrap-token`.                                                                                                                                                                                       | P2-06                                 | S    | The API refuses to start without the secret file. The token is printed only to the terminal, and only its hash is stored. The Docker Compose example mounts the secret.                                                                                                                                                     | INV-21 (configuration and log scan). Expiry and single use of the token.                                                                                                                                                                                                                            |
| P2-08 | **Account bootstrap**: `register/start` and `/finish`, the web setup screen, client-side key generation and Recovery Kit verification.                                                                                                                                                                                   | P2-03, P2-05, P2-07                   | L    | The flow in [system overview, scenario 1](../architecture/system-overview.md#1-first-account-and-vault-creation) works end to end, up to the vault step. Registration returns `404` afterwards. The kit can't be skipped.                                                                                                   | INV-20. **The INV-01 capture test** runs on this flow and asserts that no synthetic secret appears in any request, header, URL or log.                                                                                                                                                              |
| P2-09 | **Login, cookie sessions, throttling, logout and step-up** (`reauth`).                                                                                                                                                                                                                                                   | P2-08                                 | M    | Login on an enrolled device. Idle and absolute expiry. Step-up guard. Login state consumed once (INV-23). No server identifier. The `Origin` and `X-Ruvee-Request` guard on cookie requests, moved from P2-05.                                                                                                              | Unknown and known usernames are indistinguishable in shape, size and timing within a tolerance (T-16). Throttling and `Retry-After`. Cookie attributes (INV-13). Stale step-up is refused (INV-14). CSRF tests (T-17) and rejection of a request with both cookie and bearer, moved from P2-05.     |
| P2-10 | **Web unlock, lock and local store**: IndexedDB device store, crypto worker, lock manager, auto-lock, lock on session expiry.                                                                                                                                                                                            | P2-09                                 | M    | Unlock works offline after login. Every lock trigger in [sync-protocol.md §Memory and lock](../architecture/sync-protocol.md#memory-and-lock) works.                                                                                                                                                                        | INV-15 (app state after lock; `memzero` called). INV-16 (scan of IndexedDB for markers). INV-06 (a fresh browser that only logs in cannot unlock).                                                                                                                                                  |
| P2-11 | **Devices, sessions screen and revocation**, with the client wiping itself on `device_revoked`.                                                                                                                                                                                                                          | P2-09                                 | M    | Matches [device-enrollment.md §6](../security/device-enrollment.md#6-revocation-and-its-limits), including the wording.                                                                                                                                                                                                     | Revocation is immediate for every session of the device. A revoked device's requests all return `401`. Revoking requires step-up. Revoking as lost rotates `SK` (D-24), and the old `SK` no longer opens the new password wrap.                                                                     |
| P2-12 | **Pairing** between two browsers. Until Phase 3 the checkpoint is `{ seq: 0, manifestHash: zeros }`.                                                                                                                                                                                                                     | P2-10, P2-11                          | L    | [System overview, scenario 2](../architecture/system-overview.md#2-adding-a-second-device) works. Limits, expiry and single use are enforced.                                                                                                                                                                               | Malicious-server tests: replacing `epk`, changing the platform, forging the reply, replaying an old pairing, a second request, a request with another device's id, and a pending device calling encrypted-data endpoints. Each must fail, and a MAC failure burns the pairing. (T-05, T-13, INV-23) |
| P2-13 | **Recovery**: `/recovery/*`, mandatory Recovery Key rotation, Check Recovery Kit, the recovery notice on other devices.                                                                                                                                                                                                  | P2-10                                 | L    | Scenarios 4 and 5 in the [system overview](../architecture/system-overview.md#scenario-walkthroughs) work. The wording matches [account-recovery.md §8](../security/account-recovery.md#8-user-facing-wording).                                                                                                             | A wrong key gives a generic failure. Throttling. The recovery session is refused on non-recovery endpoints. The notice is raised at recovery start. Every other session is revoked after completion.                                                                                                |
| P2-14 | **Password change** and Recovery Key rotation from settings.                                                                                                                                                                                                                                                             | P2-10                                 | M    | Scenario 6 works. The `row_version` conflict path is tested.                                                                                                                                                                                                                                                                | Step-up is required. Other sessions are revoked. The old password no longer unwraps the server wrap, and a vector test confirms `AK` is unchanged.                                                                                                                                                  |
| P2-15 | **Security events** and the account activity screen.                                                                                                                                                                                                                                                                     | P2-09                                 | S    | Every event type in [database-design.md](../architecture/database-design.md#security_events) is written by its flow.                                                                                                                                                                                                        | A test that event details contain only allow-listed fields.                                                                                                                                                                                                                                         |
| P2-16 | **Phase 2 review packet**: update the threat model, risk register and invariants against what was built; prepare the independent-review scope.                                                                                                                                                                           | All of the above                      | S    | Every invariant listed above has a passing test and a link to it. Deviations are recorded.                                                                                                                                                                                                                                  | A full run of the security suites.                                                                                                                                                                                                                                                                  |

Phase 2 deliberately leaves out: token sessions for the extension and mobile (in Phase 5, with
their tests), vault items, sync, and re-seeding.

## Later phases (outline)

| Phase | Security-relevant work                                                                                                                                                                             | Gate                                   |
| ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| 3     | `vaults`, `vault_items`, `vault_commits`. Item records and manifests. Commits without concurrency. Vault reset. Local encrypted cache. Generator with unbiased sampling. Clipboard clearing.       | Phase 2 review findings addressed      |
| 4     | Concurrent commits, conflicts, offline queue, SSE, keyset updates, re-seeding, **full key rotation** (its own design review first), checkpoint comparison if D-14 says so.                         | Rotation design reviewed               |
| 5     | The MV3 extension: token sessions with refresh rotation, `chrome.storage.session` key handling, content-script isolation, origin matching for autofill, optional extension-hosted vault UI (R-01). | Extension threat-model addendum        |
| 6     | Mobile: OPAQUE binding spike (D-05), the vector runner on Hermes, Keychain and Keystore storage, biometric unlock design (D-11), native autofill.                                                  | D-05 resolved                          |
| 7     | Cards, identities, TOTP, attachments (a separate design is needed for large objects), import and export (D-13), version history, encrypted backups.                                                | Export and attachment designs reviewed |
| 8     | Passkeys, with their own design.                                                                                                                                                                   | Passkey design reviewed                |
| 9     | Hardening, independent review, restore tests, disaster recovery, operational docs.                                                                                                                 |                                        |

## Decisions needing owner review

They are listed with recommendations in [open-decisions.md](../architecture/open-decisions.md).
The decision table there says which task each decision blocks. D-25 was approved and P2-01 is
implemented. P2-02's tooling and local measurements are done; **D-26 (the reference devices)
blocks its remaining part.** P2-05 is implemented locally. **Every remaining Phase 2 task is now
blocked by an owner decision:** D-01, D-04 and D-20 block P2-03, and approval of the database
design blocks P2-06. The rest follow from those two.

## Independent review

These components need review by someone other than their author before Ruvee holds real data:

1. `packages/crypto` and the vector suite: construction, encodings, AAD, nonce handling, parsing.
2. The OPAQUE integration: configuration, identifiers, single-use login state, the fake-record
   path and server-secret handling.
3. Sessions, CSRF, throttling and step-up.
4. The pairing protocol and its implementation.
5. The recovery flow, Recovery Key formats and reset.
6. Sync verification: manifest chain, checkpoints, conflicts, re-seeding, and full rotation in Phase 4.
7. The web app's CSP and headers, and the deployment (Caddy, Docker secrets, backups).
8. The extension's message passing and autofill (Phase 5), and mobile key storage and biometrics
   (Phase 6).

### Review checklist for security-sensitive pull requests

- [ ] Which invariants does it touch? Is each one tested?
- [ ] Is a new column or field classified, and listed in threat-model §4 if it is plaintext?
- [ ] Is no secret logged, put in a URL, or returned in an error?
- [ ] Does every decryption state its purpose, key id and context? Does it fail closed?
- [ ] Is no nonce supplied by the caller, and no primitive implemented by hand?
- [ ] Are new or updated crypto dependencies pinned exactly, with their changelog reviewed?
- [ ] Do step-up, device state and session kind guards cover new endpoints?
- [ ] Is user-facing wording accurate about what is and isn't protected?

## First bounded task

**P2-01: a primitive validation harness.** It replaces the Phase 0 plan for a Python and Go
vector generator ([architecture-validation.md §8](../security/architecture-validation.md#8-test-vector-plan-reassessed)).
It turns the disposable spike into a maintained CI check of the candidate libraries before any
Ruvee format is implemented on them. It adds no production dependency and implements no Ruvee
protocol.

Prerequisites:

- Owner decision D-25 (this scope and location).
- Nothing else: it does not need D-01 to be approved, because its job is to keep producing the
  evidence for D-01.

Scope:

- `tools/crypto-validation/`, outside the pnpm workspace, with its own lockfile and exact pins:
  `libsodium-wrappers-sumo`, `libsodium-sumo`, `@noble/hashes`, `@noble/ciphers`,
  `@noble/curves`, a test runner and `playwright-core`. No app or package depends on it.
- The published vectors listed in
  [cryptographic-design.md §8](../security/cryptographic-design.md#8-test-vectors-and-interoperability-plan)
  (category 1), stored with their source URL, commit and SHA-256.
- The cross-implementation checks for keyed BLAKE2b-256, `crypto_kdf`, the sealed box and
  padding, the Argon2id chain from RFC 9106 through noble to libsodium, and the library behavior
  Ruvee relies on: generic AEAD failure, length handling, string encoding, and lone surrogates.
- A runner for Node and for Chromium, Firefox and WebKit (main thread and worker) under the
  strict CSP, and a CI job that runs it.

Acceptance criteria:

1. Every check passes in Node and in the three Playwright engines in CI, and fails the job on
   any mismatch.
2. Every vector file is verified against its recorded SHA-256 before use.
3. The README states that all inputs are synthetic and that the harness tests libraries, not
   Ruvee's format.
4. No change to `apps/*`, `packages/*` or the production dependencies. Lint and format pass.

Out of scope: Ruvee protocol vectors (category 2, which waits for P2-03 and a format review),
OPAQUE, performance budgets (P2-02), and any TypeScript implementation (P2-03).

### P2-01 status (2026-10-22)

Implemented locally in [`tools/crypto-validation/`](../../tools/crypto-validation/README.md),
with the `crypto-validation` CI job. Every check and negative control passes in Node 24, in
Playwright Chromium, Firefox and WebKit (page and worker), and in a local Linux container running
the CI job's commands. **Remote CI has not run**, because nothing has been pushed; acceptance
criterion 1 is met only when it does. Criteria 2 to 4 are met.

Deviations from the scope above:

- No test-runner dependency. The harness has a small runner of its own, so the same check code
  runs unchanged in Node, a page and a worker, and every result is checked for completeness.
- It adds negative controls (fault injection) and a check that WebAssembly fails without
  `'wasm-unsafe-eval'`.
- It found V-15 ([validation §1](../security/architecture-validation.md#1-findings)), which P2-03
  must handle.

### P2-02 status (2026-10-23)

| Part                                                                                                            | Status                                                                                                                                  |
| --------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Benchmark tooling: Node and browser workers, local page, manual instructions, cancellation, self-test in CI     | **Done**, in [`tools/crypto-validation/src/calibration/`](../../tools/crypto-validation/README.md#argon2id-calibration-benchmark-p2-02) |
| Measurements on the available computer (Apple M5; Node, Playwright Chromium, Firefox and WebKit, Google Chrome) | **Done**, in [kdf-calibration.md](../security/kdf-calibration.md). Says nothing about other devices.                                    |
| Safari                                                                                                          | **Pending:** manual run with the local page                                                                                             |
| Reference phones and older laptops                                                                              | **Pending: blocked by D-26**, then a manual run on each device                                                                          |
| Results table in research-sources.md; profile 1 confirmed or a decision raised                                  | Local results linked; confirmation **pending** the reference devices. Profile 1 stays provisional.                                      |

Deviations: the results live in [kdf-calibration.md](../security/kdf-calibration.md), with a
summary row in research-sources.md. Peak memory is reported only where it can be measured: whole
process in Node, WebAssembly memory size in browsers, which is not total peak memory. The memory
budget in cryptographic-design §3.2 needs a definition before it can be checked (D-03).

### P2-05 status (2026-10-23)

Implemented locally; remote CI has not run. Details are in
[api-design.md §What is implemented](../architecture/api-design.md#what-is-implemented).

| Acceptance item                                       | Status                                                                                                                                                                                            |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `packages/contracts`                                  | **Done.** Zod schemas for the health responses, the error shape and codes, request ids and body limits, and `base64urlBytes`. Builds without Node or DOM types; a lint rule forbids Node imports. |
| Error shape                                           | **Done.** The Phase 1 shape, with stable codes and fixed messages. Framework messages that quoted input (JSON parse errors, `Cannot GET /path`) are no longer returned.                           |
| base64url byte fields with length checks              | **Done** as a schema helper. No endpoint has a byte field yet.                                                                                                                                    |
| Body limits and content types                         | **Done:** 64 KiB, UTF-8 JSON only, no compression. The 4 MiB sync limit waits for Phase 3.                                                                                                        |
| Route-template logging                                | **Done.** Raw paths are no longer logged. Error messages are no longer logged either.                                                                                                             |
| `no-store`                                            | **Done** for every response.                                                                                                                                                                      |
| OpenAPI                                               | **Done** for the two implemented endpoints, generated from the schemas, with drift and route-coverage tests.                                                                                      |
| `Origin` and `X-Ruvee-Request` guard; cookie + bearer | **Moved to P2-09.** Without sessions they protect nothing, and implementing authentication was out of scope.                                                                                      |
| Log-scan test (INV-12)                                | **Done:** a synthetic secret in paths, queries, headers, cookies, bodies and exception messages never appears in captured logs or responses.                                                      |

Deviations: the `/api/v1` base path is not created, because no versioned endpoint exists. An
HTTP exception without a contract code is reported as `500 internal_error`, so each future status
needs a code first.

## Next bounded task

No remaining Phase 2 task is unblocked. The proposed next task is **P2-03, `packages/crypto`**:
it is the largest item on the path to account creation (P2-08), and the decisions it needs are
narrow and technical. It is blocked by:

- **D-01**: the primitive library (`libsodium-wrappers-sumo` and `libsodium-sumo` 0.8.4, exactly
  pinned).
- **D-04**: keeping the two-secret key derivation and enrollment.
- **D-20**: the password input rule (well-formed string, NFC, 1 to 4,096 UTF-8 bytes).

P2-03 must also check every length before calling libsodium.js, because of V-15.

The other paths:

- **P2-06**, the first migration, is the alternative. It is smaller and blocked only by owner
  approval of the database design, which is a broader approval than the three decisions above.
- P2-02, remaining part: **D-26** (which devices), then manual runs on them and on Safari.

## Changes after architecture validation

Status remains **Proposed**. Changes made on 2026-10-22 from
[architecture-validation.md](../security/architecture-validation.md):

- P2-01 is now a primitive validation harness (V-10). P2-03 depends on D-01, D-04 and D-20, and
  pins `libsodium-sumo` too.
- P2-09: pinning removed, single-use login state added (V-03, V-04).
- P2-12 and P2-13: tests for the single-request rule and the recovery notice at start (V-07,
  V-09).
- Which decisions block which task now follows the decision table in open-decisions.md.

## Changes after P2-01

Status remains **Proposed**. Changes made on 2026-10-22:

- P2-01 marked implemented locally, with its deviations ([status](#p2-01-status-2026-10-22)).
- P2-02 now depends on D-26 only, instead of D-01 and D-03 (see
  [next bounded task](#next-bounded-task)).

## Changes after P2-02 (local part)

Status remains **Proposed**. Changes made on 2026-10-23:

- P2-02 split into done (tooling, local computer) and pending (Safari, reference devices) parts
  ([status](#p2-02-status-2026-10-23)). Only the pending part depends on D-26.
- The next bounded task is P2-05, the first unblocked one.

## Changes after P2-05

Status remains **Proposed**. Changes made on 2026-10-23:

- P2-05 marked implemented locally, with its deviations ([status](#p2-05-status-2026-10-23)).
- The `Origin` and `X-Ruvee-Request` guard, the CSRF tests (T-17) and the cookie-plus-bearer
  rejection moved from P2-05 to P2-09, which introduces sessions.
- The proposed next task is P2-03, blocked by D-01, D-04 and D-20.
