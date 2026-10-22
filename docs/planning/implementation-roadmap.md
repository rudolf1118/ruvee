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

| ID    | Task                                                                                                                                                                                                                         | Depends on                            | Size | Acceptance criteria                                                                                                                                                                                                                   | Security tests                                                                                                                                                                                      |
| ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------- | ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| P2-01 | **Independent test-vector generator** in `tools/crypto-vectors` (see [first task](#first-bounded-task)).                                                                                                                     | D-01                                  | M    | See below.                                                                                                                                                                                                                            | Published KATs pass inside the generator. Negative vectors exist for every AAD field.                                                                                                               |
| P2-02 | **Argon2id calibration spike.** A development-only harness runs `crypto_pwhash` with profile 1 in a dedicated Web Worker on Chrome, Firefox and Safari, on the reference devices.                                            | D-01, D-03                            | S    | A results table (median, p95 and peak memory per browser and device) is added to [research-sources.md](../security/research-sources.md). Profile 1 is confirmed, or a decision is raised. Profile 1 is never weakened silently.       | Not applicable (measurement).                                                                                                                                                                       |
| P2-03 | **`packages/crypto`**: envelope codec, derivations, wraps, keyset, padding, Recovery Key and pairing code formats, over an injected libsodium interface. Adds `libsodium-wrappers-sumo` at an exact version.                 | P2-01                                 | L    | Every vector from P2-01 passes in Node, and in Chrome and WebKit through Playwright. The public API matches [cryptographic-design.md](../security/cryptographic-design.md). There is no nonce parameter outside the test-only export. | INV-02 (nonce uniqueness, test-only export lint), INV-03 (negative vectors), INV-04 (fuzzing the decoder, typed errors), INV-05 (profile floor), INV-17, INV-22 (exact-version check in CI).        |
| P2-04 | **Web security headers and CSP spike.** Caddy and Next.js headers from [api-design.md](../architecture/api-design.md#web-app-security-headers). `packages/crypto` and `@serenity-kit/opaque` load in a worker under the CSP. | P2-03                                 | S    | D-16 is resolved with evidence. CSP has no `'unsafe-inline'` or `'unsafe-eval'` for scripts. Any deviation is recorded.                                                                                                               | An HTTP test asserting every header. A Playwright test that an injected inline script is blocked.                                                                                                   |
| P2-05 | **`packages/contracts` and API conventions**: error shape, base64url byte fields with length checks, body limits, route-template logging, `Origin` and `X-Ruvee-Request` guard, `no-store`.                                  | none                                  | M    | Every rule in [api-design.md §Conventions](../architecture/api-design.md#conventions) has a test. Logs contain route templates only.                                                                                                  | CSRF tests (T-17). A request with both cookie and bearer is rejected. The log-scan test is extended (INV-12).                                                                                       |
| P2-06 | **Phase 2 database schema and first migration**: the tables in [database-design.md §Phase 2](../architecture/database-design.md#phase-2-tables).                                                                             | Owner approval of the database design | S    | The migration applies to an empty database and rolls back in CI. Every column appears in the documented list.                                                                                                                         | INV-10 column-list test.                                                                                                                                                                            |
| P2-07 | **Server secrets and admin CLI**: OPAQUE server setup loaded from a secret file, `instance_id`, and `ruvee-admin bootstrap-token`.                                                                                           | P2-06                                 | S    | The API refuses to start without the secret file. The token is printed only to the terminal, and only its hash is stored. The Docker Compose example mounts the secret.                                                               | INV-21 (configuration and log scan). Expiry and single use of the token.                                                                                                                            |
| P2-08 | **Account bootstrap**: `register/start` and `/finish`, the web setup screen, client-side key generation and Recovery Kit verification.                                                                                       | P2-03, P2-05, P2-07                   | L    | The flow in [system overview, scenario 1](../architecture/system-overview.md#1-first-account-and-vault-creation) works end to end, up to the vault step. Registration returns `404` afterwards. The kit can't be skipped.             | INV-20. **The INV-01 capture test** runs on this flow and asserts that no synthetic secret appears in any request, header, URL or log.                                                              |
| P2-09 | **Login, cookie sessions, throttling, logout and step-up** (`reauth`).                                                                                                                                                       | P2-08                                 | M    | Login on an enrolled device. Idle and absolute expiry. Step-up guard. Server public-key pinning.                                                                                                                                      | Unknown and known usernames are indistinguishable in shape, size and timing within a tolerance (T-16). Throttling and `Retry-After`. Cookie attributes (INV-13). Stale step-up is refused (INV-14). |
| P2-10 | **Web unlock, lock and local store**: IndexedDB device store, crypto worker, lock manager, auto-lock, lock on session expiry.                                                                                                | P2-09                                 | M    | Unlock works offline after login. Every lock trigger in [sync-protocol.md §Memory and lock](../architecture/sync-protocol.md#memory-and-lock) works.                                                                                  | INV-15 (app state after lock; `memzero` called). INV-16 (scan of IndexedDB for markers). INV-06 (a fresh browser that only logs in cannot unlock).                                                  |
| P2-11 | **Devices, sessions screen and revocation**, with the client wiping itself on `device_revoked`.                                                                                                                              | P2-09                                 | M    | Matches [device-enrollment.md §6](../security/device-enrollment.md#6-revocation-and-its-limits), including the wording.                                                                                                               | Revocation is immediate for every session of the device. A revoked device's requests all return `401`. Revoking requires step-up.                                                                   |
| P2-12 | **Pairing** between two browsers. Until Phase 3 the checkpoint is `{ seq: 0, manifestHash: zeros }`.                                                                                                                         | P2-10, P2-11                          | L    | [System overview, scenario 2](../architecture/system-overview.md#2-adding-a-second-device) works. Limits, expiry and single use are enforced.                                                                                         | Malicious-server tests: replacing `epk`, changing the platform, forging the reply, replaying an old pairing, and a pending device calling encrypted-data endpoints. Each must fail. (T-05, T-13)    |
| P2-13 | **Recovery**: `/recovery/*`, mandatory Recovery Key rotation, Check Recovery Kit, the recovery notice on other devices.                                                                                                      | P2-10                                 | L    | Scenarios 4 and 5 in the [system overview](../architecture/system-overview.md#scenario-walkthroughs) work. The wording matches [account-recovery.md §8](../security/account-recovery.md#8-user-facing-wording).                       | A wrong key gives a generic failure. Throttling. The recovery session is refused on non-recovery endpoints. Every other session is revoked after completion.                                        |
| P2-14 | **Password change** and Recovery Key rotation from settings.                                                                                                                                                                 | P2-10                                 | M    | Scenario 6 works. The `row_version` conflict path is tested.                                                                                                                                                                          | Step-up is required. Other sessions are revoked. The old password no longer unwraps the server wrap, and a vector test confirms `AK` is unchanged.                                                  |
| P2-15 | **Security events** and the account activity screen.                                                                                                                                                                         | P2-09                                 | S    | Every event type in [database-design.md](../architecture/database-design.md#security_events) is written by its flow.                                                                                                                  | A test that event details contain only allow-listed fields.                                                                                                                                         |
| P2-16 | **Phase 2 review packet**: update the threat model, risk register and invariants against what was built; prepare the independent-review scope.                                                                               | All of the above                      | S    | Every invariant listed above has a passing test and a link to it. Deviations are recorded.                                                                                                                                            | A full run of the security suites.                                                                                                                                                                  |

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
**D-01 to D-04, D-06 to D-09 and D-17 block Phase 2.** The others block later phases only.

## Independent review

These components need review by someone other than their author before Ruvee holds real data:

1. `packages/crypto` and the vector suite: construction, encodings, AAD, nonce handling, parsing.
2. The OPAQUE integration: configuration, the fake-record path, server-secret handling, key pinning.
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

**P2-01: an independent test-vector generator.** It is first because every later crypto task is
judged against it, and it adds no production dependency.

Scope:

- `tools/crypto-vectors/` with a pinned Python environment (`argon2-cffi`, PyCryptodome, and the
  standard `hashlib`) and a small Go program (`golang.org/x/crypto/nacl/box`) for sealed boxes. It
  is not part of the pnpm workspace build, and no app depends on it.
- Inputs: fixed test keys, salts and nonces, all labelled as test-only.
- Outputs: committed JSON files under `tools/crypto-vectors/out/`, as specified in
  [cryptographic-design.md §8](../security/cryptographic-design.md#8-test-vectors-and-interoperability-plan).
  They cover: Argon2id profile 1; every BLAKE2b and KDF derivation (`AUK`, `RWK`, `RAK`, every
  `K_*`, `K_manifest`, pairing values); every envelope purpose, with valid and negative cases;
  item record, padding, manifest, `items_digest` and `manifest_hash`; Recovery Key and pairing-code
  text with checksum failures; sealed-box open cases.

Acceptance criteria:

1. The generator first checks the published known-answer tests: RFC 9106 Argon2id, the
   XChaCha20-Poly1305 draft A.3.1, RFC 7693 BLAKE2b, and Wycheproof XChaCha20-Poly1305. It
   refuses to write output if any of them fail.
2. Running it twice produces byte-identical output.
3. Every negative vector names the single field it changes, such as `item_id`, `revision`,
   `seq`, `purpose` or `key_id`, and the expected typed error.
4. A README explains how to run it and states that the vectors are not secrets and must never be
   used as real keys.
5. No change to `apps/*` or the production dependencies. Lint and format pass.

Out of scope: any TypeScript implementation. That is P2-03.
