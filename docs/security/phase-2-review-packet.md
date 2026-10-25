# Phase 2 review packet

Status: **Self-review, 2026-10-25.** Written by the developer and an AI agent against what is
built on `vault/web-vault`. It is the input for the independent review (D-19), not a
substitute for it. Nothing here approves storing real secrets.

Everything below was run locally. Remote CI has never run. Safari, a real Caddy binary, phones and
older laptops were not tested.

## 1. How to reproduce

| Suite                                 | Command                                                                                         | Result on 2026-10-25                    |
| ------------------------------------- | ----------------------------------------------------------------------------------------------- | --------------------------------------- |
| Format, lint, types                   | `pnpm format:check && pnpm lint && pnpm typecheck`                                              | Pass                                    |
| Unit                                  | `pnpm test`                                                                                     | contracts 34, API 68, web 73, crypto 60 |
| Integration (real PostgreSQL)         | `DATABASE_URL=… pnpm test:integration`                                                          | 42                                      |
| Crypto in browsers                    | `pnpm --filter @ruvee/crypto test:browsers`                                                     | 24 checks × 6 contexts                  |
| Headers, CSP, OPAQUE under the CSP    | `pnpm --filter @ruvee/web test:headers`                                                         | 30, three engines                       |
| Design preview                        | `pnpm --filter @ruvee/web test:e2e`                                                             | 8 (needs network for `next/font`)       |
| Two- and three-device vault, real API | `RUVEE_E2E_ADMIN_DATABASE_URL=… RUVEE_E2E_BROWSER=<engine> pnpm --filter @ruvee/web test:vault` | Pass in Chromium, Firefox, WebKit       |

The integration and vault suites create and drop their own `ruvee_it_*` and `ruvee_e2e_*`
databases on the server they are given.

## 2. Invariants and the tests that prove them

"Tested" means at least one automated test fails if the invariant breaks in the code that exists.
"Partly" names what is not covered. "Structural" means the property follows from what the code
lacks, and a reviewer should confirm that by reading.

| Invariant                                            | Status                 | Tests                                                                                                                                                                                                                                                                                                                                                                                  |
| ---------------------------------------------------- | ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| INV-01 nothing secret reaches the server             | Tested                 | `apps/api/test/auth.int-spec.ts` "never sends or stores the password, Recovery Key or vault keys (INV-01 capture)"; `apps/web/e2e-vault/two-devices.spec.ts` (every request URL, header and body of three browsers scanned for passwords, Recovery Keys, item secrets and titles); `apps/web/src/vault/worker/vault-engine.test.ts` "stores items as ciphertext only"                  |
| INV-02 fresh nonces, no caller nonce                 | Tested                 | `packages/crypto/test/exports.spec.ts` (no input has a nonce field; the fixed-nonce module is test-only); portable check `nonce-uniqueness`                                                                                                                                                                                                                                            |
| INV-03 AAD from expectations                         | Tested                 | Portable checks `envelope-parsing-and-tampering`, `item-record-round-trip-and-binding`, `recovery-wrap-round-trip-and-binding`, `local-record-round-trip-and-binding`, `pairing-round-trip-and-binding`, `items-digest-and-manifest` (each changes one context field and expects failure)                                                                                              |
| INV-04 fail closed                                   | Tested                 | Portable checks `decoder-fuzz`, `envelope-parsing-and-tampering`; `packages/crypto/test/errors.spec.ts`; `sync-logic.test.ts` "rejects a record that does not decrypt at its claimed revision"                                                                                                                                                                                         |
| INV-05 known KDF profile, floor 1                    | Tested                 | Portable check `kdf-profile-floor`; the contracts accept only `kdfProfile: 1`                                                                                                                                                                                                                                                                                                          |
| INV-06 a session alone never decrypts                | Tested                 | `auth.int-spec.ts` "logs in an enrolled device, and puts an unknown device in pending" (pending device gets `device_not_enrolled` on keys and sync); `pairing.int-spec.ts` (pending device refused on keys, enrolled only by pairing)                                                                                                                                                  |
| INV-07 verify before applying                        | Tested                 | `sync-logic.test.ts` `verifyPages` cases; `vault-engine.test.ts` "stops and goes read-only when the server rolls back a record"; `sync.int-spec.ts` "pages on commit boundaries and the client can still verify the whole range"                                                                                                                                                       |
| INV-08 no silent overwrite                           | Tested                 | `vault-engine.test.ts` "syncs between two devices and turns concurrent edits into an explicit conflict", "reports an edit of an item that was deleted on another device"; the vault e2e conflict step                                                                                                                                                                                  |
| INV-09 no keyset rollback                            | Tested                 | `vault-engine.test.ts` "refuses an older keyset, or a newer one that does not open, and goes read-only (INV-09)"; server side `account-security.int-spec.ts` "rotates SK: the next keyset version…"                                                                                                                                                                                    |
| INV-10 server plaintext is the listed set            | Tested                 | `migrations.int-spec.ts` (the columns equal `column-classes.ts`)                                                                                                                                                                                                                                                                                                                       |
| INV-11 auth and decryption independent               | Structural             | No API in `packages/crypto` takes an OPAQUE export key or session key; `AUK` takes only the password, salt, profile, `SK` and account id. The `RAK` exception is the portable check `recovery-verifier-is-sha256`.                                                                                                                                                                     |
| INV-12 no secrets in logs, URLs, errors              | Tested                 | `apps/api/test/logging.spec.ts` (sentinel secret); `http.spec.ts` (errors never repeat input); `account-security.int-spec.ts` "lists security events… with only allow-listed details" (a stored non-allow-listed field never leaves); crypto `errors.spec.ts`; the vault e2e URL scan                                                                                                  |
| INV-13 random tokens, hashed, `__Host-` cookie       | Tested for cookies     | `auth.int-spec.ts`: the cookie attributes, and "stores only the SHA-256 of each 256-bit session token (INV-13)". Refresh tokens are not built (Phase 5).                                                                                                                                                                                                                               |
| INV-14 step-up for sensitive operations              | Tested for what exists | `account-security.int-spec.ts`: revoke, password change, `SK` rotation, Recovery Kit rotation each refuse a stale authentication with `step_up_required`. Vault reset, full key rotation and plaintext export are not built.                                                                                                                                                           |
| INV-15 lock drops keys                               | Partly                 | The vault e2e locks and checks that no item text is on the page; locking terminates the worker. `packages/crypto/test/ownership.spec.ts` checks wiping of intermediates. No test inspects the worker heap; JavaScript allows no such test (R-11).                                                                                                                                      |
| INV-16 no plaintext at rest                          | Tested                 | The vault e2e dumps IndexedDB, `localStorage` and `sessionStorage` of three browsers and scans for every secret; `vault-engine.test.ts` "stores items as ciphertext only"                                                                                                                                                                                                              |
| INV-17 `SK` alone decrypts nothing                   | Tested                 | Portable check `inv17-secret-key-alone-decrypts-nothing`                                                                                                                                                                                                                                                                                                                               |
| INV-18 no administrator decryption                   | Structural             | `apps/api/src/admin/cli.ts` has only `opaque-setup` and `bootstrap-token`; the server holds no key that opens any envelope.                                                                                                                                                                                                                                                            |
| INV-19 content scripts never get keys                | Not applicable yet     | Phase 5.                                                                                                                                                                                                                                                                                                                                                                               |
| INV-20 registration closed                           | Tested                 | `auth.int-spec.ts` "refuses registration without a valid bootstrap token…", "creates the account… then closes registration"                                                                                                                                                                                                                                                            |
| INV-21 OPAQUE setup never stored, logged or returned | Tested                 | `auth.int-spec.ts` "never stores, logs or returns the OPAQUE server setup (INV-21)" (every table, the logs and several responses, in base64url and hex)                                                                                                                                                                                                                                |
| INV-22 exact crypto pins                             | Tested                 | `packages/crypto/test/versions.spec.ts`                                                                                                                                                                                                                                                                                                                                                |
| INV-23 single-use protocol state                     | Tested                 | Login: `auth.int-spec.ts` "consumes a login id once"; reauth: `account-security.int-spec.ts` (a reauth id is refused by `login/finish` and works once); pairing: `pairing.int-spec.ts` and `vault-engine.test.ts` (one request per pairing, a MAC failure burns it); recovery completion: `recovery.int-spec.ts` (a second completion is refused); bootstrap token: `auth.int-spec.ts` |

## 3. Deviations and interpretations

Choices made while building that a reviewer should confirm. None weakens an invariant on purpose.

1. **Platform codes** in the pairing request MAC: web 1, extension 2, ios 3, android 4.
2. **Paired devices pull from genesis** and require the chain to pass through the checkpoint they
   received (an "anchor"), because they hold no records at that `seq`.
3. **Registration creates the vault** (`register/finish` carries it); there is no `POST /vaults`.
4. **Zod runs jitless** so it never probes `new Function` under the CSP.
5. **Step-up login states are bound to their session.** `login/finish` refuses them, so step-up can
   never mint a session.
6. **Revoking as lost rotates `SK` in the same step-up** (D-24). If only the rotation fails, the
   revocation stands and the UI offers the rotation again.
7. **Other devices adopt a rotated `SK` at their next online unlock**, where the password is in
   hand to write a new local wrap, not during a background sync. A device that missed both an `SK`
   rotation and a password change asks once for its previous password
   (`previous_password_required`) and keeps the server's wrap only if the new password and the new
   `SK` open it to the same `AK`.
8. **Recovery Kit rotation from Security** sends nothing until the new key was typed back, and asks
   for the master password last, so the 5-minute step-up window cannot lapse while the kit is
   saved. It also ends unfinished recovery sessions, which account-recovery.md §5 does not require.
9. **Activity** re-filters event details through the allowlist on the way out as well as on write.
10. **The web client adopts a newer keyset only under the current `AK` and the same vault id**;
    anything else stops sync with an integrity error (unchanged from the web-vault milestone).

## 4. Changes to the threat model and risk register

- **R-17** (exposure of `SK` persists): mitigated as designed. `SK` rotates when a device is
  removed as lost, and Security replaces it on request. It still does nothing against a device
  that already holds `AK` (R-10); only full rotation (Phase 4) does.
- **R-10** (a lost device keeps decrypting): unchanged. The removal screen says so in the words of
  device-enrollment §6.
- **R-08** (`RAK` seen by the server): unchanged under D-22. Recovery Kit rotation now also ends
  any recovery the old kit had started but not finished.
- **R-15** (no independent review): unchanged. This packet is its input.
- **T-16, T-17** (username enumeration, CSRF): covered by `auth.int-spec.ts` as listed above.
- No new server-visible plaintext. New stored values are the `secret_key_rotated` event type and
  the existing columns updated by the new endpoints; `migrations.int-spec.ts` still passes.

## 5. Scope for the independent review

In order of risk, with where to start reading:

1. **`packages/crypto`** and the vectors: `src/operations.ts`, `src/vault-operations.ts`,
   `src/pairing-operations.ts`, `src/envelope.ts`, `test/portable/`. The libsodium.js V-15
   containment (`v15-*` checks) is containment, not an upstream fix.
2. **OPAQUE integration**: `apps/api/src/auth/` (single-use login state, fake records for unknown
   users, reauth binding), `apps/web/src/vault/worker/vault.worker.ts` (D-02 configuration).
3. **Sessions, CSRF, throttling, step-up**: `apps/api/src/sessions/`, `auth/throttle.service.ts`.
4. **Pairing**: device-enrollment §3 against `vault-engine.ts` `pairing*` and
   `apps/api/src/pairing/`. D-21 requires this review before real data.
5. **Recovery and key rotations**: `recovery/`, `account/account-security.service.ts`, and the
   engine's `recovery*`, `rotateSecretKey`, `kitRotate*`, `adoptServerKeys`, `refreshKeyset`.
6. **Sync verification**: `apps/web/src/vault/worker/sync-logic.ts` and the engine's pull, rebase
   and push.
7. **Web delivery**: the CSP and headers (`apps/web/src/security/headers.ts`, `deploy/Caddyfile`)
   and the trust model of a server-served client (D-07, R-01).

Not in scope yet: the extension (Phase 5), mobile (Phase 6), full key rotation (Phase 4).
