# Phase 2 review packet

Status: **Self-review, updated 2026-10-26.** Written by the developer and an AI agent against
what is built on `vault/web-vault`, now including the browser extension and bearer-token
sessions. It is the input for the independent review (D-19), not a substitute for it, and not an
audit. **D-19 is open: real data stays blocked until the review in §6 has happened.**

Everything below was run locally. Remote CI has never run. Safari, a real Caddy binary, phones,
older laptops and a packed (store) build of the extension were not tested. A passing test is
evidence for the specific behaviour it exercises, not proof that an invariant holds everywhere.

## 1. How to reproduce

| Suite                                                 | Command                                                                                          | Result on 2026-10-26                                            |
| ----------------------------------------------------- | ------------------------------------------------------------------------------------------------ | --------------------------------------------------------------- |
| Format, lint, types                                   | `pnpm format:check && pnpm lint && pnpm typecheck`                                               | Pass                                                            |
| Unit                                                  | `pnpm test`                                                                                      | contracts 34, API 70, web 33, vault 54, extension 27, crypto 60 |
| Integration (real PostgreSQL)                         | `DATABASE_URL=… pnpm test:integration`                                                           | 55 passed, 3 todo (D-28 placeholders)                           |
| Crypto in browsers                                    | `pnpm --filter @ruvee/crypto test:browsers`                                                      | 24 checks × 6 contexts                                          |
| Headers, CSP, OPAQUE, local fonts                     | `pnpm --filter @ruvee/web test:headers`                                                          | 33, three engines                                               |
| Design preview                                        | `pnpm --filter @ruvee/web test:e2e`                                                              | 8 (no network needed since the fonts are local)                 |
| Web vault, three devices and an export, real API      | `RUVEE_E2E_ADMIN_DATABASE_URL=… RUVEE_E2E_BROWSER=<engine> pnpm --filter @ruvee/web test:vault`  | Pass in Chromium, Firefox, WebKit                               |
| Extension, real API and web app                       | `RUVEE_E2E_ADMIN_DATABASE_URL=… pnpm --filter @ruvee/extension test:extension`                   | 9, Chromium (unpacked test build)                               |
| Restore into a fresh installation (two installations) | `RUVEE_E2E_ADMIN_DATABASE_URL=… RUVEE_E2E_BROWSER=<engine> pnpm --filter @ruvee/web test:import` | Pass in Chromium, Firefox, WebKit                               |

The integration, vault and extension suites create and drop their own `ruvee_it_*` and
`ruvee_e2e_*` databases on the server they are given.

## 2. Invariants and the tests that prove them

"Tested" means at least one automated test fails if the invariant breaks in the code that exists.
"Partly" names what is not covered. "Structural" means the property follows from what the code
lacks, and a reviewer should confirm that by reading.

| Invariant                                            | Status                        | Tests                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------------------------------------------- | ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| INV-01 nothing secret reaches the server             | Tested                        | `apps/api/test/auth.int-spec.ts` "never sends or stores the password, Recovery Key or vault keys (INV-01 capture)"; `apps/web/e2e-vault/two-devices.spec.ts` (every request of three browsers scanned); `apps/extension/e2e/extension.spec.ts` "capture" (every request of the extension and web app, both master passwords, the item password, the Recovery Key); `packages/vault/src/vault-engine.test.ts` "stores items as ciphertext only" |
| INV-02 fresh nonces, no caller nonce                 | Tested                        | `packages/crypto/test/exports.spec.ts` (no input has a nonce field; the fixed-nonce module is test-only); portable check `nonce-uniqueness`                                                                                                                                                                                                                                                                                                    |
| INV-03 AAD from expectations                         | Tested                        | Portable checks `envelope-parsing-and-tampering`, `item-record-round-trip-and-binding`, `recovery-wrap-round-trip-and-binding`, `local-record-round-trip-and-binding`, `pairing-round-trip-and-binding`, `items-digest-and-manifest` (each changes one context field and expects failure)                                                                                                                                                      |
| INV-04 fail closed                                   | Tested                        | Portable checks `decoder-fuzz`, `envelope-parsing-and-tampering`; `packages/crypto/test/errors.spec.ts`; `sync-logic.test.ts` "rejects a record that does not decrypt at its claimed revision"                                                                                                                                                                                                                                                 |
| INV-05 known KDF profile, floor 1                    | Tested                        | Portable check `kdf-profile-floor`; the contracts accept only `kdfProfile: 1`                                                                                                                                                                                                                                                                                                                                                                  |
| INV-06 a session alone never decrypts                | Tested                        | `auth.int-spec.ts` (pending device refused on keys and sync); `pairing.int-spec.ts`; `tokens.int-spec.ts` (a pending extension gets `device_not_enrolled` on keys); the extension e2e (a revoked extension that logs in again is pending and must be paired)                                                                                                                                                                                   |
| INV-07 verify before applying                        | Tested                        | `sync-logic.test.ts` `verifyPages` cases; `vault-engine.test.ts` "stops and goes read-only when the server rolls back a record"; `sync.int-spec.ts` "pages on commit boundaries and the client can still verify the whole range"                                                                                                                                                                                                               |
| INV-08 no silent overwrite                           | Tested                        | `vault-engine.test.ts` "syncs between two devices and turns concurrent edits into an explicit conflict", "reports an edit of an item that was deleted on another device"; the vault e2e conflict step                                                                                                                                                                                                                                          |
| INV-09 no keyset rollback                            | Tested                        | `vault-engine.test.ts` "refuses an older keyset, or a newer one that does not open, and goes read-only (INV-09)"; server side `account-security.int-spec.ts` "rotates SK: the next keyset version…"                                                                                                                                                                                                                                            |
| INV-10 server plaintext is the listed set            | Tested                        | `migrations.int-spec.ts` (the columns equal `column-classes.ts`)                                                                                                                                                                                                                                                                                                                                                                               |
| INV-11 auth and decryption independent               | Structural                    | No API in `packages/crypto` takes an OPAQUE export key or session key; `AUK` takes only the password, salt, profile, `SK` and account id. The `RAK` exception is the portable check `recovery-verifier-is-sha256`.                                                                                                                                                                                                                             |
| INV-12 no secrets in logs, URLs, errors              | Tested                        | `apps/api/test/logging.spec.ts` (sentinel secret); `http.spec.ts` (errors never repeat input); `account-security.int-spec.ts` "lists security events… with only allow-listed details" (a stored non-allow-listed field never leaves); crypto `errors.spec.ts`; the vault e2e URL scan                                                                                                                                                          |
| INV-13 random tokens, hashed, `__Host-` cookie       | Tested                        | `auth.int-spec.ts`: cookie attributes, "stores only the SHA-256 of each 256-bit session token"; `tokens.int-spec.ts` "stores only hashes of access and refresh tokens", rotation, reuse revoking the family, expiry; extension e2e "a reused refresh token ends the session for the extension too"                                                                                                                                             |
| INV-14 step-up for sensitive operations              | Tested for what exists        | `account-security.int-spec.ts`: revoke, password change, `SK` rotation, Recovery Kit rotation each refuse a stale authentication with `step_up_required`. Vault reset, full key rotation and plaintext export are not built.                                                                                                                                                                                                                   |
| INV-15 lock drops keys                               | Partly                        | Web: the vault e2e locks and checks no item text remains; locking terminates the worker. Extension e2e: lock, auto-lock (alarm, and an expired unlock after a worker restart), logout, refresh-token reuse and revocation each leave no `ak` in `chrome.storage.session`; logout and revocation also remove both tokens. `ownership.spec.ts` checks wiping of intermediates. No test can inspect a JavaScript heap (R-11).                     |
| INV-16 no plaintext at rest                          | Tested                        | The web vault e2e and the extension e2e dump IndexedDB, `chrome.storage.local` / `session` and web storage and scan for every secret; `vault-engine.test.ts`. D-27 reads "persists" as written to persistent storage: `AK` is in `chrome.storage.session` while unlocked.                                                                                                                                                                      |
| INV-17 `SK` alone decrypts nothing                   | Tested                        | Portable check `inv17-secret-key-alone-decrypts-nothing`                                                                                                                                                                                                                                                                                                                                                                                       |
| INV-18 no administrator decryption                   | Structural                    | `apps/api/src/admin/cli.ts` has only `opaque-setup` and `bootstrap-token`; the server holds no key that opens any envelope.                                                                                                                                                                                                                                                                                                                    |
| INV-19 content scripts never get keys                | Tested for the current design | Extension e2e: a content script (isolated world) is refused `chrome.storage.session`, the page's own world has no storage API, the popup never receives the item password, and fills go only to the saved origin; `fill.test.ts`, `origin.test.ts`. There is no persistent content script to test.                                                                                                                                             |
| INV-20 registration closed                           | Tested                        | `auth.int-spec.ts` "refuses registration without a valid bootstrap token…", "creates the account… then closes registration"                                                                                                                                                                                                                                                                                                                    |
| INV-21 OPAQUE setup never stored, logged or returned | Tested                        | `auth.int-spec.ts` "never stores, logs or returns the OPAQUE server setup (INV-21)" (every table, the logs and several responses, in base64url and hex)                                                                                                                                                                                                                                                                                        |
| INV-22 exact crypto pins                             | Tested                        | `packages/crypto/test/versions.spec.ts`                                                                                                                                                                                                                                                                                                                                                                                                        |
| INV-23 single-use protocol state                     | Tested                        | Login, reauth, pairing, recovery completion and bootstrap token as before; refresh tokens: `tokens.int-spec.ts` and the extension e2e (a rotated refresh token presented again revokes the session)                                                                                                                                                                                                                                            |

## 2a. Browser-level evidence added on 2026-10-26, and its limits

Closed (each is a test in `apps/extension/e2e/extension.spec.ts` unless noted):

| Gap                              | What the test shows                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| -------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Extension auto-lock              | An unlock that expired while Chrome had stopped the worker is never resumed; with no message at all, the alarm locks the vault. Writing this test found a defect: the worker recorded activity _before_ checking idleness, so a late alarm let the next message resume an expired unlock. Fixed.                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Worker suspension                | A proven restart (a marker in the old global scope is gone) resumes from `chrome.storage.session` while within the window.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| Navigation during fill           | A fill requested after the tab moved to another origin is refused and nothing is injected; back on the saved origin it works.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| Previous-password unlock         | After `SK` and the password both changed in the web app, the locked extension asks for the previous password, refuses a wrong one, adopts the new keys, and then opens with the new password only.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| Revoked device reconnecting      | A locked extension removed in the web app is wiped (device record, `AK`, both tokens) on its first server contact and must be paired again. Web: the existing vault e2e covers an unlocked browser removed while online.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     |
| Refresh-token reuse              | A copied refresh token presented after the extension rotated it is refused, the session family is revoked, the extension locks, and a `refresh_reuse` event exists.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `storage.session` access         | Refused to a content script; absent from the page's main world.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              |
| Logout                           | Removes `AK` and both tokens and ends the server session. Writing this test found orphaned server sessions after a second sign-in from the same device; a new login now supersedes that device's older sessions (`tokens`/`account-security` integration tests).                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
| Import into a fresh installation | `packages/vault/src/import.test.ts`: a fixed fixture (hand-written expected contents, structure checked without the reader) restores into a new account with new account, vault, key and item ids, revision-1 items in a new chain, only the new device, and nothing of the source on the wire; wrong kit, tampering, other versions, item-count and size limits refused before anything is created; cancelling leaves nothing or an empty account; a dropped connection plus a browser restart, and a lost commit response, each end with every item exactly once. `test:import`: export from A, restore into a separate B, unlock B with its own credentials, A and the file unchanged, wire, console and storage scanned. |
| Encrypted export                 | `vault-engine.test.ts`: round trip onto a device with no account, wrong or mistyped kit, wrong password, and 18 tamperings each refused; web vault e2e: export from Security, opened in a fresh browser context, wrong kit refused, file and request bodies scanned, nothing stored.                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| Fonts                            | The web app no longer fetches Google fonts at build or run time; `security-headers.spec.ts` checks that every font request is to the app's own origin. The export is pixel-identical (compared during the change).                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

Remaining, and why:

- **The race between the worker's last origin check and injection.** The page navigating in that
  millisecond window cannot be timed in a browser test. It is covered by the in-page check
  (`fill.ts` compares `location.origin` before touching any field; `fill.test.ts`).
- **Same-origin frames, Firefox, Safari, packed builds:** not built or not tested.
- **What `chrome.storage.session` does with memory under swap, hibernation or a crash dump** is
  not documented by Chrome and cannot be tested from the extension (D-27 unknown).
- **An offline device** that is never told of its revocation keeps opening its copy with the
  password it knows; this is a stated limit (device-enrollment §6), not a test gap.
- **A malicious or compromised extension update, or another extension with broad host
  permissions on an unlocked browser** (E-06, T-23): outside what tests here can show.
- **The test build** differs from the shipped build only by `__RUVEE_TEST__` (the popup may name
  its target tab) and host permission for `127.0.0.1`; a reviewer should confirm nothing else
  depends on it.

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
11. **Import (backup-restore.md §4.4a)** goes only into a vault that has never held an item and
    has never had an import; it queues every item re-encrypted, as ciphertext, in one IndexedDB
    transaction, uploads through the normal commit path in batches small enough for the 1 MiB
    pending record, and blocks other writes until it is complete. Source tombstones are counted and
    not imported; trashed items stay trashed; created and updated times are kept.
12. **The encrypted export (D-13 A)** carries its own `recoveryKeyId`, freshly generated: devices
    do not learn the server kit's id. The verifier passes every expectation from the file's fields
    and lets the AEADs and `items_digest` reject any difference; it never reads a key id from an
    envelope header.
13. **A login for a known device supersedes that device's older cookie and token sessions**
    (revoke reason `superseded`). Recovery sessions are not affected.
14. **Bearer tokens:** the extension fetches with `credentials: 'omit'`; unauthenticated writes from
    an extension origin pass the CSRF check only if listed in `EXTENSION_ORIGINS` and cookie-less;
    registration and recovery stay web-only.
15. **D-27:** only `AK` (not `VK`) is kept in `chrome.storage.session`; sync-protocol §12 names
    both. Idleness is checked before every message as well as by the alarm.
16. **The extension's popup can only call an allow-listed subset of engine methods**, without
    `secret`; fills happen in the worker.

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
- No new server-visible plaintext. New stored values are the `secret_key_rotated` event type,
  `refresh_tokens` (hashes), the `superseded` revoke reason, and existing columns updated by the
  new endpoints; `migrations.int-spec.ts` still passes.
- **R-18** (a stolen locked device may hold a live session): for the extension, a refresh token
  in its IndexedDB lives up to 90 days; reuse after rotation ends the session, and removal from
  Devices ends it at once.
- **Backups:** a restored database copy brings back removed devices and their sessions
  (`backup-restore.int-spec.ts`); the proposed rule is D-28 ([backup-restore.md](../architecture/backup-restore.md)).

## 4a. Server restore: risks found while preparing M1 (D-28 open)

Characterization tests show what restoring an older database copy does **today**, with no restore
policy (`apps/api/test/backup-restore*.int-spec.ts`, `packages/vault/src/vault-engine.test.ts`
"clients after a server restore"):

| Risk                                                                                                                                  | Evidence                                        | Proposed handling ([backup-restore.md §3.6](../architecture/backup-restore.md#36-recommended-v1-restore-policy-d-28-option-a-as-specified)) |
| ------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| A device removed after the snapshot is active again, with its old session                                                             | Tested                                          | Sessions ended; the owner removes it again (as lost, rotating `SK`)                                                                         |
| A refresh token rotated after the snapshot works again; the newer one is unknown                                                      | Tested                                          | Every session and so every token family ended                                                                                               |
| A recovery session ended after the snapshot works again                                                                               | Tested                                          | Ended with every session                                                                                                                    |
| A snapshot taken before the account existed reopens registration to the holder of its setup token                                     | Tested                                          | Unused setup tokens deleted                                                                                                                 |
| Security events after the snapshot vanish                                                                                             | Tested                                          | A `server_restored` event; older logs are the operator's                                                                                    |
| A password, `SK` or Recovery Kit replaced after the snapshot is the old one again on the server; ending sessions does not change that | Reasoned (§3.4, §3.7); `keyset_rollback` tested | Clients stop; the owner repeats each change                                                                                                 |
| Devices ahead of the snapshot cannot export without the server                                                                        | Code (`exportVault` needs an online step-up)    | Offline encrypted export from the local verified copy                                                                                       |
| A device added after the snapshot becomes an orphan pending device                                                                    | Code (`loginFinish` for an unknown device id)   | Start over on this device, pair again                                                                                                       |
| An interrupted restore could be served half-loaded                                                                                    | Design                                          | New database only, completion marker, API refuses without it                                                                                |
| Old dumps keep old wraps forever                                                                                                      | Design (account-recovery.md §5)                 | Retention guidance; full rotation (Phase 4)                                                                                                 |

For the reviewer: the policy must not be read as making stale decryption or recovery material
current. It only ends authentication state; key material is repeated by the owner (§3.4).

## 5. Scope for the independent review

Concrete areas, in order of risk. This list is what D-19 must cover before real data; none of it
has been reviewed by anyone other than its authors.

1. **Pinned library defect and its containment.** libsodium.js 0.8.4 has V-15:
   `crypto_kdf_derive_from_key` with a subkey length outside 16..64 ignores the C error and returns
   uninitialized WebAssembly heap (in a probe, a previous subkey and earlier plaintext). Ruvee
   contains it in `packages/crypto/src/primitives.ts` by passing only the constant 32 and checking
   it before the call; `v15-defect-present-in-pinned-library` reproduces it and
   `v15-contained-by-wrapper` checks the wrapper. This is containment, not a fix; confirm every
   KDF call goes through the wrapper (`exports.spec.ts` "only src/libsodium.ts imports the
   library") and track upstream libsodium.js#370.
2. **`packages/crypto`** constructions and vectors: `src/operations.ts`, `src/vault-operations.ts`,
   `src/pairing-operations.ts`, `src/envelope.ts`, `test/portable/`.
3. **Pairing** (D-21 requires this review): device-enrollment §3 against
   `packages/vault/src/vault-engine.ts` `pairing*` and `apps/api/src/pairing/`, including the
   platform code in the MAC now that extensions pair (platform 2) and the server's check that a
   request names the requester's own platform.
4. **Recovery and key rotation:** `apps/api/src/recovery/`, `account/account-security.service.ts`,
   and the engine's `recovery*`, `rotateSecretKey`, `kitRotate*`, `adoptServerKeys`,
   `refreshKeyset`, the `previous_password_required` path, and D-24's rotation on lost removal.
5. **Session and token lifecycle:** `apps/api/src/sessions/` (cookie and bearer paths, CSRF with
   `EXTENSION_ORIGINS`), `session.service.ts` `createToken`/`refresh` (rotation, reuse detection,
   concurrent refresh), login superseding older sessions, step-up binding, throttling, and the
   extension's `tokens.ts` and transport refresh-and-retry.
6. **Extension key retention and message boundaries:** `apps/extension/src/background.ts` (D-27:
   `AK` in `chrome.storage.session`, resume, idle check, lock, `forget`), sender checks
   (`sender.id`, `sender.origin`), the schema in `messages.ts`, the method allowlist, and what the
   test build changes.
7. **Autofill origin validation:** `apps/extension/src/origin.ts` (exact origin, HTTPS or loopback,
   userinfo, IDN/trailing dot), `fill.ts` (top frame, visible fields, in-page origin re-check),
   and the worker's re-read of the tab URL before injection.
8. **Sync verification:** `packages/vault/src/sync-logic.ts` and the engine's pull, rebase, push.
9. **Encrypted export format and import** (D-13 A, approved for development only):
   `packages/vault/src/export-file.ts` and the engine's `exportVault`/`exportOpen` against
   backup-restore.md §4: that every field is bound by an existing envelope or `items_digest`, the
   fail-closed order, key wiping, and that the file never leaves the client; for the import,
   `importIntoEmptyVault`, `feedImport` and `finishImport` (the empty-vault rule, the queue and
   completion conditions, and that nothing of the source account is sent).
10. **OPAQUE integration:** `apps/api/src/auth/` and both clients' D-02 configuration.
11. **Web delivery:** CSP and headers, `deploy/Caddyfile`, local fonts, and the trust model of a
    server-served client (D-07, R-01).

Not in scope yet: mobile (Phase 6), full key rotation (Phase 4), server backups (designed in
[backup-restore.md](../architecture/backup-restore.md), blocked on D-28).
