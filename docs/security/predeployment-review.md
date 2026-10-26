# Pre-deployment security review

**This is an AI-assisted code review, not a professional independent security audit. It does
not complete D-19.** It looks for defects before the synthetic private deployment rehearsal.

## 1. What was reviewed

| Item         | Value                                                                                                                                                                                                                                                                                               |
| ------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Commit       | `0617ba16e4554f12143eeb2669006fd3921d004f` (`0617ba1`), branch `vault/web-vault`, clean working tree at the start                                                                                                                                                                                   |
| Date         | 2026-10-26                                                                                                                                                                                                                                                                                          |
| Scope        | `apps/api` (auth, sessions, guard, recovery, pairing, sync, account security, backup, restore, reopening, maintenance, CLI), `packages/crypto`, `packages/vault` (engine, sync logic, store, export and import), `apps/extension`, `apps/web` (worker boundary, headers, build), `deploy/Caddyfile` |
| Out of scope | Mobile (not built), the PostgreSQL server itself, host and TLS hardening, third-party library internals (libsodium.js, `@serenity-kit/opaque`, `age-encryption`) beyond their use                                                                                                                   |

**Method.** I read the review packet, threat model, invariants, ADRs, open decisions and the
specifications. Four reviewers then each read one area's code: auth and sessions; crypto, sync and
storage; pairing, extension and web; backup, restore and reopening. They got only the code and the
specifications, not earlier reports. Every finding below was then either **reproduced by a test
that runs against the real code** (marked _Confirmed, reproduced_), **confirmed by reading the
whole code path** (_Confirmed by reading_), or left as _Plausible_. Claims that did not hold up
were dropped or narrowed (see §6).

**Independence caveat.** The same AI session that wrote most of the backup, restore and
reopening code (D-28, D-29, D-30) ran this review. That is why the area reviews were delegated
without earlier conclusions. The caveat still lowers how much this review is worth for those
areas.

**Reproduction tests.** They are added for this review and not yet committed. Each asserts the
**current** behaviour and is written to fail once its finding is fixed; then it should be turned
into a regression test of the fixed behaviour.

| File                                             | Findings |
| ------------------------------------------------ | -------- |
| `apps/api/test/review/r1-path-case.int-spec.ts`  | R1       |
| `apps/api/test/review/r2-r3-login.int-spec.ts`   | R2, R3   |
| `apps/api/test/review/r7-r8-backup.int-spec.ts`  | R7, R8   |
| `packages/vault/src/review/r5-r6-client.test.ts` | R5, R6   |

They ran against a task-owned PostgreSQL 18 container (`ruvee-task-review-pg`, loopback only,
removed afterwards). The Caddy checks ran in throwaway `caddy:2.11-alpine` (v2.11.7) containers.
Synthetic data only.

## 2. Findings, most severe first

| ID  | Severity                                  | Status                                        | Title                                                                                                     |
| --- | ----------------------------------------- | --------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| R1  | **High** (critical for the restore model) | Confirmed, reproduced                         | A change of case in `/API/` bypasses the maintenance and reopening gate, CSRF checks and bearer parsing   |
| R2  | **High**                                  | Confirmed, reproduced                         | The password plus a known device id gives an active device, and then a lock-out of the owner without `SK` |
| R8  | **High** (conditional)                    | Confirmed, reproduced                         | SQL in a restored dump can open the guard itself; the restore then reports success                        |
| R10 | Medium (deployment)                       | Confirmed, reproduced (Caddy 2.11.7)          | An unset `RUVEE_CSP` gives an empty CSP header (fail-open); unknown paths lack `no-store`                 |
| R7  | Medium                                    | Confirmed, reproduced                         | `?dbname=` in the URL makes `pg_dump` back up a database the synthetic-only check never saw               |
| R9  | Medium                                    | Confirmed by reading                          | VERIFY reads each backup file again by path, so a storage controller can defeat the trusted digest        |
| R5  | Medium                                    | Confirmed, reproduced (engine and FakeServer) | A replayed commit reply lowers the client checkpoint, so a later rollback is accepted (INV-07)            |
| R6  | Medium                                    | Confirmed, reproduced                         | Forgotten-password recovery on an enrolled browser erases its unsynced edits without warning              |
| R3  | Medium                                    | Confirmed, reproduced                         | The per-username login throttle is checked only at `start`; parallel guesses all count                    |
| R11 | Medium                                    | Confirmed by reading                          | Anyone can keep a restored installation closed by using up the reopening code                             |
| R12 | Low                                       | Confirmed by reading                          | Reopening's password path completes without proof of `AK` (same root as R2)                               |
| R13 | Low                                       | Plausible                                     | `restore-reopen-code` can race a reopening's completion                                                   |
| R14 | Low                                       | Confirmed by reading                          | The maintenance gate caches `none` as open, not only `open`                                               |
| R15 | Low                                       | Plausible                                     | With the `docker exec` prefix, killing the client does not stop `pg_restore`; an early exit can hang LOAD |
| R16 | Low                                       | Confirmed by reading                          | The documented 300 requests/min per-session limit does not exist                                          |
| R17 | Low                                       | Confirmed by reading                          | No warning when the proxy address is unset (one global throttle bucket); IPv6 is limited per address      |
| R18 | Low                                       | Confirmed by reading                          | Extension fill checks only the field's own visibility                                                     |
| R19 | Low                                       | Plausible                                     | An extension lock during an in-flight unlock can be undone                                                |
| R20 | Low                                       | Plausible                                     | Recovery on a device that already holds data drops its rollback floors                                    |
| R21 | Low                                       | Plausible                                     | Concurrent pairing creates can exceed `MAX_OPEN_PAIRINGS`                                                 |
| R22 | Low                                       | Confirmed by reading                          | `startOver` ignores the conflict count; `feedImport` can queue duplicates                                 |
| R23 | Info                                      | Confirmed by reading                          | Smaller items (§2.23)                                                                                     |

### R1. A change of case bypasses the maintenance gate, CSRF checks and bearer parsing (High)

- **Where:**
  - `apps/api/src/maintenance/maintenance.service.ts:50` and `:54`
  - `apps/api/src/sessions/access.guard.ts:53` and `:90`
  - Every boundary decision is a case-sensitive `req.path.startsWith('/api/')`.
- **Why it works:**
  - Express 5's router is case-insensitive by default ("case sensitive routing" is never set).
  - `/API/v1/...` and `/Api/v1/...` therefore reach the same handlers with none of those checks.
  - Caddy 2.11.7's `handle /api/*` forwards `/API/`, `/Api/` and even `/%61pi/` to the API. I checked this with a throwaway Caddy container.
  - Percent-encoded, doubled-slash and trailing-slash variants are **not** routed or are still gated. The test asserts this.
- **Preconditions:**
  - A restored installation in `restoring`, `review` or `reopening`.
  - An attacker with the snapshot-time password and an active device's id. Ids are not secret (see R2).
- **Reproduction:**
  - `r1-path-case.int-spec.ts` puts a database in `reopening` with every restored session revoked, then calls `POST /API/v1/auth/login/start` and `/finish`.
  - It gets a full active session. `GET /API/v1/account/keys` returns 200 while the lower-case route returns 503.
  - Revoked restored cookies stay refused.
  - In the open state, `POST /API/v1/auth/logout` succeeds with no `Origin` and no `X-Ruvee-Request`, while the lower-case route is `403 csrf_rejected`.
- **Impact:**
  - Defeats D-28 rules 3 and 4 and D-30 entirely: the backup-time password opens a restored server with no review and no host code. This is exactly the leaked-password case D-30 exists for.
  - In normal operation it removes the Origin and custom-header CSRF checks. `SameSite=Strict` and JSON-preflight still limit this to bodyless same-site requests.
  - It also removes the cookie-xor-bearer rule.
- **Fix:**
  - Enable case-sensitive and strict routing: set it on the Express instance before Nest registers routes.
  - Base the gate and the CSRF and bearer decisions on the matched handler's metadata (controller and `@Access` level), not on URL text.
  - Reject any `/api` path whose lower-case form differs.
  - Add the upper-case cases to the maintenance, reopening and CSRF tests.

### R2. Password plus a known device id gives an active device, then a lock-out without `SK` (High)

- **Where:**
  - `apps/api/src/auth/auth.service.ts:227-275`: `loginFinish` trusts the client-supplied `deviceId`. A known, non-revoked device of the right platform becomes the session's device, with its status.
  - `apps/api/src/account/account-security.service.ts:132-160` (`passwordFinish`) checks the new wrap's header only (`:141`). The kit rotation (`:243`) and reopening completion do the same.
- **Preconditions:**
  - The password (phished, reused or guessed).
  - One active device id. Ids are "server-visible metadata" that may be logged (api-design.md); they are also in database copies, security events and `GET /devices`.
- **Reproduction:** `r2-r3-login.int-spec.ts`.
  1. A client holding no key logs in with `{ username, password, deviceId }` and gets `status: 'active'`.
  2. The full key material is served.
  3. A step-up succeeds.
  4. `password/finish` accepts a wrap whose ciphertext is overwritten with `0x41` bytes. It is no wrap at all.
  5. The owner's password no longer logs in.
- **Impact:**
  - Device enrollment says a password alone yields a _pending_ device that can do nothing until paired (D-04, INV-06). That is not true for known device ids.
  - A password-only attacker gets T-14 powers: lock the owner out of the server copy, rotate the Recovery Kit to garbage, revoke devices, push garbage commits.
  - Decryption still needs `SK`, so the vault contents stay safe, and devices keep their local copies.
  - Each such login also ends the genuine device's sessions as `superseded`.
- **Fix (needs a decision):** bind enrolled devices to a credential issued at enrollment, for example a per-device secret or key whose hash or public key the server stores and checks at login. Otherwise always create a new pending device.
  - Separately, consider a key-confirmation value the server can check on wrap replacement, for example an `AK`-derived verifier, so a session without `AK` cannot replace wraps.
  - Both are protocol changes. Record them as a new decision; do not just add a quick patch.

### R8. SQL inside a restored dump can open the guard (High, conditional)

- **Where:**
  - `apps/api/src/admin/server-restore.ts:350-372`: the guard and code tables are created by the role that then runs `pg_restore`.
  - `server-restore.ts:420`: APPLY POLICY's `UPDATE … SET state = 'review' WHERE state = 'restoring'` does not check that a row changed.
- **Preconditions:** a hostile dump gets restored. That can happen through:
  - `--no-trusted-digest`;
  - the R9 race;
  - a backup made by an already-compromised server, which §3.2a notes the digest cannot catch.
- **Reproduction:** `r7-r8-backup.int-spec.ts`. The source database has a table whose CHECK constraint calls a plpgsql function. While `pg_restore` copies rows, inside the restore's own transaction, that function runs `UPDATE public.ruvee_restore_guard SET state = 'open'`. `restoreBackup` reports success, and the guard is `open`: no review, no reopening code.
- **Impact:** §3.2b already says a decrypted dump is trusted SQL. It does not say the restore's own safety state can be rewritten by that SQL. A hostile backup turns into an instantly open installation.
- **Fix:**
  - Create the guard and code tables owned by a different role than the one `pg_restore` connects as, or `REVOKE` write access from it.
  - Schema-qualify them.
  - After LOAD and MIGRATE, re-read the guard and require `state = 'restoring'` with the expected `restore_id`.
  - Require `rowCount === 1` on every guard transition.
  - Keep the non-superuser restore role of §3.2b, and add that the restore role must not own the guard.

### R10. An unset `RUVEE_CSP` gives an empty CSP header; unknown paths lack `no-store` (Medium, deployment)

- **Where:** `deploy/Caddyfile:32` (`Content-Security-Policy {$RUVEE_CSP}`) and `:42-46`.
- **Reproduction:** with `RUVEE_CSP` unset, `caddy adapt` produces `"Content-Security-Policy":[""]`, and responses carry an empty header, which is no policy at all. This was run against the repository Caddyfile on Caddy 2.11.7 serving `apps/web/out`.
  - `/no-such-page` returns 200 with no `Cache-Control`, and so do the RSC payloads `index.txt` and `__next.*.txt`.
  - The header tests run against `scripts/serve-export.mjs`, which sends `no-store` and real 404s, so they don't describe Caddy.
- **Impact:** a deployment that forgets the variable has no CSP. That removes the main mitigation for T-18 (XSS while unlocked).
- **Fix:**
  - Fail closed: refuse to start without the variable, or use `{$RUVEE_CSP:default-src 'none'}`.
  - Apply `no-store` to everything except `/_next/static/*`.
  - Serve real 404s.
  - Generate the header block from `security-headers.ts`; the Permissions-Policy is a hand copy.
  - Add a Caddy-based header test to the rehearsal checklist.

### R7. `?dbname=` bypasses the synthetic-only backup check (Medium)

- **Where:**
  - `apps/api/src/admin/server-restore.ts:127-128` checks the URL **path**.
  - `apps/api/src/admin/pg-tools.ts:46-52` passes the whole URL, query included, to `pg_dump`, and libpq honours `dbname` in the query.
- **Reproduction:** `r7-r8-backup.int-spec.ts`. A URL whose path is a migrated `ruvee_it_*` database and whose query is `?dbname=review_r7_not_synthetic` produces a backup of the non-synthetic database. Its marker table is in the decrypted dump, and the Ruvee tables are not.
- **Impact:**
  - The control that keeps real data out of M1 can be bypassed by accident or on purpose.
  - The same split applies to `RESTORE_DATABASE_URL`: the guard and the data can land in different databases, and then the gate reads `none`, which counts as open.
- **Fix:** parse once and refuse any query parameter, or an allowlist such as `sslmode`, and pass libpq an explicit `dbname` equal to the checked name. Apply the same to the restore URL. Add tests.

### R9. VERIFY reads each file again by path (Medium)

- **Where:** `apps/api/src/admin/backup-files.ts`:
  - `:309` hashes the meta and dump files by path.
  - `:317` reads the meta again to decrypt it.
  - `:331` opens the dump again for `verifyDump` and again for LOAD.
  - `:202` (`lstat`) and `:237`/`:277` read the identity and manifest after a separate `lstat`.
- **Precondition:** the backup storage is controlled by the attacker during the restore. This is the adversary the trusted digest exists for, for example a network mount that serves different bytes on the second read.
- **Path:** the genuine meta is hashed, then a forged meta (encrypted to the public recipient) is decrypted. It vouches for a forged dump, which can also carry R8's SQL.
- **Impact:** the trusted-digest check, §3.2a's only provenance control, can be defeated.
- **Fix:**
  - Open each file once with `O_NOFOLLOW` and `fstat` the descriptor.
  - Read the meta into memory and hash and decrypt those same bytes.
  - Hash the dump ciphertext in the same stream that is decrypted, in both passes, and compare it with the manifest.
  - Copy the set into a private staging directory first if needed.

### R5. A replayed commit reply lowers the client checkpoint (Medium)

- **Where:** `packages/vault/src/vault-engine.ts:3228-3257`. `push()` takes `{ seq }` from the commit response unchecked and sets `checkpoint.seq` to it, overlaying the in-flight mutations on `synced`. `pull()` never reconciles the in-flight commit.
- **Reproduction:** `r5-r6-client.test.ts`.
  1. Device A's commit is applied but its reply is dropped.
  2. B commits on top.
  3. A syncs. Its pull verifies B's commit, then the retried commit's idempotent reply (`seq` = A's old one) becomes the checkpoint. A shows its own older edit.
  4. The server then removes B's commit, and A reports `synced` with no integrity error.
- **Impact:**
  - A malicious server can hide a change the device already verified, such as a rotated password, which defeats INV-07 for that device.
  - With an honest server the view is stale until the next pull. A local export made in that window is stale too.
- **Fix:**
  - Never let the checkpoint `seq` decrease.
  - Accept a commit reply only if `seq === inflight.body.baseSeq + 1`; otherwise reconcile.
  - Have `pull()` clear the in-flight commit when the verified chain contains its manifest hash or `commitId`.
  - Add a two-device lost-reply test.

### R6. Recovery on an enrolled browser erases its unsynced edits (Medium)

- **Where:** `packages/vault/src/vault-engine.ts:1884` keeps the device id for the same username, and `:2205` (`recoveryFinish`) calls `store.wipe()`, which deletes `pending`, `conflicts` and the checkpoint. The lock screen offers "Use your Recovery Kit" (`apps/web/src/components/app/vault-app.tsx`).
- **Reproduction:** `r5-r6-client.test.ts`. An offline edit exists only in the browser's store; the test checks the server never received it and an offline unlock shows it pending. Recovery on the same browser ends with only the synced item and `pendingCount: 0`. No warning is shown.
- **Impact:** silent loss of user data. Compare `startOver`, which requires an export or typed confirmation.
- **Fix:** recovery yields the same `AK`, so the local `pending` and `conflicts` records can be opened and kept, then rebased after the genesis pull. At minimum, count them and require an export or acknowledgement first.

### R3. Login throttle checked only at `start` (Medium)

- **Where:** `apps/api/src/auth/auth.service.ts:203` checks; `:227-240` (finish) never checks `blockedUntil`. The same applies to reauth (`:313` and `:340`) and reopening (`reopen.service.ts`).
- **Reproduction:** `r2-r3-login.int-spec.ts`. Twelve starts issued before any failure, then twelve finishes: all twelve are evaluated (401), none is refused (429), and a new start is already blocked. The per-IP window is reset between requests, as a few addresses would give.
- **Impact:** guesses are bounded by parallelism times the number of addresses, not by the documented 5-then-delay schedule. T-15 is weaker than documented.
- **Fix:** check `blockedUntil` in every finish before running `finishLogin`. Limit concurrent pending login states per username in `LoginStateStore`.

### R11. Anyone can keep a restored installation closed (Medium, availability)

- **Where:** `apps/api/src/reopen/reopen.service.ts:75-90`: a wrong code counts a failure on **every** usable code, and five revoke it. `:207` records a recovery attempt before checking the code, which uses up the owner's 5-per-hour recovery budget.
- **Impact:** anyone who can reach the API can keep a restored server closed and force the host to keep reissuing codes. The tests assert this behaviour ("revokes a code after five failures").
- **Fix:** with 256-bit codes a wrong code tells an attacker nothing. Throttle wrong codes per IP, count failures only against the presented code (right code, wrong credentials), and check the code before recording a recovery attempt.

### R12–R22. Low

- **R12. Reopening's password path completes without proof of `AK`** (`reopen.service.ts:294-330`, header checks only). Whoever holds the code, the old password and a device id can install their own password and junk wraps, locking the owner out. The code is host-issued, and the host holder is the owner in this model, so this is low here. It has the same root and fix as R2.
- **R13. `restore-reopen-code` racing completion.**
  - `complete` authenticates the reopen session before its transaction. Inside it, it checks only that the linked code has `revoked_at IS NULL` (`reopen.service.ts:319`).
  - `issueCode` (`server-restore.ts:589-605`) revokes only unconsumed codes and does not lock the guard row. A host revocation committed in between is ignored.
  - Fix: re-check the session `FOR UPDATE` inside the transaction; have `issueCode` lock the guard row and revoke consumed codes too.
- **R14. The gate caches `none` as open** (`maintenance.service.ts:39`). An API that touched the target database before PREPARE stays open after the guard appears. The specification says only `open` is cached. Fix: cache only `open`.
- **R15. `docker exec` kill and an early pg_restore exit** (`pg-tools.ts:85`, `server-restore.ts:293-296`).
  - Killing the `docker exec` client gives `pg_restore` inside the container a clean EOF, contrary to the comment on `load`.
  - If `pg_restore` exits 0 early, the drain wait never settles.
  - The guard still keeps the database closed, so only defence in depth is lost. Fix: race drain against `done`, and document the prefix limitation.
- **R16. No per-session request limit** (authentication.md §7 lists 300/min/session). Not implemented.
- **R17. Proxy and IP keying** (`sessions/client-info.ts`). Behind Caddy without `TRUSTED_PROXY_ADDRESS`, every client is 127.0.0.1, so one attacker exhausts the global 20/min auth budget. Nothing warns. IPv6 is limited per address, not per /64.
- **R18. Extension fill visibility** (`apps/extension/src/fill.ts:13-22`). Only the element's own style is checked: an ancestor with `opacity:0`, off-screen or clipped fields pass. Precondition: HTML injection on the exact saved origin, and a user click on Fill.
- **R19. Extension lock race** (`apps/extension/src/background.ts:113`, `:136-147`, `:266`). An `ended` lock during an in-flight `unlock` can be followed by `rememberUnlocked` writing `AK` back. It self-corrects on the next sync. Fix: a lock generation counter or one serialized queue.
- **R20. Recovery on a device with data drops rollback floors** (`vault-engine.ts:1914-1937`, `:2205-2212`). It accepts any keyset version and resets the checkpoint to 0, so an old keyset or state could be re-served to a device that knew better.
- **R21. Pairing open-count race** (`apps/api/src/pairing/pairing.service.ts:51-81`). Count then insert at READ COMMITTED. It bypasses a rate limit only for an already active device.
- **R22. `startOver` and `feedImport`.**
  - `startOver` checks only `pendingSeen` (`vault-engine.ts:2900`), so conflict drafts are erased uncounted.
  - `feedImport` (`:2970`) can queue a batch while `pending` is non-empty, which produces spurious self-conflicts. No loss.

### R23. Info

- `EXTENSION_ORIGINS` passes CSRF for every `none`-level route, not only `login` and `refresh` (`access.guard.ts:67-72`).
- The empty-target check counts only `pg_tables` (`server-restore.ts:349`): functions, types, views and other schemas pass.
- The API queries the guard tables unqualified, so they resolve via `search_path`.
- Key zeroing gaps: `wipeMemory` does not clear `this.recovery` or `kitRotation`, and some `openKeyset` failure paths leave `AK` unwiped. This is best effort under INV-15.
- Pairing:
  - the approval sends no device `label` (the specification does);
  - `requestedAt` is not covered by the request MAC;
  - a malformed `epk` or platform from the server is not burned and leaves no `pairing_mac_failed` event.
- extension-design.md says messages with `sender.tab` are dropped; the code checks `sender.id` and `sender.origin` (sufficient). The document should change, not the code.
- The test servers (`serve-export.mjs`) forward client `X-Forwarded-For` and crash on a malformed `%` escape. They are not used in production.

## 3. Invariants checked, and how

| Invariant                                    | Result                                                                                                          | How                                                                                                                                                                                         |
| -------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| INV-01, INV-10 server never receives secrets | Held                                                                                                            | Request schemas and controllers read; the existing sentinel scan of a decrypted dump (`backup-confidentiality.int-spec.ts`) re-read                                                         |
| INV-02, INV-03, INV-04 envelopes             | Held                                                                                                            | `packages/crypto` read: fresh CSPRNG nonce, AAD rebuilt from expectations, typed fail-closed errors; crypto suite run                                                                       |
| INV-05 KDF profiles                          | Held                                                                                                            | Registry read; unknown profiles refused before any library call                                                                                                                             |
| V-15 containment                             | Held                                                                                                            | The only libsodium import is `packages/crypto/src/libsodium.ts`; no direct use in `apps/` or `packages/vault` source. The lint boundary is missing in `packages/vault` and `apps/api` (gap) |
| INV-06 session alone never grants decryption | Held for decryption; **enrollment claim broken (R2)**                                                           | R2 reproduction                                                                                                                                                                             |
| INV-07 verify before applying                | **Broken for a device after a lost commit reply (R5)**                                                          | R5 reproduction                                                                                                                                                                             |
| INV-08 no silent overwrite                   | Held in `rebase`; R5 overlays an older own edit                                                                 | Code read, R5                                                                                                                                                                               |
| INV-09 keyset never lower                    | Held on refresh; recovery resets the floor (R20)                                                                | Code read                                                                                                                                                                                   |
| INV-12 no secrets in logs, URLs, errors      | Held                                                                                                            | Log serializers, exception filter and env errors read; the reopening code is in bodies and component state only                                                                             |
| INV-13 token hashing and cookies             | Held                                                                                                            | Session service read                                                                                                                                                                        |
| INV-14 step-up                               | Held in code; three endpoints untested when stale (gap)                                                         | Code read                                                                                                                                                                                   |
| INV-15 lock drops keys                       | Best effort; gaps (R23) and R19                                                                                 | Code read                                                                                                                                                                                   |
| INV-16, INV-17 client storage                | Held                                                                                                            | Store contents read (`SK` is the documented exception)                                                                                                                                      |
| INV-18 no admin decryption                   | Held                                                                                                            | The CLI has no decrypting command; backups use the owner's identity offline                                                                                                                 |
| INV-19 content scripts                       | Held; R18 weakens "visible field"                                                                               | Code read                                                                                                                                                                                   |
| INV-20 bootstrap                             | Held                                                                                                            | Advisory lock and atomic consumption read                                                                                                                                                   |
| INV-21 OPAQUE setup                          | Held                                                                                                            | Never in the database or dump; the existing `backup-confidentiality.int-spec.ts` scan                                                                                                       |
| INV-22 pinned crypto deps                    | Held                                                                                                            | Exact pins and lockfile                                                                                                                                                                     |
| INV-23 single-use state                      | Held for login, recovery, reopening and pairing within one process; concurrency tests missing for pairing (gap) | Code read; reopening concurrency is tested                                                                                                                                                  |
| D-28/D-30 closure (§3.6, §3.13)              | **Broken (R1, R8)**                                                                                             | R1 and R8 reproductions                                                                                                                                                                     |

## 4. Coverage gaps (tests that do not enforce what is claimed)

- Every maintenance, reopening and CSRF test uses lower-case paths only (R1).
- `auth.int-spec.ts` asserts a known device id yields an active device (R2 as intended behaviour). No test asks for proof of possession.
- The throttle tests are sequential (R3). Reauth and reopening throttling are untested.
- The lost-reply engine test uses one device (R5). Recovery is tested only on a new device (R6, R20).
- The LOAD-failure test only flips a byte. It never substitutes a validly encrypted dump, adds padding, or swaps the meta between hash and read (R8, R9).
- The forged-set test uses a set that stays the same between reads (R9).
- Nothing races `issueReopenCode` against completion (R13), or runs parallel reopen finishes (R3).
- The synthetic-only test checks the name, not the effective connection target (R7).
- The header tests run against `serve-export.mjs`, not Caddy (R10).
- There is no test of the 300/min per-session limit (R16), of `clientIp` behind a proxy, or of extension sender filtering. There are no concurrent pairing request or approve tests, no server-swapped pairing `platform` or device id, and no hidden-ancestor fill.
- The INV-16 IndexedDB scan runs only in a clean synced state.

## 5. Untested areas and limitations

- **Not a professional audit.** AI-assisted, with the independence caveat in §1. D-19 remains open.
- **Not run:**
  - the extension against hostile pages in a real browser (only unit tests and the existing e2e);
  - Safari; fuzzing; load or denial-of-service testing; TLS and host hardening;
  - a real multi-instance deployment. `LoginStateStore` and the in-memory IP windows are single-process by design.
- **Not reviewed:** library internals (libsodium.js, OPAQUE, `age-encryption`); the PostgreSQL role setup of a deployment, which doesn't exist yet.
- **Partly verified:**
  - R9 and R15 are confirmed by reading only. Reproducing R9 needs a file system that changes between reads.
  - R13, R19, R20 and R21 are plausible.
  - R5 is reproduced against the in-memory FakeServer, whose idempotent replay follows sync-protocol §4.2, not against the real API.

## 6. Claims narrowed or dropped during verification

- **R1, narrowed.** A reviewer reported that restored _cookies_ work through `/API/`. In a real restore those sessions are revoked, and the reproduction shows they stay refused. The real path is the snapshot-time **password** plus a device id.
- **R1, variants.** Only case variants bypass the gate. Percent-encoded, doubled-slash and trailing-slash paths do not.
- **R3, narrowed.** In the first run the per-IP limit (20/min) masked the issue. The finding is about the per-username limit when several addresses are used.
- **R6, narrowed.** Not reproducible while the browser stays unlocked online, because the edit uploads first. It reproduces for the realistic case: locked, edit never uploaded, recovery from the lock screen.

## 7. Prioritized remediation plan

**Before the synthetic rehearsal (P0):**

1. **R1:** case-sensitive and strict routing, with metadata-based gate and CSRF decisions. Add upper-case tests to every gate and CSRF test.
2. **R8:** guard tables not writable by the restore role, guard re-read after LOAD and MIGRATE, row-count checks on every transition.
3. **R7:** refuse URL query parameters in backup and restore URLs; use an explicit `dbname`.
4. **R10:** fail-closed CSP in Caddy, `no-store` on everything except hashed assets, real 404s, and a Caddy-based header check in the rehearsal.

**Before any real data (P1):**

5. **R2 and R12:** device credential at enrollment and key-confirmation for wrap replacement. Needs a decision, probably a new D-number, and a review.
6. **R9:** single-open, descriptor-bound verification with ciphertext hashed in the decryption stream.
7. **R5:** monotonic checkpoint and commit-reply reconciliation.
8. **R6 and R20:** keep local edits and floors through recovery, or require an export first.
9. **R3, R11, R16, R17:** check the throttle at finish, per-IP wrong-code limits, the per-session limit, and a proxy configuration warning.
10. **R13, R14, R15:** reopening transaction re-checks, cache only `open`, and LOAD termination.

**Later (P2):** R18, R19, R21, R22, the R23 items, and the coverage gaps of §4.

## 8. Can a synthetic private deployment rehearsal proceed?

**Not yet. It can, after the P0 items (R1, R7, R8, R10) are fixed and their tests pass, under
these conditions:**

- synthetic data and synthetic identities only, with `--synthetic-test-only` still enforced;
- a private network or loopback only, with no internet exposure, so R2, R3 and R11 cannot be reached by outsiders;
- `TRUSTED_PROXY_ADDRESS` set for the Caddy in front (R17), and the CSP checked on the actual Caddy;
- restores only from backups made during the rehearsal, with the trusted digest (never `--no-trusted-digest`), from local storage the operator controls (R9);
- the restore run by a non-superuser role that does not own the guard tables (R8, §3.2b);
- R2, R3, R5, R6, R9 and R11 recorded as known open issues in the rehearsal plan.

Real-data use stays blocked by the P1 items and by D-19.
