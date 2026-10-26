# Pre-deployment security review

**This is an AI-assisted code review, not a professional independent security audit. It does
not complete D-19.** It looks for defects before the synthetic private deployment rehearsal.

> **Remediation (2026-10-26):** milestone 1 fixed R1, R7, R8, R9 and R10 (§9); milestone 2 fixed
> R3, R5, R6, R11, R13, R14, R15, R16, R17 and R20 (§10); the D-31 milestone fixed R2 and R12
> with device proof of possession (§11); the final batch fixed R18, R19, R21, R22 and every R23
> item but one (§12). Their reproductions are now regression tests. **Open:** R23's device-label
> item (needs a decision). D-31's protocol is unreviewed, D-19 is open and real-data use stays
> blocked. §12 has the disposition of all 23 findings.

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

| ID  | Severity                                  | Status                              | Title                                                                                                     |
| --- | ----------------------------------------- | ----------------------------------- | --------------------------------------------------------------------------------------------------------- |
| R1  | **High** (critical for the restore model) | **Fixed** (509b092); §9             | A change of case in `/API/` bypasses the maintenance and reopening gate, CSRF checks and bearer parsing   |
| R2  | **High**                                  | **Fixed** (a98e299, e62a198); §11   | The password plus a known device id gives an active device, and then a lock-out of the owner without `SK` |
| R8  | **High** (conditional)                    | **Fixed** (5bc18cd, 40dc0bc); §9    | SQL in a restored dump can open the guard itself; the restore then reports success                        |
| R10 | Medium (deployment)                       | **Fixed** (bfb248a), real Caddy; §9 | An unset `RUVEE_CSP` gives an empty CSP header (fail-open); unknown paths lack `no-store`                 |
| R7  | Medium                                    | **Fixed** (4367db9); §9             | `?dbname=` in the URL makes `pg_dump` back up a database the synthetic-only check never saw               |
| R9  | Medium                                    | **Fixed** (e8259da); §9             | VERIFY reads each backup file again by path, so a storage controller can defeat the trusted digest        |
| R5  | Medium                                    | **Fixed** (40a6cf4); §10            | A replayed commit reply lowers the client checkpoint, so a later rollback is accepted (INV-07)            |
| R6  | Medium                                    | **Fixed** (a916561); §10            | Forgotten-password recovery on an enrolled browser erases its unsynced edits without warning              |
| R3  | Medium                                    | **Fixed** (b990cd0); §10            | The per-username login throttle is checked only at `start`; parallel guesses all count                    |
| R11 | Medium                                    | **Fixed** (56eef75); §10            | Anyone can keep a restored installation closed by using up the reopening code                             |
| R12 | Low                                       | **Fixed** (a98e299, e62a198); §11   | Reopening's password path completes without proof of `AK` (same root as R2)                               |
| R13 | Low                                       | **Fixed** (233333d); §10            | `restore-reopen-code` can race a reopening's completion                                                   |
| R14 | Low                                       | **Fixed** (d239bb5); §10            | The maintenance gate caches `none` as open, not only `open`                                               |
| R15 | Low                                       | **Fixed** (6ed27df); §10            | With the `docker exec` prefix, killing the client does not stop `pg_restore`; an early exit can hang LOAD |
| R16 | Low                                       | **Fixed** (417acfe); §10            | The documented 300 requests/min per-session limit does not exist                                          |
| R17 | Low                                       | **Fixed** (417acfe); §10            | No warning when the proxy address is unset (one global throttle bucket); IPv6 is limited per address      |
| R18 | Low                                       | **Fixed** (e67266f, 773626b); §12   | Extension fill checks only the field's own visibility                                                     |
| R19 | Low                                       | **Fixed** (56731e2, 773626b); §12   | An extension lock during an in-flight unlock can be undone                                                |
| R20 | Low                                       | **Fixed** (a916561); §10            | Recovery on a device that already holds data drops its rollback floors                                    |
| R21 | Low                                       | **Fixed** (5d1f571); §12            | Concurrent pairing creates can exceed `MAX_OPEN_PAIRINGS`                                                 |
| R22 | Low                                       | **Fixed** (56731e2); §12            | `startOver` ignores the conflict count; `feedImport` can queue duplicates                                 |
| R23 | Info                                      | 9 of 10 fixed; 1 open; §12          | Smaller items (§2.23)                                                                                     |

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
- **Remediation (509b092):**
  - Express runs with `case sensitive routing` and `strict routing` (`createHttpAdapter()` in
    `configure-app.ts`, used by `main.ts` and the test app), so `/API/…`, `/api/V1/…` and
    `/api/…/` match no handler.
  - Enforcement no longer reads the URL. Each handler has a route class (`@RouteClassOf`:
    `api` by default, `recovery`, `reopen`, `health`). The guard runs the maintenance gate for
    the matched class (default deny: closed states serve only `health`, and `reopening` also
    `reopen`), then the CSRF checks and the cookie-xor-bearer rule on **every** non-health
    route. `REOPEN_PREFIX` and the `/api/` prefix tests are gone.
  - Caddy refuses any other spelling of `/api` with 404 (`@apiSpelling`), as a second layer; the
    API does not depend on it.
  - **Regression:** `r1-path-case.int-spec.ts` (reopening state, revoked restored sessions): nine
    spellings of the keys route (upper and mixed case, `%61pi`, `%41PI`, trailing slash, double
    slash, `%2F`) get 404 or 503, never 200; `POST /API/…/login/start` and `/finish` create no
    session; health spellings other than the real one are 404; in the open state a CSRF-less
    write under any routable spelling is 403 or 404, and cookie plus bearer is 400. Through real
    Caddy (`check-caddy.mjs`) eleven spellings get 404, the real keys route `503 reopening`, and
    the reopening route is served.
  - **Residual:** a new controller without `@RouteClassOf` is gated like any API route (safe
    default); a new exception must be added deliberately. Unit tests now send the CSRF headers
    on test-only POSTs.

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
- **Fixed (§11):** D-31 option A. A known device id now gives a pre-proof session limited to an allowlist; acting as the device needs its Ed25519 key, and wrap replacement also needs an `AK`-derived proof checked against the stored `AVPK`. Step 4 of the reproduction now fails at step-up.

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
- **Remediation (5bc18cd, 40dc0bc):**
  - The guard and reopening codes moved to the schema `ruvee_control`, owned by the restore's
    admin role, with nothing granted to PUBLIC and never included in a backup
    (`restore-control.ts`). All API queries are schema-qualified.
  - `pg_restore` connects as a per-restore loader role (`ruvee_loader_<16 hex>`, random
    password, `NOINHERIT`, no superuser, createdb, createrole, replication or bypassrls) with
    only `CONNECT` and `USAGE, CREATE` on `public`; PUBLIC loses its database privileges. The
    dump's SQL therefore cannot read, write or shadow the control schema, whatever it executes.
  - After LOAD, an allowlist check refuses every object Ruvee does not create (functions,
    triggers, rules, views, policies, event triggers, extensions, other schemas, other relation
    kinds and types, collations, operators, text search objects, foreign servers, publications,
    large objects, row security, unknown or missing tables). The loader's objects are then
    reassigned and the role dropped, in a `finally`. Guard transitions lock the row and require
    one changed row.
  - **Regression:** `r7-r8-backup.int-spec.ts`: the original hostile CHECK constraint now fails
    LOAD (the loader has no access to `ruvee_control`), and the guard stays `restoring`. Eight
    planted objects (a function, a trigger on `sessions`, a view, a rule, another schema, a
    `public.restore_guard` shadow table, a domain, row security) are each refused at LOAD with
    the guard `restoring` and the loader role dropped.
  - **Residual:** see backup-restore.md §3.2b, "Still possible with a hostile dump": denial of
    service during LOAD, anything the loader may do in `public` while loading (examined
    afterwards), and wrong but well-formed rows. A LOAD killed outright can leave its loader
    role; its name is in the guard row and the operator guide says how to drop it. The admin
    role needs `CREATEROLE`.

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
- **Remediation (bfb248a):**
  - The web build writes `apps/web/out-caddy/security-headers.caddy` from the exported HTML
    (script hashes) and `security-headers.ts` (every other header). It refuses an empty or
    weakened CSP (`cspProblems`: `default-src 'none'`, a script hash, `frame-ancestors 'none'`,
    no `'unsafe-inline'`/`'unsafe-eval'`, nothing Caddy cannot quote) and refuses the diagnostic
    export, so the probe build can never produce production headers.
  - `deploy/Caddyfile` imports the snippet for normal responses and again in `handle_errors`
    (Caddy resets headers on errors). A missing snippet is a startup error; `RUVEE_CSP` no
    longer exists. Unknown paths are real 404s with the export's 404 page; `no-store` replaces
    (not adds to) the API's own value; only `/_next/static/*` is cacheable.
  - **Regression:** `apps/api/scripts/check-caddy.mjs` (`test:caddy`), real Caddy 2.11.7 in a
    task-owned container in front of the built API: Caddy without the snippet refuses to start
    ("File to import not found"); the generator refuses the diagnostic export and leaves the
    snippet unchanged; `/`, `/index.html`, an RSC payload, two unknown paths, a hashed chunk and
    an API response each carry exactly this build's CSP, every static header, no `Server`, and
    the right single `Cache-Control`; unknown paths are 404. 87 checks. Unit tests cover each
    `cspProblems` refusal and that the Caddyfile carries no header values or environment
    fallback.
  - **Residual:** HSTS must still be added by hand for public HTTPS; `out/` and `out-caddy/`
    must be deployed from the same build (documented).

### R7. `?dbname=` bypasses the synthetic-only backup check (Medium)

- **Where:**
  - `apps/api/src/admin/server-restore.ts:127-128` checks the URL **path**.
  - `apps/api/src/admin/pg-tools.ts:46-52` passes the whole URL, query included, to `pg_dump`, and libpq honours `dbname` in the query.
- **Reproduction:** `r7-r8-backup.int-spec.ts`. A URL whose path is a migrated `ruvee_it_*` database and whose query is `?dbname=review_r7_not_synthetic` produces a backup of the non-synthetic database. Its marker table is in the decrypted dump, and the Ruvee tables are not.
- **Impact:**
  - The control that keeps real data out of M1 can be bypassed by accident or on purpose.
  - The same split applies to `RESTORE_DATABASE_URL`: the guard and the data can land in different databases, and then the gate reads `none`, which counts as open.
- **Fix:** parse once and refuse any query parameter, or an allowlist such as `sslmode`, and pass libpq an explicit `dbname` equal to the checked name. Apply the same to the restore URL. Add tests.
- **Remediation (4367db9):**
  - One parser (`db-target.ts`) refuses query parameters, fragments and several hosts in backup
    and restore URLs. node-pg gets an explicit config (with `options` fixed), the tools get
    libpq keyword conninfo with an explicit `dbname`, and their environment is stripped of every
    `PG*` variable; the CLI also clears them at start.
  - Every connection checks `current_database()` and `current_user` against the parsed target
    before use. The backup also reads the database name from `pg_dump`'s own archive header and
    holds back every byte until it matches, so a redirected tool publishes nothing.
  - **Regression:** `r7-r8-backup.int-spec.ts` with a non-synthetic fixture named
    `ruvee_production_like_r7` (created and dropped in the task container): five query overrides
    (`dbname`, `service`, `options`, `host`, `sslmode`), a fragment and a second host are refused
    before connecting, with nothing written; inherited `PGDATABASE`, `PGOPTIONS`, `PGSERVICE`
    are ignored and the dump is of the checked database; a `pg_dump` redirected to the other
    database fails with nothing published; a restore URL with `?dbname=` is refused and the
    other database is untouched.
  - **Residual:** the synthetic-only rule is still a name rule (`ruvee_it_*`, `ruvee_e2e_*`) on
    the database actually reached; it does not prove the contents are synthetic.

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
- **Remediation (e8259da):**
  - Each source file (manifest, metadata, dump, identity) is opened once with `O_NOFOLLOW`;
    type and size come from `fstat` of that descriptor. The manifest and metadata are read into
    memory, and the same bytes are hashed, compared and decrypted.
  - The encrypted dump is copied once from its descriptor into a private `mkdtemp` directory
    (0700, `--staging-dir` or the system temporary directory) while its SHA-256 is computed and
    compared with the manifest. VERIFY and LOAD read only that copy, and each pass hashes the
    ciphertext again (against the manifest) and the plaintext (against the metadata) in the
    decryption stream; `pg_restore`'s input is closed only when both match. No plaintext is
    written; the staging directory is removed in a `finally`.
  - **Regression:** `r9-verified-bytes.int-spec.ts` (10 tests), with a test hook at each open:
    a symbolic link in place of the manifest, metadata, dump or identity is refused; a forged
    metadata or dump renamed into place just before it is read is refused; a dump replaced by a
    link just before opening is refused; replacing the whole source set in place and by rename
    after it was read has no effect and the genuine data is restored; changing the staged copy
    after VERIFY fails LOAD with the guard `restoring`.
  - **Residual:** a process running as the same OS user can still change the staged copy; that
    is detected (LOAD fails), not prevented. A failed copy needs space for one ciphertext.

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
- **Remediation (40a6cf4):** a pull whose verified chain contains the in-flight commit's
  manifest hash clears it (it landed; only its reply was lost), so it is not resent. A commit
  reply moves the checkpoint only if the commit was built on the current checkpoint and the reply
  is exactly the next seq; anything else is the integrity error `stale_commit_reply`. The
  checkpoint never decreases.
  - **Regression:** `r5-r6-client.test.ts`: the review's two-device lost-reply sequence now ends
    at B's seq with B's edit shown, and the later rollback is `integrity_error`/`server_behind`
    (before: A's old seq, A's edit, `synced`); the same across a restart with the commit
    persisted in flight; a reply for an older seq is refused and the checkpoint kept; and with
    syncs, saves and B's commits interleaved, the checkpoint read on every engine event never
    decreases (before: 4 → 3 inside one sync).
  - **Residual:** freeze and fork stay as documented (sync-protocol §Limits, D-14).
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
- **Remediation (a916561):** on a browser holding this account's vault (same account,
  device and vault under the same `AK`), recovery keeps its synced records, pending edits,
  conflicts, import state, checkpoint and anchor, replaces only the password wrap, salt and
  keyset, and says what it kept. A browser holding another account's vault (another username, or
  the same name on another server) is never erased without an explicit confirmation that says its
  unsynced changes are lost from this browser (`local_data_other_account`).
  - **Regression:** `r5-r6-client.test.ts`: the review's sequence now ends with both items and
    `keptLocal: { pending: 1 }`, and the edit is uploaded by the first sync; an offline edit that
    meets a newer server change is kept as a conflict; both other-account cases refuse, leave the
    first account's pending edit intact, and erase only after `replaceLocalData`. Browser:
    `e2e-vault/two-devices.spec.ts` adds an offline note on A, forgotten-password recovery from
    A's own lock screen, the "kept its own copy … 1 change not yet uploaded" notice, and the note
    arriving on C.
  - **Residual:** a browser whose own records cannot be opened with the recovered `AK` (a future
    full rotation) falls under the other-account rule: replaced only with confirmation.

### R3. Login throttle checked only at `start` (Medium)

- **Where:** `apps/api/src/auth/auth.service.ts:203` checks; `:227-240` (finish) never checks `blockedUntil`. The same applies to reauth (`:313` and `:340`) and reopening (`reopen.service.ts`).
- **Reproduction:** `r2-r3-login.int-spec.ts`. Twelve starts issued before any failure, then twelve finishes: all twelve are evaluated (401), none is refused (429), and a new start is already blocked. The per-IP window is reset between requests, as a few addresses would give.
- **Impact:** guesses are bounded by parallelism times the number of addresses, not by the documented 5-then-delay schedule. T-15 is weaker than documented.
- **Fix:** check `blockedUntil` in every finish before running `finishLogin`. Limit concurrent pending login states per username in `LoginStateStore`.
- **Remediation (b990cd0):** every password check (login, step-up and reopening finish) reserves
  its attempt in one SQL statement that counts it, sets the delay its count implies and refuses
  while a delay is in force; recovery and bootstrap attempts are reserved the same way against
  their hourly bounds. The reservation, not the count of pending login states, is the bound.
  - **Regression:** `r2-r3-login.int-spec.ts`, through the documented topology (trusted proxy,
    a different `X-Forwarded-For` for every request): twelve parallel login finishes → 5
    evaluated, 7 × 429 (before: 12 evaluated); seven sequential → 5 and 2 × 429; nine parallel
    step-ups → 5 and 4 × 429 (before: 9); nine parallel recovery attempts → 5 and 4 × 429
    (before: 9).
  - **Residual:** pending login states are still only bounded globally (10,000), not per
    username; filling them costs the attacker nothing beyond the per-address limit and gains no
    guesses.

### R11. Anyone can keep a restored installation closed (Medium, availability)

- **Where:** `apps/api/src/reopen/reopen.service.ts:75-90`: a wrong code counts a failure on **every** usable code, and five revoke it. `:207` records a recovery attempt before checking the code, which uses up the owner's 5-per-hour recovery budget.
- **Impact:** anyone who can reach the API can keep a restored server closed and force the host to keep reissuing codes. The tests assert this behaviour ("revokes a code after five failures").
- **Fix:** with 256-bit codes a wrong code tells an attacker nothing. Throttle wrong codes per IP, count failures only against the presented code (right code, wrong credentials), and check the code before recording a recovery attempt.
- **Remediation (56eef75):** a wrong, malformed, expired or used code is limited per client
  address (10 per 15 minutes; refused before any lookup once over) and never counts against the
  usable code; failed credentials presented with the usable code still count on it, and five
  revoke it. The Recovery Kit path reserves the owner's recovery budget only after the code
  checked out. Security events record `reason: code | credentials`, never the code.
  - **Regression:** `reopen.int-spec.ts` R11 block: twenty wrong codes from one address → ten
    401 then ten 429, the usable code untouched, and the owner then reopens (before: the fifth
    wrong code revoked it); eight wrong codes on the kit path from different addresses, then the
    owner reopens with the kit (before: 429 from the sixth); the old tests that asserted
    wrong-code counting now assert the opposite.
  - **Residual:** an attacker with many addresses can still make many wrong-code requests (each
    address bounded); they cannot affect the usable code.

### R12–R22. Low

- **R12. Reopening's password path completes without proof of `AK`** (`reopen.service.ts:294-330`, header checks only). Whoever holds the code, the old password and a device id can install their own password and junk wraps, locking the owner out. The code is host-issued, and the host holder is the owner in this model, so this is low here. It has the same root and fix as R2. **Fixed (§11):** the reopening login signs with the restored device key, and the completion carries `DSK` and `AVSK` proofs; a password-only completion is refused.
- **R13. `restore-reopen-code` racing completion.**
  - `complete` authenticates the reopen session before its transaction. Inside it, it checks only that the linked code has `revoked_at IS NULL` (`reopen.service.ts:319`).
  - `issueCode` (`server-restore.ts:589-605`) revokes only unconsumed codes and does not lock the guard row. A host revocation committed in between is ignored.
  - Fix: re-check the session `FOR UPDATE` inside the transaction; have `issueCode` lock the guard row and revoke consumed codes too.
  - **Fixed (233333d):** exactly that. Regression in `reopen.int-spec.ts`: a completion whose
    session the host ended after authentication fails and the state stays `reopening` (before:
    it opened); a completion and a new code run concurrently: exactly one takes effect (before:
    both).
- **R14. The gate caches `none` as open** (`maintenance.service.ts:39`). An API that touched the target database before PREPARE stays open after the guard appears. The specification says only `open` is cached. Fix: cache only `open`.
  - **Fixed (d239bb5)**, more broadly: a missing control schema is now **uninitialized** and
    closed; a fresh installation is opened explicitly by `ruvee-admin init`, which refuses any
    database that already has a control schema; a guard decides wherever one exists, and a
    missing row, unknown state or schema with neither table is closed; only `open` is cached.
    Regression `r14-gate-lifecycle.int-spec.ts`: an uninitialized database serves only health
    (20 parallel requests too); one app sees every later state of a restore target at once
    (before: it stayed open); `init` opens a fresh database once and refuses a restored one.
    Deployment change: run `init` once per new database (README, operator guide).
- **R15. `docker exec` kill and an early pg_restore exit** (`pg-tools.ts:85`, `server-restore.ts:293-296`).
  - Killing the `docker exec` client gives `pg_restore` inside the container a clean EOF, contrary to the comment on `load`.
  - If `pg_restore` exits 0 early, the drain wait never settles.
  - The guard still keeps the database closed, so only defence in depth is lost. Fix: race drain against `done`, and document the prefix limitation.
  - **Fixed (6ed27df):** LOAD holds the last decrypted chunk back until both hashes match, so a
    clean end of input after a failure leaves `pg_restore` a truncated archive that rolls back;
    waiting for pipe space races `pg_restore`'s exit. Regression in `r9-verified-bytes.int-spec.ts`:
    with the input ended instead of killed (the `docker exec` case), a forged staged dump no
    larger than the genuine one leaves 0 tables (before: its 14 tables were committed behind the
    closed guard); a tool that exits 0 without reading fails LOAD in under a second (before:
    hung). Observed: in this environment `pg_restore` connects late, so the old code was also
    saved by the loader role being dropped first; the test isolates the archive property by
    connecting as the admin role. The prefix remains for development; the guide says so.
- **R16. No per-session request limit** (authentication.md §7 lists 300/min/session). Not implemented.
  - **Fixed (417acfe):** every authenticated request (normal, token, recovery, reopen sessions)
    counts against an in-memory 300/minute window per session. Regression
    `r16-r17-limits.int-spec.ts`: the 301st request is 429 with `Retry-After`, another session
    of the same account is unaffected; unit tests for the window. Residual: in memory, one
    process (as V1 specifies).
- **R17. Proxy and IP keying** (`sessions/client-info.ts`). Behind Caddy without `TRUSTED_PROXY_ADDRESS`, every client is 127.0.0.1, so one attacker exhausts the global 20/min auth budget. Nothing warns. IPv6 is limited per address, not per /64.
  - **Fixed (417acfe):** per-address windows key IPv6 by /64; the API warns once (without the
    header's value) when a request carries `X-Forwarded-For` and `TRUSTED_PROXY_ADDRESS` is
    unset, and at start in production when it is unset. Regression: the warning test in
    `r16-r17-limits.int-spec.ts`; `throttle-windows.spec.ts` for /64 keys (compressed, zoned and
    IPv4-tailed forms). Residual: the operator must still set the variable; the API cannot
    detect a proxy that strips the header.
- **R18. Extension fill visibility** (`apps/extension/src/fill.ts:13-22`). Only the element's own style is checked: an ancestor with `opacity:0`, off-screen or clipped fields pass. Precondition: HTML injection on the exact saved origin, and a user click on Fill. **Fixed (§12).**
- **R19. Extension lock race** (`apps/extension/src/background.ts:113`, `:136-147`, `:266`). An `ended` lock during an in-flight `unlock` can be followed by `rememberUnlocked` writing `AK` back. It self-corrects on the next sync. Fix: a lock generation counter or one serialized queue. **Fixed (§12)**, wider than described: the engine itself kept running an operation on zeroed keys after a lock.
- **R20. Recovery on a device with data drops rollback floors** (`vault-engine.ts:1914-1937`, `:2205-2212`). It accepts any keyset version and resets the checkpoint to 0, so an old keyset or state could be re-served to a device that knew better.
  - **Fixed (a916561, with R6):** the kept checkpoint and anchor are the floor for the first sync, and a
    keyset older than this browser's is refused in `recoveryBegin`, before the server changes
    anything. Regression in `r5-r6-client.test.ts`: a server that rolled back one commit →
    `integrity_error`/`server_behind` after recovery (before: `synced`); an older keyset →
    `integrity` and the password unchanged on the server (before: accepted). A browser with no
    data still has no floor (sync-protocol §Limits).
- **R21. Pairing open-count race** (`apps/api/src/pairing/pairing.service.ts:51-81`). Count then insert at READ COMMITTED. It bypasses a rate limit only for an already active device. **Fixed (§12).**
- **R22. `startOver` and `feedImport`.**
  - `startOver` checks only `pendingSeen` (`vault-engine.ts:2900`), so conflict drafts are erased uncounted.
  - `feedImport` (`:2970`) can queue a batch while `pending` is non-empty, which produces spurious self-conflicts. No loss.
  - **Fixed (§12).** The duplicate needs a commit in flight (pending empty), not a non-empty pending queue.

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
| INV-06 session alone never grants decryption | Held for decryption; enrollment claim broken (R2), **fixed by D-31 (§11)**                                      | R2 reproduction                                                                                                                                                                             |
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

- ~~Every maintenance, reopening and CSRF test uses lower-case paths only (R1).~~ Closed (§9).
- ~~`auth.int-spec.ts` asserts a known device id yields an active device (R2 as intended behaviour). No test asks for proof of possession.~~ Closed (§11).
- The throttle tests are sequential (R3). Reauth and reopening throttling are untested.
- The lost-reply engine test uses one device (R5). Recovery is tested only on a new device (R6, R20).
- ~~The LOAD-failure test only flips a byte. It never substitutes a validly encrypted dump, adds padding, or swaps the meta between hash and read (R8, R9).~~ Closed for substitution and swaps (§9); padding is covered by the size check.
- ~~The forged-set test uses a set that stays the same between reads (R9).~~ Closed (§9).
- Nothing races `issueReopenCode` against completion (R13), or runs parallel reopen finishes (R3).
- ~~The synthetic-only test checks the name, not the effective connection target (R7).~~ Closed (§9).
- ~~The header tests run against `serve-export.mjs`, not Caddy (R10).~~ Closed: `test:caddy` (§9).
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
  - R15 is confirmed by reading only. R9 was confirmed by reading; its regression tests now change the files at each open through a test hook (§9).
  - R13, R19, R20 and R21 are plausible.
  - R5 is reproduced against the in-memory FakeServer, whose idempotent replay follows sync-protocol §4.2, not against the real API.

## 6. Claims narrowed or dropped during verification

- **R1, narrowed.** A reviewer reported that restored _cookies_ work through `/API/`. In a real restore those sessions are revoked, and the reproduction shows they stay refused. The real path is the snapshot-time **password** plus a device id.
- **R1, variants.** Only case variants bypass the gate. Percent-encoded, doubled-slash and trailing-slash paths do not.
- **R3, narrowed.** In the first run the per-IP limit (20/min) masked the issue. The finding is about the per-username limit when several addresses are used.
- **R6, narrowed.** Not reproducible while the browser stays unlocked online, because the edit uploads first. It reproduces for the realistic case: locked, edit never uploaded, recovery from the lock screen.

## 7. Prioritized remediation plan

Items 1 to 4 and 6 are done (milestone 1, §9). Items 7, 8, 9 and 10 are done (milestone 2,
§10). Item 5 (R2, R12) is done (D-31 milestone, §11), pending review of the protocol. P2 is open.

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

**Later (P2):** R18, R19, R21, R22, the R23 items, and the coverage gaps of §4. Done in §12,
except R23's device-label item.

## 8. Can a synthetic private deployment rehearsal proceed?

**Not yet decided.** The P0 items (R1, R7, R8, R10) and R9 are fixed and their tests pass (§9).
Whether to rehearse is the owner's decision after reviewing that milestone; this report does not
propose it. If it is approved, these conditions apply:

- synthetic data and synthetic identities only, with `--synthetic-test-only` still enforced;
- a private network or loopback only, with no internet exposure, so R2, R3 and R11 cannot be reached by outsiders;
- `TRUSTED_PROXY_ADDRESS` set for the Caddy in front (R17), and the CSP checked on the actual Caddy;
- restores only from backups made during the rehearsal, with the trusted digest (never `--no-trusted-digest`), from local storage the operator controls (R9);
- the restore run by a non-superuser role that does not own the guard tables (R8, §3.2b);
- R2, R3, R5, R6, R9 and R11 recorded as known open issues in the rehearsal plan.

Real-data use stays blocked by the P1 items and by D-19.

## 9. Remediation milestone 1 (2026-10-26): R1, R7, R8, R9, R10

Local commits on `vault/web-vault`, none pushed:

| Commit    | Finding  | Change                                                                                    |
| --------- | -------- | ----------------------------------------------------------------------------------------- |
| `e1056db` | baseline | This report and the reproduction tests, as reviewed                                       |
| `509b092` | R1       | Case-sensitive, strict routing; gate, CSRF and bearer rules decided by route class        |
| `4367db9` | R7       | One URL parser, explicit connection parameters, connected-identity and dump-header checks |
| `5bc18cd` | R8       | `ruvee_control` schema, per-restore loader role, restored-object allowlist                |
| `40dc0bc` | R8       | Lint fix in the allowlist (typed catalog map)                                             |
| `e8259da` | R9       | Single-open sources, private staging of the ciphertext, hashes in both passes             |
| `bfb248a` | R10      | Build-generated Caddy header snippet, fail-closed import, real-Caddy check                |

The reproductions in `apps/api/test/review/` (R1, R7, R8, R9) were run first against the
vulnerable code and then rewritten to assert the secure outcome; the evidence for each is in its
finding's **Remediation** entry. R10 was reproduced with real Caddy during the review and is now
checked by `apps/api/scripts/check-caddy.mjs`.

**Checks run** (2026-10-26, after the last commit, from a fresh `pnpm build`):

- `pnpm format:check`, `pnpm lint`, `pnpm typecheck`: pass.
- `pnpm test`: contracts 37, crypto 60, extension 27, API 72, web 43, vault 64 (+1 skipped
  fixture regenerator): pass.
- `pnpm test:integration` against a task-owned PostgreSQL 18 container, with `pg_dump` and
  `pg_restore` 18 run inside it: 20 files, 129 tests, pass.
- Browser suites: `test:restore` 2, `test:vault` 1, `test:import` 1, `test:headers` 33,
  extension `test:extension` 9, `pnpm test:e2e` 8 (+4 skipped as before): pass.
- `test:caddy` with `caddy:2.11-alpine` (2.11.7): 87 checks, pass.

**Still open:** R2 to R6 and R11 to R23, unchanged by this milestone. R14 in particular still
applies (`MaintenanceService` caches `none` as open). R2's protocol choice is prepared as a
proposal, not a decision: [r2-device-proof-decision.md](r2-device-proof-decision.md) (D-31,
proposed).

## 10. Remediation milestone 2 (2026-10-26): R3, R5, R6, R11, R13 to R17, R20

Local commits on `vault/web-vault`, none pushed. Each reproduction was run against the code
before its fix (by restoring the old source files temporarily) and failed there, then passed
after; the figures are in each finding's entry.

| Commit    | Finding    | Change                                                                                       |
| --------- | ---------- | -------------------------------------------------------------------------------------------- |
| `70c6a15` | test infra | Temporary databases tracked by exact name; dropped on every failure path and by a run ledger |
| `d239bb5` | R14        | Explicit installation lifecycle (`ruvee-admin init`); only `open` is cached                  |
| `b990cd0` | R3         | Atomic reservation of every password, recovery and bootstrap attempt                         |
| `56eef75` | R11        | Wrong codes limited per address, never charged to the usable code                            |
| `233333d` | R13        | Completion and code issuing serialized on the guard row; consumed codes revoked              |
| `6ed27df` | R15        | Last chunk held back until verified; drain raced against exit                                |
| `417acfe` | R16, R17   | 300/min per session; IPv6 by /64; proxy warnings                                             |
| `40a6cf4` | R5         | Landed in-flight commits cleared on pull; stale replies refused                              |
| `a916561` | R6, R20    | Recovery keeps this browser's vault and floors; other accounts erased only on confirmation   |

**Test-resource lifecycle.** Run alone and together, the integration suites left no database
behind on success; the five databases found after milestone 1 came from failed, timed-out or
killed runs. Several suites created databases outside a `try`/`finally`, the harness leaked its
database when its app failed to start, and a URL recorded after a harness had pointed
`DATABASE_URL` at a dropped database could not be used to drop anything. Now every database is
recorded by exact name before it is created, dropped after each file and at the end of the run,
and always through a non-temporary database; a lifecycle test reproduces the harness leak.
Nothing is dropped by prefix.

**Checks run** (2026-10-26, after the last code commit, task-owned PostgreSQL 18.6 container,
`pg_dump`/`pg_restore` 18 inside it):

- `pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm build`: pass.
- `pnpm test`: contracts 37, crypto 60, API 83, extension 27, web 43, vault 72 (+1 skipped
  fixture regenerator): pass.
- `pnpm test:integration`: 23 files, 150 tests: pass; no `ruvee_it_*`/`ruvee_e2e_*` database
  and no loader role left afterwards.
- Browser (Chromium): `test:vault` 1 (now with recovery on an enrolled browser that has an
  unsynced edit; it waits out the documented 20/min per-address window, which the run's own
  sign-ins reach because every context is 127.0.0.1), `test:restore` 2, `test:import` 1,
  `test:headers` 33, extension 9, `test:e2e` 8 (+4 skipped as before): pass.
- `test:caddy` (Caddy 2.11.7): 87 checks: pass.

**Not run:** Firefox and WebKit for the vault and restore suites (as before, Chromium only); a
multi-instance API (V1 is one process; the in-memory windows are per process).

**Still open:** R2 and R12 (they need the D-31 protocol decision:
[r2-device-proof-decision.md](r2-device-proof-decision.md), proposed, not approved), R18, R19,
R21, R22 and the R23 items. Two R23 items were addressed by milestone 1's R8 work (the
schema-qualified guard queries and the empty-target check), and the item stays open for the
rest.

## 11. D-31 milestone (2026-10-26): R2, R12

Development direction D-31 option A, as approved: a per-device Ed25519 key (`DSK`), sealed under
`K_local` and usable only while unlocked, plus an `AK`-derived verification key (`AVPK`) for
operations that replace key material. The protocol is [device-proof.md](device-proof.md) and
[ADR-0011](../adr/0011-device-proof-of-possession.md); it was written and made consistent before
any code. **It has not been independently reviewed** (device-proof.md §12, D-19). Local commits on
`vault/web-vault`, none pushed.

| Commit    | Scope   | Change                                                                                              |
| --------- | ------- | --------------------------------------------------------------------------------------------------- |
| `6c127d7` | spec    | device-proof.md and ADR-0011, before implementation                                                 |
| `3876ad1` | crypto  | Guarded `crypto_sign_*`, the `rvakver1` context, the signed-byte encoders, `pair-req-2`             |
| `a98e299` | API     | Login challenge, pre-proof sessions, proof nonces, tiered authorization, completion checks, restore |
| `e62a198` | clients | Engine, web and extension hold, seal, load and wipe `DSK`; every bound operation signed; migration  |
| `640a12b` | docs    | ADR-0002, authentication, enrollment, T-14, INV-24, review packet, migration guide                  |
| `3d9b8bf` | tests   | Operation proofs bound to account, operation and session; a used nonce stays used                   |

**What changed for R2.** A password plus a device id now gives a pre-proof session. It reaches
`devices/current`, `account/keys`, a `session_proof` nonce, `session-proof` and logout only,
lapses after 10 minutes, and no longer signs the genuine device out. Acting as the device needs a
signature with its `DSK`. Password, Secret Key and Recovery Kit changes also need a fresh
single-use nonce and an `AVSK` proof checked against the stored `AVPK`; device revocation needs a
nonce-bound `DSK` proof after step-up; sync commits need a proven session. Device keys are
accepted only with the setup token, an approving device's proof over the exact key (the pairing
MAC now covers it), the Recovery Key plus `AK`, or a reopening.

**What changed for R12.** The reopening password path signs `reopen/login/finish` with the restored
device key, and `reopen/complete` carries `DSK` and `AVSK` proofs. A completion that is not backed
by `AK` is refused with `device_key_mismatch` or `device_proof_failed`.

**Regression evidence** (real API and PostgreSQL unless noted):

- `r2-r3-login.int-spec.ts`, "REVIEW R2 (regression)":
  - the pre-proof session reaches only the allowlist, and the device's proven session survives;
  - it cannot step up, replace wraps, rotate the kit, revoke devices or commit. Baseline step 4,
    the `0x41` wrap, now fails at step-up, and the owner's password still logs in;
  - a login proof made with a substituted key, for another operation, or for another login fails;
  - session-proof nonces are bound to their session and operation, single-use, expire, and only
    one of two concurrent uses succeeds;
  - an operation proof (device revocation, after step-up) signed for another account, sent with
    a nonce of another operation or another session, or reusing a nonce that already succeeded
    is refused, and the second device stays active;
  - an unproven session lapses after 10 minutes;
  - token refreshes keep the proof status, proven or not.
- `reopen.int-spec.ts`, "REVIEW R12 (regression)": a password-only reopening and a junk wrap are
  refused; the restored key and `AK` complete it.
- `recovery.int-spec.ts`: R-08, where `RAK` alone with another key gives another `AVPK` and is
  refused; the recovery installs the new `DPK`.
- `pairing.int-spec.ts`: a device key swapped after A read the request is not enrolled.
- `restore.int-spec.ts`: proof nonces and sessions from the snapshot are gone after restore.
- `account-security.int-spec.ts`: a password change with a device proof but no valid `AVSK`
  proof is refused; a revocation signed for one reason and sent with another is refused, and its
  nonce is burnt. Password, Secret Key and kit changes and revocation succeed with the right
  proofs.
- `@ruvee/crypto` `device-proof.spec.ts`: RFC 8032 vectors; the signed bytes computed
  independently; every field changes the signature; an `AVSK` signature never verifies as a device.
- Engine against the FakeServer, which verifies every proof with the same code,
  `d31-device-proof.test.ts`:
  - setup registers `DPK` and `AVPK`, and the key is stored sealed;
  - unlock proves a new session, and a locked engine cannot sign;
  - a pre-D-31 device keeps its pending edit offline and is migrated with the kit, keeping it;
  - an extension service-worker restart (resume from `AK`) still signs;
  - an enrollment interrupted after approval becomes a new pending device.

**Checks run** (2026-10-26, task-owned PostgreSQL 18.6 container):

- `pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm build`: pass.
- `pnpm test`: pass. The counts are contracts 40, crypto 67, API 83, extension 27, web 43, and
  vault 77 (+1 skipped fixture regenerator).
- `pnpm test:integration`: 23 files, 158 tests: pass. No `ruvee_it_*` or `ruvee_e2e_*` database
  and no loader role was left afterwards.
- Browser `test:vault` 1, `test:restore` 2 and `test:import` 1, each in **Chromium, Firefox and
  WebKit**: pass. Firefox and WebKit are Playwright's builds, not Safari.
- Chromium only: `test:headers` 33, extension 9, `test:e2e` 8 (+4 skipped as before): pass.
- `test:caddy` (Caddy 2.11.7): 87 checks: pass.

**Not run, or partly covered:**

- The extension suite runs in Chromium only, since the extension targets Chromium. Its
  service-worker restart is covered by the engine test above and the existing extension suite,
  not by a browser test that kills the worker mid-operation.
- Safari itself; a multi-instance API, since nonces are in the database but login challenges are
  in process memory.
- An independent review of the protocol (D-19).

**Residual risk, recorded in T-14 and INV-24:**

- A pre-proof session still exposes the encrypted key material. This is useless without `SK` and
  is already in every database copy.
- Code running in the unlocked origin, through XSS or a malicious extension, can sign. A stolen
  proven session can do tier-2 work (sync commits, ending sessions) until it is revoked.
- Migration re-enrolls one device per Recovery Kit rotation.
- A valid signature proves possession of a key for one payload, never that a wrap or envelope in
  that payload decrypts.

**Still open:** R18, R19, R21, R22 and the R23 items (P2). D-19 stays open and real-data use stays
blocked.

## 12. Final remediation batch (2026-10-27): R18, R19, R21, R22, R23, D-31 verification

Local commits on `vault/web-vault`, none pushed. Every regression test below was run against the
code before its fix (old source files restored temporarily, or, for the milestone-1 empty-target
check, a `pg_tables`-only stand-in) and failed there, unless the entry says otherwise.

| Commit    | Scope                   | Change                                                                                      |
| --------- | ----------------------- | ------------------------------------------------------------------------------------------- |
| `56731e2` | R19, R22, R23 (zeroing) | Lock-aware engine and extension worker; start-over conflict count; import feed; key zeroing |
| `e67266f` | R18                     | Fill requires the field to be visible to the user                                           |
| `82183d7` | R23 (pairing)           | Malformed pairing requests burned and reported; A shows its own receipt time                |
| `5d1f571` | R21, R23 (CSRF), D-31   | Account-row lock for pairing; extension CSRF per route; nonce issue under the session lock  |
| `fa73e0c` | topology                | One API process per database, enforced with an advisory lock                                |
| `74ab988` | R23 (doc)               | Extension sender filtering described as built                                               |
| `fbb72fb` | D-31                    | Sequential migration, logout zeroing, a lost session proof                                  |
| `773626b` | R18, R19, worker stops  | Real-Chromium extension tests                                                               |

### 12.1 Findings of this batch

**R18. Extension fill visibility.** Boundary: the extension's injected fill function against a
hostile page on the exact saved origin. The function checked only the field's own style.

- Fix: every ancestor displayed and visible, effective opacity ≥ 0.5, at least 8 × 8 px, the
  centre inside the viewport (a field below the fold is scrolled to first), and the field the
  topmost element at its centre.
- Evidence: `fill.test.ts` (ancestor opacity 0 and 0.27, ancestor `visibility:hidden`, 1 px,
  off screen, covered, nothing on top) and extension e2e "R18" (a real page with each case on
  the saved origin). The old function filled all of them.
- Residual: a determined page can still make a field look like something else (a visible field
  with a misleading label). The fill stays manual, per click, on the exact origin.

**R19. A lock during work in flight.** Boundary: the lock (INV-15) in the shared engine and the
extension worker. Reproduced in two forms. In the extension, an unlock the lock overtook finished
afterwards and stored `AK` back in `chrome.storage.session`. Wider than reported: in the engine,
an operation waiting on the network or IndexedDB kept running after `wipeMemory`, so it could
install a session again, or seal records under the zeroed keys.

- Fix: the engine counts locks; an operation that began before the latest lock has its writes
  refused (`putDevice`, `apply`, `wipe`), and whatever it unlocked is cleared and reported as
  `locked`. The worker also counts locks and never stores `AK` after one. Logout now zeroes the
  engine's keys too.
- Evidence: `p2-client.test.ts` (a lock before the session exists, after it exists, during a
  sync), and extension e2e "R19" (a lock sent at eight delays after an unlock; the original
  engine and worker ended unlocked).
- Residual: the web app terminates its worker 250 ms after asking it to wipe; a write already
  inside an IndexedDB transaction when the lock arrives completes with intact keys.

**R21. Pairing open-count race.** Boundary: per-account pairing limits (authentication.md §7).
Reproduced: eight parallel creates made eight pairings.

- Fix: the create transaction locks the account row first.
- Evidence: `p2-api.int-spec.ts` (eight parallel creates make exactly three; rounds of parallel
  creates stop at exactly ten an hour). Before: eight open pairings, and twelve in an hour.

**R22. Start-over and import counts.** Boundary: the "never erase silently" rule of the restore
help, and import integrity.

- Fix: `startOver` requires the conflict count the user was shown as well as the pending count
  (the web app sends both). An import batch is fed only into an empty pending queue with no
  commit in flight.
- Evidence: `p2-client.test.ts` (a device with one conflict and no pending edit was erased; a
  dropped connection left a batch in flight that was queued a second time).

**R23. Info items, one by one.**

| Item                                                          | Disposition                                                                                                                                                                                                       |
| ------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EXTENSION_ORIGINS` passes CSRF on every `none` route         | **Fixed** (`5d1f571`): only `@ExtensionMayCall` handlers (login start and finish, refresh). Test: registration, recovery and reopening from the extension origin are `csrf_rejected`.                             |
| The empty-target check counts only `pg_tables`                | **Fixed in milestone 1** (R8 work); regression added (`5d1f571`): a function, view, type, domain, schema, sequence or large object alone makes the target non-empty. Failed against a `pg_tables`-only check.     |
| Guard tables queried unqualified                              | **Fixed in milestone 1** (R8): every query names `ruvee_control`; the existing regression plants `public.restore_guard` (`r7-r8-backup.int-spec.ts`).                                                             |
| Key-zeroing gaps (`recovery`, `kitRotation`, `openKeyset`)    | **Fixed** (`56731e2`): `wipeMemory` zeroes an unfinished setup and recovery and drops a kit rotation; failed unlocks, recoveries and reopenings zero what they opened. Tests in `p2-client.test.ts`.              |
| The approval sends no device `label`                          | **Open, requires a decision.** No client names devices yet; the device list shows the platform. Implementing it is a product feature (naming on A, encrypting, displaying). Decide: implement, or amend the spec. |
| `requestedAt` is not covered by the request MAC               | **Fixed** without a protocol change (`82183d7`): A shows the time it received the verified request, not the server's. The MAC format (`pair-req-2`, D-31) is unchanged.                                           |
| Malformed `epk` or platform is not burned and leaves no event | **Fixed** (`82183d7`): a key of the wrong size, an unknown platform or an unparsable reply counts as a failed MAC: burned, cancelled with `mac_failed`.                                                           |
| The extension design says `sender.tab` messages are dropped   | **Fixed** (`74ab988`): the document describes the `sender.id` and `sender.origin` check, and why `sender.tab` cannot be used.                                                                                     |

That is ten R23 items: nine closed, one open.

### 12.2 D-31 verification

Traced through the engine, the API and the browser suites:

- **Recovery on a fresh browser** (only the Recovery Kit). The recovery start creates a pending
  device with a new id; the engine generates a new `DSK` at completion; the server checks the
  `AVSK` proof against the stored `AVPK` and sets the new `DPK`. `AVPK` is unchanged. Tests:
  `recovery.int-spec.ts` (new key enrolled, `AVPK` unchanged, a different `AK` refused); web
  `test:vault` "Device C" in three engines.
- **Reopening through the Recovery Kit on a fresh browser.** It does **not** use a restored
  device key: the engine generates a new one, like a recovery (`recoveryFinish`, `r.reopen ===
'recovery'`); only the password path proves the restored key. The snapshot device's key and
  `AVPK` stay as they were. Tests: `reopen.int-spec.ts` (Recovery Kit path), web `test:restore`
  "reopening on a new browser with the Recovery Kit" in three engines. The earlier summary was
  right for the password path only; the fresh-browser path is not broken.
- **Sequential migration of pre-D-31 devices.** Two devices, each with an unsynced edit, migrate
  in turn. Each recovery rotates the kit, and the first kit is refused afterwards. Each keeps its
  pending edit and enrolls its own key; the first sets `AVPK` and the second leaves it
  (`d31-device-proof.test.ts`).
- **Refresh.** Pre-proof and proven token sessions keep their status across refreshes, including
  a session proven after login (`r2-r3-login.int-spec.ts`, `p2-api.int-spec.ts`).
- **Lock, logout and key cleanup.** A locked engine cannot sign; lock and logout zero `DSK` in
  memory and keep only the sealed record (`d31-device-proof.test.ts`).
- **Concurrency.** Nonce issue is now under the session row lock: parallel requests leave
  exactly one open nonce, and only the last issued works (before: six requests left six open). Concurrent
  consumption: exactly one wins (`r2-r3-login.int-spec.ts`).
- **Lost responses.** A revocation sent again after its reply was lost changes nothing and
  records one event. A session proof sent again is `forbidden` and leaves the session proven. In
  the engine, a lost session-proof reply ends in one proven session through a new login with the
  device key.
- **Caller-supplied `AVPK`.** Only registration (setup token), recovery completion and reopening
  completion carry an `AVPK`, and the latter two accept it only if it equals the stored one. On an
  account with no stored `AVPK`, a correct `DSK` and `AVSK` proof for a kit change is refused, and
  nothing establishes one from the request (`p2-api.int-spec.ts`). Hardened: which operations
  need the `AVSK` proof is fixed per operation (`NEEDS_ACCOUNT_KEY_PROOF`), never inferred from
  the request body.
- **Known D-31 limitation (development accounts only).** On an account from before D-31, the first
  recovery or kit reopening establishes `AVPK`. Someone holding only that account's `RAK`, without
  `AK`, could therefore register their own `AVPK` there (device-proof.md §8). No account created
  since D-31 has this property. **Not accepted here:** recorded for D-19, and it has to be closed
  or explicitly accepted by the owner before any account from before D-31 holds real data.

### 12.3 Deployment topology

V1 is documented as a single API instance (authentication.md §7). Login states, per-address
windows and per-session limits are in process memory. Multi-process operation is **not**
supported, so it is now enforced instead of exercised:

- The serving process holds a PostgreSQL session advisory lock. A second process on the same
  database answers liveness only; readiness is 503 and every route is `503 server_unavailable`.
  It takes over within seconds when the first stops (`topology.int-spec.ts`).
- Startup still does not wait for the database. A lost lock connection is retried; nothing is
  served meanwhile.
- README "Deployment topology": one process per database, a direct connection or a session-mode
  pooler (a transaction-mode pooler does not hold session advisory locks), no replicas.

Shared rate limiting, maintenance transitions and nonce consumption across two processes were
therefore not exercised. The guarantees they would need do not exist in V1.

### 12.4 Checks run

2026-10-27, at `773626b`, task-owned PostgreSQL 18 container, `pg_dump`/`pg_restore` 18 in it:

- `pnpm format:check`, `pnpm lint`, `pnpm typecheck`, `pnpm build`: pass.
- `pnpm test`: pass. Per package: contracts 41, crypto 67, API 84, extension 29, web 43, vault
  92 (+1 skipped fixture regenerator).
- `pnpm test:integration`: 25 files, 175 tests: pass. No `ruvee_it_*`/`ruvee_e2e_*` database or
  loader role was left afterwards.
- Browser, each in **Chromium, Firefox and Playwright WebKit** (not Safari): `test:vault` 1,
  `test:restore` 2, `test:import` 1: pass.
- Chromium only: extension suite 13 (four new), `test:headers` 33, `test:e2e` 8 (+4 skipped as
  before): pass.
- `test:caddy` (Caddy 2.11.7): 87 checks: pass.

**Not run, or partly covered:**

- The extension in Firefox or WebKit: it is a Chromium MV3 extension.
- Safari itself.
- Two API processes serving at once, by design (§12.3).
- Fuzzing and load testing.
- Remote CI: nothing was pushed, and its status is unchanged.
- The R19 browser test needs a lock to land mid-unlock at one of eight delays. It did in every
  run here, but it depends on timing; the engine tests hold the operation open deterministically.
- The service-worker stop during a fill accepts either outcome (filled once, or not at all). The
  run here does not show which one happened.

### 12.5 Disposition of all 23 findings

**Fixed and tested:** R1, R7, R8, R9, R10 (§9); R3, R5, R6, R11, R13, R14, R15, R16, R17, R20
(§10); R2, R12 (§11); R18, R19, R21, R22 (§12); R23 except the device label (nine items, §12.1).

**Open:** R23, device label (see "Requires a decision").

**Accepted limitation with explicit existing authorization:** none is accepted in this report.
Limitations that rest on an owner decision already recorded elsewhere: `AK` in
`chrome.storage.session` while unlocked (D-27); the unreviewed pairing composition (D-21);
reopening codes that a network attacker can use up (D-30). Each is still subject to D-19.

**Requires a decision:**

1. R23 device label: implement naming on the approving device, or amend device-enrollment.md.
2. D-31 limitation above: how accounts created before D-31 get a trusted `AVPK` if they are ever
   to hold real data (today they are synthetic development accounts).
3. D-19: who reviews, and when. The checklist for it is
   [follow-up-review-checklist.md](follow-up-review-checklist.md).

**Residual risks not specific to one finding** (T-14, INV-24): a pre-proof session can read the
encrypted key material; code running in the unlocked origin can sign; a stolen proven session can
commit until it is revoked; D-31 is unreviewed.

Real-data use stays blocked: D-19 is open, and nothing in this report is a security approval.
