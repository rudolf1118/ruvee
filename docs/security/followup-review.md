# Follow-up security review (2026-10-27)

**This is an AI-assisted code review, not an independent professional audit. It does not complete
D-19, and it is not a statement of production readiness.** It re-examines the code from scratch
instead of relying on the dispositions in [predeployment-review.md](predeployment-review.md), and
it investigates the test instability that report left open (§13.4 there).

## 1. What was reviewed

| Item                      | Value                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Application code reviewed | `1702ea612320dcc3c673b7c431c4c8bf8bc85b4f` (`1702ea6`), branch `vault/web-vault`                                                                                                                                                                                                                                                                                                                                                                 |
| Later commits             | `0298e58`, `3b67a30`: `git diff --name-only 1702ea6 3b67a30` lists only `docs/` files (verified)                                                                                                                                                                                                                                                                                                                                                 |
| This review's own commit  | Tests, the README and this report only; no application code changed (§5, §9)                                                                                                                                                                                                                                                                                                                                                                     |
| Specifications read       | predeployment-review.md, follow-up-review-checklist.md, device-proof.md, ADR-0011, device-enrollment.md, account-recovery.md, threat-model.md, security-invariants.md, backup-restore.md, legacy-account-migration.md                                                                                                                                                                                                                            |
| Method                    | Five read-only reviewer passes, each given the code and the original findings but not the earlier conclusions: D-31 end to end; client engine and extension; routing, CSRF, gate and instance lock; restore, backups and throttles (one earlier server pass stopped before reporting and was replaced by the last two). Every finding below marked **confirmed** was then checked against the code by hand, and the Medium ones were reproduced. |
| Data                      | Synthetic only. Task-owned PostgreSQL 18.6 containers; no deployment, push or remote CI.                                                                                                                                                                                                                                                                                                                                                         |

## 2. Confirmed findings, by severity

Each reproduction is a test that states the **correct** behaviour and is marked `it.fails` while
the defect exists, so the suite stays green and vitest reports when a fix makes it pass. Each was
first run without the mark and failed on the stated assertion.

### F-1 (Medium). A proven session can end the owner's Recovery Kit recovery, indefinitely

- **Where:** `GET /sessions` lists recovery sessions
  (`apps/api/src/account/account-security.service.ts:96`); `DELETE /sessions/:id` ends any session
  of the account, of any kind, at tier 2 (`:119-128`); a revoked recovery session is refused
  (`apps/api/src/sessions/session.service.ts:190`).
- **Attack:** whoever holds a proven cookie or a refresh token (a lost laptop's extension keeps one
  for up to 90 days, and it survives lock) polls `GET /sessions` and deletes every `recovery` row.
  The owner's recovery fails as unauthenticated each time. Without another device the owner cannot
  revoke the thief (revocation needs step-up and a device key), and there is no operator command
  to end sessions.
- **Reproduction:** `apps/api/test/review/followup-repro.int-spec.ts`, "a normal session cannot
  end a recovery in progress": after the owner's session ends the recovery session,
  `GET /recovery/material` with the recovery cookie returns `401` (expected `200`).
- **Impact:** availability of the last-resort recovery against an attacker who already holds a
  session; no key or plaintext exposure. device-proof.md §7 rates ending sessions as "a re-login,
  nothing more", which misses this.

### F-2 (Medium). Two tabs of one browser overwrite each other's unsynced edits

- **Where:** each tab runs its own worker and engine on the same IndexedDB
  (`apps/web/src/vault/worker/vault.worker.ts:45-60`); `DeviceStore` has no cross-tab
  coordination (`packages/vault/src/store.ts:85-98`); `persistLocal`
  (`packages/vault/src/vault-engine.ts:1499`) writes the whole pending list from that engine's
  memory.
- **Reproduction:** `packages/vault/src/review/followup-repro.test.ts`, "two engines on one store
  keep both tabs' unsynced edits": tab 1 and tab 2 each save one item offline; after both lock,
  the store holds only tab 2's (`['Saved in tab 2']`).
- **Impact:** silent loss of unsynced edits (INV-08). By reading, the same pattern can write back a
  stale device record or checkpoint from the other tab. Reproduced in the engine with
  `fake-indexeddb`; not yet in two real browser tabs.

### F-3 (Medium). Resolving one conflict can queue two mutations of one item and stop sync

- **Where:** `resolveConflict('mine')` for a local deletion appends a tombstone without removing an
  existing pending edit of the same item (`packages/vault/src/vault-engine.ts:1804-1807`); the API
  refuses a commit naming one item twice with `400 invalid_request`
  (`apps/api/src/vault/sync.service.ts:57-58`); the client maps that to `internal`, then `offline`
  (`vault-engine.ts:275-276`).
- **Sequence:** A deletes X offline; B edits X; A syncs and gets `edited_after_delete`; A edits X
  offline, then chooses "mine".
- **Reproduction:** `followup-repro.test.ts`, "resolving a conflict never queues two mutations of
  one item": the next commit names X twice. The fake server accepts it, which is why the existing
  suite cannot see this; the real API's refusal is confirmed by reading.
- **Impact (by reading):** the in-flight commit is re-sent on every sync and always refused, so the
  device never syncs again; the only exits erase local changes. Not reproduced end to end against
  the real API.

### F-4 (Medium). A password change from a device with an outdated Secret Key locks the account out and undoes a Secret Key rotation

- **Where:** `changePassword` refuses only when the server's keyset is older than the local one
  (`packages/vault/src/vault-engine.ts:2960-2962`), then wraps `AK` under the local, possibly
  outdated `SK`.
- **Sequence:** device A replaces the Secret Key (D-24, for example after removing a lost device);
  device B, unlocked since before, changes the password.
- **Reproduction:** `followup-repro.test.ts`, "a password change from a device with an older
  Secret Key keeps the account usable": afterwards device A, which holds the current `SK`, gets
  `wrong_password` with the new password.
- **Impact:** every device with the current `SK` (and any newly paired one) is locked out until
  the Recovery Kit is used; and the server's password wrap is again under the **old** `SK`, which
  undoes what D-24's rotation was for (a copy of the server data plus the lost device's `SK`).

### F-5 (Low). If the worker started at lock fails to load, the app offers "Create an account" on a browser that holds a vault

- **Where:** `apps/web/src/components/app/vault-app.tsx:103` treats any failure of the new
  worker's `phase` call as a new device; any startup failure in the worker (WASM init,
  IndexedDB open, script load) becomes such a failure (`vault.worker.ts:45-60`), and the failed
  start is cached for that worker.
- **Reproduction:** a temporary Playwright test (kept with the evidence, §5.3) aborted every
  request after setup and pressed **Lock now**: Chromium, Firefox and Playwright WebKit all showed
  the welcome screen while IndexedDB still held the device record. A reload shows the lock screen.
- **Impact:** confusing and alarming, not data loss: setup refuses a browser with a device record
  (`vault-engine.ts:447`), recovery keeps this browser's vault, and V1's one account per server
  stops "log in" from overwriting the record with another account's (`vault-engine.ts:709-724`,
  `apps/api/src/auth/auth.service.ts:285`). This is the defect behind the WebKit test failure
  (§5.3).

### F-6 (Low). Any bearer-shaped `Authorization` header skips the CSRF checks of unauthenticated routes

- **Where:** `apps/api/src/sessions/access.guard.ts:107-111` sets `bearer` for any 43-character
  value, which skips the CSRF block, and `:134` returns for `none` routes without using it.
- **Reproduction:** `followup-repro.int-spec.ts`, "an unauthenticated route refuses a request
  without Origin and X-Ruvee-Request": `POST /recovery/start` with `Authorization: Bearer AAA…`
  and no `Origin` reaches the handler (`401 recovery_failed`, expected `403 csrf_rejected`).
- **Impact:** web pages cannot send the header cross-origin (no CORS, so the preflight fails); any
  browser extension with host permission can call registration, login, recovery and reopening
  start routes, defeating the R23 per-route extension restriction. No ambient credential is used.

### Low, confirmed by reading (not reproduced)

| ID   | Issue                                                                                                                                                                                                                                                     | Where                                                                            |
| ---- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| F-7  | A `TRUSTED_PROXY_ADDRESS` written differently from the peer address (upper-case or expanded IPv6, or an IPv4 value while the proxy connects over IPv6) never matches, silently: every client is keyed as the proxy (the R17 symptom, without the warning) | `apps/api/src/sessions/client-info.ts:10,20-24`; `config/env.ts:37`              |
| F-8  | The per-address limiter clears its whole table when it reaches 10,000 entries; an attacker with that many IPv6 /64s resets every client's window                                                                                                          | `apps/api/src/auth/throttle.service.ts:106-110`                                  |
| F-9  | Extension fill (R18) still fills fields hidden by `filter: opacity(0)` on an ancestor, transparent text and background, `clip-path`, or an overlay with `pointer-events: none` (which `elementFromPoint` looks through)                                   | `apps/extension/src/fill.ts:23-44`                                               |
| F-10 | Pairing fails if B logged in more than 10 minutes before A approves: once B's device is active, its unproven session lapses by creation time                                                                                                              | `apps/api/src/sessions/session.service.ts:384-389`                               |
| F-11 | `refresh` does not apply the 10-minute pre-proof lapse, so a password-only token session of an active device can be refreshed for its full lifetime (it stays restricted to the pre-proof allowlist, but keeps "last seen" fresh)                         | `session.service.ts` `refresh`                                                   |
| F-12 | Unlock and resume install the session before loading the device key; if that load throws, the call fails but the engine stays unlocked with `AK` in memory                                                                                                | `packages/vault/src/vault-engine.ts:860-862`                                     |
| F-13 | A lock that lands before an operation's later write leaves its session installed when that write is refused (`exclusive` clears only on success): rotated keyset at unlock, revocation, pairing and setup finishes                                        | `vault-engine.ts:408-427`, `:1128`, `:2221`, `:690`                              |
| F-14 | Enrollment is saved in several transactions (device, then checkpoint and anchor, then key); an interruption leaves an active device with no anchor (no rollback floor on its first pull) and no key                                                       | `vault-engine.ts:2207-2223`, `:682-692`, `:2664-2744`                            |
| F-15 | Any non-contract error body (a proxy's 502 page) during pairing is treated as a MAC failure: the pairing is burned and a false `pairing_mac_failed` event recorded. Introduced by the previous batch's own R23 fix (`37166f0`)                            | `packages/vault/src/api.ts:123-125`; `vault-engine.ts:1897`                      |
| F-16 | A conflict draft is replaced without notice when the same item conflicts again (INV-08)                                                                                                                                                                   | `vault-engine.ts:3831`                                                           |
| F-17 | Every `device_proof_failed` (an expired or replaced nonce included) is shown as "re-enroll with your Recovery Kit", which forces a new password and kit                                                                                                   | `vault-engine.ts:266-269`; `apps/web/src/components/app/messages.ts:78`          |
| F-18 | Recovery completion does not re-check its session or device under a lock; a device revoked between authentication and the transaction is set active again (the caller still needs `RAK` and `AK`)                                                         | `apps/api/src/recovery/recovery.service.ts:172-210`                              |
| F-19 | Remaining key-zeroing gaps: `recoveryBegin` refusals before its `try` leave `RWK`/`RAK`; the reopen password finish drops second copies of `AK`/`SK`/`VK`; `revoked()`, failed `pairingWait`, `adoptServerKeys` and failed unlock paths leave copies      | `vault-engine.ts:2253-2264`, `:2773`, `:1207-1212`, `:2173`, `:1177`, `:836-858` |

**Info (by reading):** F-20 a save that completes after the user opened another editor replaces
that editor without notice (seen in a Firefox test run, §5.3). F-21 the extension's allow-list
includes `detail`, which the popup never uses (`apps/extension/src/messages.ts:9-21`). F-22
request bodies are parsed before authentication and the gate (`app.module.ts:42-45`). F-23 the
op-3 payload does not sign every stored registration field (`saltPw`, `keysetVersion`,
`vault.vkId`, `username`); only a setup-token holder on the path could exploit it, and they could
re-sign anyway. F-24 consumed and expired `proof_nonces` rows are never deleted. F-25 the API must
run as the restore admin role, which owns `ruvee_control` (backup-restore.md speaks of a separate
application role).

## 3. Suspected issues (not confirmed)

- **S-1 (Low).** The instance-lock connection has no keep-alive and is never re-checked; a
  silently dropped connection could free the advisory lock while the process still believes it
  holds it, letting a second process serve (`instance-lock.service.ts:76-99`).
- **S-2 (Low).** After LOAD, restored tables are checked by kind and name only, not by column,
  constraint or default definitions (`restore-control.ts:85-158`). A forged backup could alter an
  allowed table's constraints. Ordinary grants in the archive are **not** applied (`pg_restore
--no-owner --no-privileges`, `pg-tools.ts:112-113`), which refutes the reviewer's broader claim;
  SQL embedded in other archive entries was not tested.
- **S-3 (Low).** R15 variant: `pg_restore` may commit a forged archive that ends before its last
  encrypted chunk (trailing bytes) before the hash check fails. The guard stays `restoring`, so
  this is defence in depth, as in the original finding.
- **S-4 (Info).** An operation whose effect fails rolls back its nonce consumption, so the same
  signed request is replayable for up to 2 minutes. No state was found where a retry turns a
  failure into a success.
- **S-5 (Info).** A malicious server can make a browser's recovery take the "another account"
  path (by answering with another device, key or vault id); one checkbox then erases pending edits
  and the R20 floors.

## 4. Disposition of the original 23 findings

| Finding                   | Verdict            | Notes                                                                                                                                                                                                                     |
| ------------------------- | ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1 path case              | Fixed              | Strict, case-sensitive routing; decisions from handler metadata. Tests would also pass with a prefix check (gap).                                                                                                         |
| R2 device proof           | Fixed (D-31)       | See §6.                                                                                                                                                                                                                   |
| R3 username throttle      | Fixed              | Atomic `INSERT … ON CONFLICT`; no parallel test for the reopen password finish.                                                                                                                                           |
| R5 checkpoint             | Fixed (one engine) | Two tabs can still lower the stored floor (F-2).                                                                                                                                                                          |
| R6 recovery keeps data    | Fixed (one engine) | S-5; untested: in-flight commit, anchor, import state.                                                                                                                                                                    |
| R7 backup target          | Fixed              | `RUVEE_PG_TOOLS_HOST` can point the tools at another host (operator configuration).                                                                                                                                       |
| R8 restore isolation      | Fixed, with S-2    | Definitions of allowed tables are not compared.                                                                                                                                                                           |
| R9 verified bytes         | Fixed              |                                                                                                                                                                                                                           |
| R10 headers               | Fixed              | Checked briefly.                                                                                                                                                                                                          |
| R11 reopening code        | Fixed              |                                                                                                                                                                                                                           |
| R12 reopen proof          | Fixed (D-31)       |                                                                                                                                                                                                                           |
| R13 reopen race           | Fixed              | Recovery completion lacks the same re-check (F-18).                                                                                                                                                                       |
| R14 gate cache            | Fixed              |                                                                                                                                                                                                                           |
| R15 `pg_restore` input    | Partly             | S-3.                                                                                                                                                                                                                      |
| R16 session limit         | Fixed              | Tested for cookie sessions only.                                                                                                                                                                                          |
| R17 proxy                 | Partly             | F-7.                                                                                                                                                                                                                      |
| R18 fill visibility       | Partly             | F-9.                                                                                                                                                                                                                      |
| R19 lock races            | Partly             | F-12, F-13.                                                                                                                                                                                                               |
| R20 recovery floors       | Fixed              | Anchor floor after recovery untested.                                                                                                                                                                                     |
| R21 pairing limit         | Fixed              |                                                                                                                                                                                                                           |
| R22 start-over and import | Fixed              | Related: F-3.                                                                                                                                                                                                             |
| R23 (10 items)            | 6 fixed, 4 partly  | Partly: CSRF per route (F-6), empty-target kinds (collations, operators, text search objects, default and database ACLs, role settings not counted), key zeroing (F-19), malformed pairing requests (false alarms, F-15). |

The legacy-account hardening (predeployment-review §13) holds: `ak_verify_key` is written only by
registration (`apps/api/src/auth/auth.service.ts:167-181`), and `recovery/start`,
`reopen/recovery/start` and `proveCompletion` refuse a null one.

## 5. Test instability

Evidence is kept per run under unique identifiers in this session's scratchpad
(`flake-evidence/int-<id>/`: vitest JSON, console output, per-step timings, host load and server
connections every 2 s, and the server log for that window; `flake-evidence/*webkit*`,
`*-firefox-*`: Playwright output and traces). It is local to this machine and not in the
repository. The timing instrumentation was temporary and reverted; its diff is kept there too.

### 5.1 Integration teardown timeouts (explained)

- **Mechanism, measured.** In run A1 (default 9 workers): `app.close()` was fast (p90 1.3 s), but
  `DROP DATABASE … WITH (FORCE)` took up to 132 s and `CREATE DATABASE` up to 102 s. The server
  log shows 40 checkpoints, every one `immediate force wait`, each 27–74 s, dominated by `fsync`
  of 2,500–3,900 files (e.g. `sync=53.084 s`); the checkpointer was busy 343 of the run's 351 s.
- **Which statement forces it.** On an idle server, `CREATE DATABASE` forced no checkpoint and
  `DROP DATABASE` forced one (16 ms when idle). So every test-file teardown waits for a full
  checkpoint of all concurrent databases' dirty data; drops queue, and a hook with a 10 s limit
  times out.
- **Interventions.** Same suite, one run each: 3 workers → all 26 files pass, worst checkpoint
  2.2 s; default workers on a server with `fsync=off` → all pass, checkpoint sync 0.001 s, worst
  drop 1.8 s; default workers again with `fsync` on (A2) → pass, worst checkpoint 4.8 s.
- **Not machine load as measured.** The mean 1-minute load average was 15.7–17.0 in all four runs
  (and about 17 with no tests running, from Spotlight indexing), yet A1 took 385 s and A2 50 s.
  What varied was storage latency during checkpoints (sync phases of 22–53 s in A1, at most 4.2 s
  in A2). What made storage slow during A1 was not identified.
- **Disposition.** Explained; not a product defect. No timeout or retry was added. The README now
  states the constraint and the two measured mitigations (a throwaway server with `-c fsync=off`,
  or `--maxWorkers=3`). Whether to change the default worker count is left open.

### 5.2 Transient database connection failure (partly explained, open)

- The earlier failure was Prisma's `P1001` ("Can't reach database server") during `migrate
deploy`, whose connect timeout defaults to 5 s.
- In A1 the server logged 1,241 connections: p50 17 ms from arrival to authentication, but 7 took
  over 5 s (worst 43 s), and **all 7 fell inside forced checkpoints**. Peak client connections were
  58 of 100, so the limit was not reached.
- No `P1001` occurred in the four instrumented runs, so the link is strongly suggested, not
  observed. Open.

### 5.3 WebKit migration test showing the welcome screen (explained)

- **Cause.** `test:migrate` locks while the browser context is offline, and locking starts a new
  worker whose script must load. In a passing trace, that script request started at 14.860 s and
  the context came back online at 14.863 s. Making the test wait for the lock screen before going
  online turned the race into a reliable failure in WebKit (welcome screen while offline, 1 of 1).
  When the load fails, the app shows the welcome screen (F-5, reproduced in all three engines).
- **Earlier tally.** 1 failure in 10 runs; the next 9 passed.
- **Test fix.** The spec now reloads the page online after the offline lock, before unlocking, so
  it starts from stored state. Two other attempts were tried and rejected, with evidence kept:
  waiting for the lock screen (reproduces F-5) and blocking only the API origin (Chromium's
  worker-originated requests bypass the context route, so the note synced). With the reload:
  Chromium, Firefox and WebKit pass, and 3 more WebKit runs pass.
- **F-5 stays open** as an application defect; whether real Safari fails the offline worker load
  was not tested.
- **Also found.** A Firefox run timed out (240 s) waiting for a Save button: the test opened the
  next editor before the previous save finished, and the late completion replaced the editor
  (F-20). The spec now waits for the save. Afterwards all three engines pass.

## 6. D-31 assessment

**Traced:**

- normal and pre-proof login;
- changed-password unlock, including the previous-password path;
- setup;
- pairing;
- fresh-browser recovery;
- both reopening paths;
- revocation, including a replay after a lost reply, and refresh;
- device-key storage, lock and extension resume;
- where `AVSK` is required;
- the transcripts.

**Results:**

- No authorization bypass was found. No password-only or `RAK`-only path registers a `DPK` or
  `AVPK`.
- `AVPK` is written only by registration.
- For every operation, client and server payload fields match one for one, and they cover every
  field the server writes. Op 3 omits some stored fields (F-23).
- `DSI` and `AKSI` are domain-separated. Payloads are length-prefixed and include the op code.
- Nonces are hashed and bound to a session and an operation. They expire after 2 minutes, are
  issued under the session row lock, and are consumed in the effect's transaction. They are
  deleted on restore.
- No circular dependency was found: the changed-password path uses the pre-proof `GET
/account/keys` to reach `DSK`.

**Mismatches with device-proof.md, none a vulnerability:**

- §8's pairing order: the code proves B's session before reading the reply.
- §5 step 4: the previous-password login is unproven, then op 2.
- §5 table: an active device with no `DPK` that sends a proof gets `401`.
- §6 "never reuse": see S-4.
- §9: `recovery/start` charges the recovery throttle before answering `migration_required`.
- Reopening a pre-D-31 snapshot by the password path answers `reopen_failed` and counts against
  the code, not `migration_required`.

**Limitations as designed** (these are properties of D-31, not defects):

- Possession is proven once per session, not per request. Stolen proven sessions keep tier 2
  (F-1 builds on this).
- `AK` never rotates, so anyone who ever held it keeps the account-key proof.
- `DSK` is protected only by `K_local`, which every `AK` holder can derive.
- Code running in an unlocked origin can sign.
- A valid signature proves possession of a key for one payload. It does not prove that an uploaded
  wrap or envelope decrypts correctly: an `AK` holder can still install garbage wraps.
- A malicious server or database writer ignores proofs. Clients verify nothing D-31-specific.

## 7. Coverage gaps

- **Missing tests:**
  - two engines or tabs on one store (F-2);
  - a fake server that refuses duplicate items like the API does (F-3);
  - a password change on a device holding an older keyset (F-4);
  - the guard's fail-closed paths (a handler without `@Access`, recovery or reopen levels outside
    their controllers);
  - losing and re-taking the instance lock while running;
  - restore with changed table definitions;
  - R15's truncated-archive variant;
  - CSRF on all six other `none` routes;
  - R16 for token, recovery and reopen sessions;
  - recovery keeping an in-flight commit, an anchor or an import;
  - zeroing on reopen, pairing and revocation;
  - a 5xx with a non-contract body during pairing.
- **Not run:** Safari, the extension outside Chromium, two API processes, fuzzing, load tests,
  remote CI.

## 8. Can a private synthetic deployment rehearsal proceed?

_Updated by §10: F-1 to F-4 are now fixed, so condition 1 is met and condition 4 is no longer needed._

**Not yet; it can after one bounded fix batch.** No finding exposes vault keys or plaintext to the
server, and nothing here concerns real data, which stays blocked by D-19. But F-1 and F-4 break
recovery and unlock, which are exactly what a rehearsal exercises, and F-2 and F-3 lose or wedge
local changes in normal use.

Conditions for the rehearsal:

1. F-1 to F-4 are fixed, and their reproductions pass without `it.fails`. Alternatively, the owner
   explicitly accepts each one for the rehearsal.
2. Synthetic data only, and one API process per database.
3. The production database keeps `fsync` on. The `fsync=off` advice is for throwaway test servers
   only.
4. One open tab per browser profile until F-2 is fixed.
5. No accounts from before D-31.
6. The rehearsal records F-5 to F-19 as known issues.

## 9. Remaining blockers

1. F-1, F-2, F-3, F-4 (Medium): before the rehearsal, or explicitly accepted by the owner.
2. F-5 to F-19 (Low): before real data, each fixed or explicitly accepted.
3. S-1 to S-3: confirm or refute.
4. The connection-failure item (§5.2) stays open until it is observed or ruled out.
5. D-19: an independent review of `1702ea6` plus whatever fixes follow. This report is not one.
6. The real-data restrictions remain in force.

## 10. Fix batch for F-1 to F-4 (2026-10-27)

Made after this review, on top of `6576324`; the commit that adds this section (`bdf5ba5`). It changes
application code, so a later review covers `1702ea6` **plus this commit**. Still not D-19.

| Finding | Change                                                                                                                                                                                                                                                                                                                                                                                          | Test                                                                                                                                                                                                |
| ------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F-1     | `DELETE /sessions/{id}` ends only `cookie` and `token` sessions; a `recovery` session is refused with `forbidden` (account-security.service.ts `endSession`). A new Recovery Kit, which needs the account-key proof, still ends it. The devices screen labels a recovery session and offers no sign-out for it.                                                                                 | `followup-repro.int-spec.ts` F-1 passes without `it.fails`, and now also asserts the 403                                                                                                            |
| F-2     | The web app runs the vault in one tab per browser profile: the page holds a Web Lock (`apps/web/src/vault/tab-lock.ts`) before it starts the worker. Another tab shows "Ruvee is open in another tab"; **Use it here** asks the holder over a BroadcastChannel to let queued operations finish (`settle`, at most 5 s), lock and let go. A browser without Web Locks is treated as unsupported. | `two-devices.spec.ts` hands the vault to a second tab and back, in Chromium, Firefox and WebKit. The engine-level reproduction stays `it.fails` on purpose: the engine itself remains single-writer |
| F-3     | Choosing "Keep mine" for a deletion replaces any edit queued for that item during the conflict, so a commit never names an item twice.                                                                                                                                                                                                                                                          | F-3 passes without `it.fails`, and now also checks that the deletion reaches the other device                                                                                                       |
| F-4     | Before re-wrapping, `changePassword` adopts a newer keyset with `AK` (the same `refreshKeyset` used at unlock), and refuses (`changed_elsewhere`) unless the server's keyset version then equals this device's.                                                                                                                                                                                 | F-4 passes without `it.fails`                                                                                                                                                                       |

What is left after these fixes:

- F-2: the handover discards an unsaved editor draft in the tab that lets go. If an operation
  takes longer than 5 s, it is cut off the same way a normal lock cuts it off. The extension
  was not changed: it runs one engine in its service worker.
- F-4: the server still cannot tell which `SK` is under a new password wrap, so another client
  could repeat the mistake. Binding the keyset version into the `password_change` proof is a
  protocol change, and it is left to the owner's decision.
- F-5 to F-19, S-1 to S-5 and §5.2 are unchanged.

Tests run on this commit:

- vault unit tests: 99 passed, 1 expected fail (F-2 engine), 1 skipped;
- every other package's unit tests;
- the API integration suite: 27 files, 183 passed, 1 expected fail (F-6). This was run F2-fixes.
  Run F1-fixes failed in the restore suites only because the host's `pg_dump` 14 was used
  (environment; evidence kept);
- `test:vault`, `test:migrate`, `test:import` and `test:restore` in Chromium, Firefox and WebKit;
- the default web e2e;
- lint, typecheck and format.

Every run used a task-owned PostgreSQL 18.6 container with `fsync=off`. Not run: Safari, the
extension e2e, remote CI.

**Rehearsal:** with this commit, a private synthetic rehearsal can proceed under §8 conditions 2, 3,
5 and 6. That means synthetic data only, one API process per database, `fsync` on, no pre-D-31
accounts, and F-5 to F-19 recorded as known issues.

## 11. Remediation batch 2 (2026-10-28)

Made on `vault/web-vault` after PR #1's first CI run at `ad31918`, which established a clean Linux
baseline and nothing more. Each fix below has a regression that was run against the code before
the fix and failed there, on the assertion stated. This is still not D-19, and the real-data
restrictions stand.

Three intermediate commits did not pass lint or typecheck on their own and were fixed by the next
commit (`b306603` by `a0eb89a`, `05bd217` by `d5e298f`, `a7bb0be` by `1158b5c`). History was not
rewritten; review the batch as a whole.

### 11.1 Fixed findings

| Finding     | Commit    | Boundary and change                                                                                                                                                                                                                                                                               | Regression (fails on the old code)                                                                                                                                                                                                                                                       |
| ----------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F-6         | `b3f16fc` | Authentication choice and CSRF are decided together in `access.guard.ts`: a bearer token exempts a request from the CSRF checks only on routes that authenticate it (`session`, `active`, `step-up`). Any of the three cookies together with a bearer token is refused, as is a malformed header. | `f6-csrf-bearer.int-spec.ts`: all nine unauthenticated write routes with no header, a fake, a real and a foreign-origin bearer, malformed values, and each cookie mixed with a bearer; real bearers on authenticated routes; bearers on recovery routes. 28 of 69 fail on the old guard. |
| F-2         | `b306603` | The device store had no writer coordination. The engine that loads state claims the store; a write by an engine that loaded earlier is refused in its own IndexedDB transaction, and that engine locks with `open_elsewhere`. The web tab lock (`bdf5ba5`) stays in front of it.                  | `followup-repro.test.ts`: the earlier engine's save is refused and reported, never silently lost, and it keeps no keys. Two of three fail on the old store; the third guards edits saved before the second engine opened.                                                                |
| F-5         | `1da2d77` | A worker that fails to start is no longer read as a new device. The app shows "Ruvee couldn't start" with Reload, and the worker no longer caches a failed start.                                                                                                                                 | `two-devices.spec.ts` aborts every request at lock, expects that screen and no "Create an account", then reloads and unlocks. On the old lock code the screen never appears. Passes in Chromium, Firefox and WebKit.                                                                     |
| F-7         | `7525ca8` | The peer, `TRUSTED_PROXY_ADDRESS` and forwarded hops are compared in one canonical form. A forwarded header from a peer that is not the proxy is now logged once.                                                                                                                                 | `client-info.spec.ts`: upper-case, expanded and IPv4-mapped spellings.                                                                                                                                                                                                                   |
| F-8         | `b9811dc` | A full limiter table evicts expired windows, then windows under their limit. A refused address is dropped only when all are.                                                                                                                                                                      | `throttle-windows.spec.ts`: a refused address stays refused through a flood of 25,000 new ones.                                                                                                                                                                                          |
| F-10, F-11  | `ced2ffa` | One pre-proof lapse rule. The 10 minutes start at the later of login and device enrollment (pairing approved late still completes), and refresh applies the same lapse.                                                                                                                           | `pairing.int-spec.ts` with a 30-minute-old pending session; `r2-r3-login.int-spec.ts` refreshing an 11-minute-old unproven token session. Two existing tests now also age `enrolled_at`, so they still describe a device that has been active that long.                                 |
| F-12, F-13  | `73e8fd9` | `exclusive` clears a session that a failing operation installed, and everything when a lock overtook it.                                                                                                                                                                                          | An unlock whose stored device key does not open; the same with a lock during it.                                                                                                                                                                                                         |
| F-14        | `66f17ca` | Setup, pairing and both recovery paths store the active device record, its key and its checkpoint (and the pairing anchor) in one transaction.                                                                                                                                                    | Store spies: exactly one write makes the device active, and it carries all parts (setup and pairing).                                                                                                                                                                                    |
| F-15        | `29ff3cf` | An error status whose body is not the API's is `unexpected_error`, apart from a malformed success (`unexpected_response`). Only the latter burns a pairing.                                                                                                                                       | Pairing stays hosted through a 502 page and still burns on a malformed reply; the API client tells the two apart.                                                                                                                                                                        |
| F-17        | `05bd217` | `device_proof_failed` maps to `proof_rejected` ("nothing changed; try again"), not to re-enrollment. Re-enrollment is still advised for `device_proof_required`.                                                                                                                                  | A refused secret-key rotation reports `proof_rejected`, and the retry succeeds.                                                                                                                                                                                                          |
| F-18        | `134ad48` | Recovery completion reads its session and device `FOR UPDATE` inside the transaction, as reopening does (R13).                                                                                                                                                                                    | The device is revoked between authentication and the transaction. Old code: 200, and the device is active again.                                                                                                                                                                         |
| F-19 (part) | `a7bb0be` | A revoked device zeroes `AK`, `VK` and its device key. A recovery start refused for local data derives no keys.                                                                                                                                                                                   | The captured key arrays are all zero afterwards.                                                                                                                                                                                                                                         |
| F-9         | `2b1088a` | Fill visibility multiplies `filter: opacity()`, refuses clip paths, legacy `clip` and transparent text, and hit-tests with every element taking part (a `pointer-events: none` overlay no longer hides).                                                                                          | The extension e2e adds four hidden fields; the old fill code fills the page. Aggregate only: which of the four the old code filled was not measured.                                                                                                                                     |

### 11.2 Suspected issues

- **S-1, confirmed and fixed (`401d7b0`).**
  - **Reproduction:** a TCP relay dropped traffic silently while the server ended the lock's backend. The lock was free and another connection took it, yet the process went on serving with no limit (`s1-instance-lock.int-spec.ts`).
  - **Fix:** the holder now checks every 10 s, on its own connection, that the lock is granted, bounded by `READINESS_DB_TIMEOUT_MS` and with TCP keep-alive.
  - **Residual:** two processes can overlap for about one interval plus that timeout.
- **S-2, confirmed and fixed (`8b18090`).**
  - **Reproduction:** five backups restored successfully even though one of their allowed tables had a dropped CHECK constraint, a dropped unique index, a changed default, an extra column or a changed type.
  - **Fix:** APPLY POLICY now compares a fingerprint of the migrated public schema with `EXPECTED_SCHEMA`. `schema-fingerprint.int-spec.ts` keeps that constant equal to a freshly migrated database.
  - **Residual:** the fingerprint covers columns, defaults, constraints, indexes, enums and sequences, but not storage parameters, statistics targets or comments. A PostgreSQL release that prints definitions differently would refuse restores until the constant is updated, which is a fail-closed outcome.
- **S-3, mechanism confirmed, contained; not changed.**
  - **Reproduction:** given a complete archive followed by trailing bytes, `pg_restore --single-transaction` committed and exited 0 within a second, while its input was still open.
  - **What that means for LOAD:** holding back the last chunk is not a commit barrier. A Ruvee backup whose dump is a complete archive followed by 256 KiB of extra bytes restored successfully; the extra bytes were never read.
  - **The real barrier:** VERIFY checks every byte before LOAD starts, against the metadata and the trusted digest, and the staged copy is private (R9). Unverified bytes can reach `pg_restore` only if that staged file changes between the two passes. In that case LOAD's check fails after the commit, the guard stays `restoring`, and the operator is told to discard the database.
  - **Evidence:** a script and outputs in the session's evidence folder (`s3-repro/`). No repository test was kept, because the only stable assertion would lock in the acceptance of trailing bytes.
- **S-4, S-5:** not investigated in this batch; unchanged.

### 11.3 Still open

- **F-16** (a conflict draft is replaced when the same item conflicts again). Not specified: sync-protocol §6 describes one conflict per item. It needs a decision: keep the older draft, the newer one, or both as items.
- **F-19, the rest:** second copies on reopening with the password, failed `pairingWait`, `adoptServerKeys`, and the unlock paths not covered by F-12. Zeroing in JavaScript stays best-effort.
- **F-20 to F-25** (Info), **S-4, S-5**, §5.2 (connection failure), and the coverage gaps in §7 not named above.
- **F-4, server side:** see §11.4.
- **No expected failures remain:** every reproduction in `followup-repro.*` is an ordinary passing test.

### 11.4 F-4: the protocol decision (not implemented)

- **What it addresses.** Device B has not seen a Secret Key replacement made on A. B fetches the account keys _after_ the replacement, so `expectedRowVersion` is current and the server's `row_version` check passes, then wraps `AK` under its old `SK`. The server cannot see which `SK` is under the wrap, so it accepts. This locks out every device holding the current `SK` and undoes the replacement. The client fix (`bdf5ba5`) makes the web and extension engines adopt the newer keyset first. Nothing on the server stops another client (mobile, or a future one) from repeating it. A race between B's read and A's rotation is already caught: rotation increments `row_version`.
- **Version to bind.** The `keyset_version` whose `SK` the client used to derive `AUK'` for `wrappedAkPassword`. After the client fix, that is the version it just adopted, and it must equal the server's current `account_keys.keyset_version`.
- **Transcript.** Add `keysetVersion` to `passwordChangeFinishRequestSchema`. Op 4's signed payload becomes `registrationRecord, u8(kdfProfile), saltPw, wrappedAkPassword, u64(expectedRowVersion), u32(keysetVersion)`, encoded as op 5 (`secret_key_rotate`) already encodes it, and signed by both the device and `AK`. Old signatures no longer verify, so this is a deliberate breaking change of op 4. With no deployed clients that is acceptable, but every client must change together.
- **Server check.** Inside the existing transaction, after the nonce is consumed: `UPDATE account_keys … WHERE account_id = $1 AND row_version = $2 AND keyset_version = $3`. Zero rows means one of the two moved. Both return `409 row_version_conflict`, which the client reports as `changed_elsewhere`. Nothing changes, and the nonce rolls back (S-4).
- **Stale clients and retries.**
  - A client that gets the conflict runs `refreshKeyset` (adopting the newer `SK` with `AK`), fetches a new nonce, and the user tries again. Each retry is a new signature over the new version; nothing is retried automatically.
  - A client still on the old op-4 payload gets `400 invalid_request` (missing field) or `401 device_proof_failed` (signature over the old layout), and changes nothing.
- **Compatibility.** Shared contract change: the mobile app must send and sign `keysetVersion`. Recovery and reopening completions also write a password wrap. They take `SK` from the keyset they just read, so `row_version` already protects them, but the same binding could be added there for uniformity.
- **Question for the owner:** approve binding `keysetVersion` into op 4 as above, as a breaking change to `password_change` for all clients (web, extension, mobile), with the server refusing a mismatch as `row_version_conflict`?

### 11.5 Shared changes the mobile session must take in

The mobile branch (`mobile/vault-app`, worktree `ruvee-mobile`) was not touched. When it rebases onto this batch:

1. **CSRF (F-6).** On the unauthenticated routes (login, refresh, registration, recovery and reopening starts), a request needs `Origin` and `X-Ruvee-Request: 1` even when it carries a bearer token. The app's current approach (SC-3 option 1: send the server origin) passes this unchanged. Any Ruvee cookie together with a bearer token is refused; the app already sends no cookies.
2. **New client error codes.**
   - `VaultErrorCode` gains `open_elsewhere` (F-2) and `proof_rejected` (F-17).
   - The `ended` event gains the reason `open_elsewhere`.
   - `NetworkError.reason` gains `unexpected_error` (F-15).
   - The app's message mapping and its ended-event handling should cover them. `device_proof_failed` no longer means "re-enroll".
3. **Device store (F-2, F-14).**
   - The engine calls `store.claim()` when it loads state, if the store has one; writes of an engine that lost the claim must be refused with `StoreTakenError`. The mobile store has none, which is correct for one engine per process. Add one only if two engines can ever share it.
   - Enrollment now writes `device` together with `local` (`checkpoint`, `anchor`, `device-key`) in one `apply` call. The mobile store's `apply` must write both atomically.
4. **Pre-proof lapse (F-10, F-11).** A refresh of an unproven token session of an active device fails with `session_expired` once 10 minutes have passed since the later of the login and the enrollment. The engine proves right after login and pairing, so nothing changes for a correct client.
5. **Worker protocol.** `VaultMethods` gains `settle` (used by the web tab handover). It is in the shared dispatch; the mobile UI does not need it.
6. **If F-4 is approved:** `passwordChangeFinishRequest` gains `keysetVersion`, signed into op 4. Every client must change at the same time.
