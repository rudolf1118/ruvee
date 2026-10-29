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
- Two more instrumented runs (§16.5) also had no `P1001`, and connection set-up never exceeded
  0.27 s. Still not reproduced.
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
  - **Residual:** two processes can overlap for about one interval plus that timeout. What that
    overlap does and does not affect is in §16.6; it is not accepted.
- **S-2, confirmed and fixed (`8b18090`).**
  - **Reproduction:** five backups restored successfully even though one of their allowed tables had a dropped CHECK constraint, a dropped unique index, a changed default, an extra column or a changed type.
  - **Fix:** APPLY POLICY now compares a fingerprint of the migrated public schema with `EXPECTED_SCHEMA`. `schema-fingerprint.int-spec.ts` keeps that constant equal to a freshly migrated database.
  - **Residual:** the fingerprint covers columns, defaults, constraints, indexes, enums and sequences, but not storage parameters, statistics targets or comments. A PostgreSQL release that prints definitions differently would refuse restores until the constant is updated, which is a fail-closed outcome.
- **S-3, mechanism confirmed, contained; not changed.**
  - **Reproduction:** given a complete archive followed by trailing bytes, `pg_restore --single-transaction` committed and exited 0 within a second, while its input was still open.
  - **What that means for LOAD:** holding back the last chunk is not a commit barrier. A Ruvee backup whose dump is a complete archive followed by 256 KiB of extra bytes restored successfully; the extra bytes were never read.
  - **The real barrier:** VERIFY checks every byte before LOAD starts, against the metadata and the trusted digest, and the staged copy is private (R9). Unverified bytes can reach `pg_restore` only if that staged file changes between the two passes. In that case LOAD's check fails after the commit, the guard stays `restoring`, and the operator is told to discard the database.
  - **Evidence:** a script and outputs in the session's evidence folder (`s3-repro/`). No repository test was kept, because the only stable assertion would lock in the acceptance of trailing bytes.
- **S-4:** fixed with the owner's option B (§15.5). **S-5:** not investigated; unchanged.

### 11.3 Still open

- **F-16:** fixed with the owner-approved behaviour (§16.1).
- **F-19, the rest:** fixed in §13 (`51432e2`), with the limits of zeroing in JavaScript stated there.
- **F-20 to F-25, S-5, §5.2 and the S-1 residual:** dispositions in §16. F-25 was implemented
  after the owner approved it (§17.1). Still open: F-22 and F-23 (informational), §5.2 (not
  reproduced), and the S-1 overlap (a design decision; recommendation in §17.2). Also the
  coverage gaps in §7 not named above.
- **F-4, server side:** implemented in §12, with the residual stated there.
- **No expected failures remain:** every reproduction in `followup-repro.*` is an ordinary passing test.

### 11.4 F-4: the protocol decision (approved and implemented in §12)

- **What it addresses.** Device B has not seen a Secret Key replacement made on A. B fetches the account keys _after_ the replacement, so `expectedRowVersion` is current and the server's `row_version` check passes, then wraps `AK` under its old `SK`. The server cannot see which `SK` is under the wrap, so it accepts. This locks out every device holding the current `SK` and undoes the replacement. The client fix (`bdf5ba5`) makes the web and extension engines adopt the newer keyset first. Nothing on the server stops another client (mobile, or a future one) from repeating it. A race between B's read and A's rotation is already caught: rotation increments `row_version`.
- **Version to bind.** The `keyset_version` whose `SK` the client used to derive `AUK'` for `wrappedAkPassword`. After the client fix, that is the version it just adopted, and it must equal the server's current `account_keys.keyset_version`.
- **Transcript.** Add `keysetVersion` to `passwordChangeFinishRequestSchema`. Op 4's signed payload becomes `registrationRecord, u8(kdfProfile), saltPw, wrappedAkPassword, u64(expectedRowVersion), u32(keysetVersion)`, encoded as op 5 (`secret_key_rotate`) already encodes it, and signed by both the device and `AK`. Old signatures no longer verify, so this is a deliberate breaking change of op 4. With no deployed clients that is acceptable, but every client must change together.
- **Server check.** Inside the existing transaction, after the nonce is consumed: `UPDATE account_keys … WHERE account_id = $1 AND row_version = $2 AND keyset_version = $3`. Zero rows means one of the two moved. Both return `409 row_version_conflict`, which the client reports as `changed_elsewhere`. Nothing changes, and the nonce is spent (S-4, §15.5).
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
6. **F-4 (approved; §12).** The password change is now op 12 with a signed `keysetVersion`. The exact handoff is [mobile-handoff-f4.md](../planning/mobile-handoff-f4.md).

## 12. F-4: password change bound to the keyset version

Owner approval (2026-10-28), for development, with conditions: check that `keysetVersion` really
versions the Secret Key, state the actual guarantee, and test a malicious stale client. Commit
`01e8a35`, documented in `7dd94a7`. Its parent is `4249cbe`, a branding commit (icons and a dark
theme) made in this checkout while this work ran; it is not part of F-4 and is described in §14.
Still not D-19; the real-data restrictions stand.

### 12.1 Is `keyset_version` the Secret Key's version?

- **As built, yes, and it is the only identifier there is.** `account_keys.keyset_version` is
  set to 1 at registration and changed only by `POST /account/secret-key`, which requires
  exactly the next version and replaces the keyset (holding `SK`) and the password wrap in one
  statement. No other code writes it (recovery and reopening read it). There is no separate `SK`
  id.
- **It is a keyset version, not an `SK` version.** The design also changes it on vault creation
  and on full rotation (sync-protocol.md §10); neither is built. Once they are, a version change
  without a new `SK` makes a password change from a device that has not yet read the new keyset
  fail with `409`, and the user's next attempt succeeds after adopting it. For an honest client
  that is a refusal it did not need, not the acceptance of a stale wrap. A client that claims a
  version its `SK` did not come from is not covered by this argument (§12.3). Full rotation also
  changes `AK`, which the envelope's `ak_id` and `ak_epoch` already bind.
- The client signs the version **of the keyset its `SK` came from** (`enrolled.keysetVersion`),
  not the server's current value, so an honest stale client is refused rather than carried along.

### 12.2 The protocol change

- **Explicit version.** A new operation code, **op 12 `password_change_v2`**. Op 4 is retired: no
  nonce is issued for it, `@ruvee/crypto` no longer encodes it, and the code is never reused.
  Every signed input carries `u8(op)`, so no op-4 signature verifies as op 12.
- **Payload.** `registrationRecord`, `u8(kdfProfile)`, `saltPw`, `wrappedAkPassword`,
  `u64(expectedRowVersion)`, `u32(keysetVersion)`, signed by both `DSK` (DSI) and `AVSK` (AKSI).
- **Contract.** `passwordChangeFinishRequestSchema` requires `keysetVersion` (u32), and stays
  strict. A body without it, or with a value outside u32, is `400 invalid_request`. There is no
  fallback to the old format.
- **Server.** After both signatures verify, in one transaction: consume the nonce, then
  `UPDATE account_keys … WHERE account_id AND row_version = expected AND keyset_version =
claimed`. Zero rows is `409 row_version_conflict`, and the whole transaction rolls back: the
  OPAQUE record, the wrap, the sessions and the security events are untouched.
- **Client (web and extension, shared engine).** `changePassword` first adopts a newer keyset
  through the existing rotation protocol (`refreshKeyset`): it opens the keyset with the `AK` it
  holds, and keeps the new `SK` only if the server's wrap opens with it and the step-up password.
  It then refuses locally (`changed_elsewhere`) unless the server's version equals its own, and
  signs that version. A
  `409` is shown as `changed_elsewhere`. Nothing retries on its own.

### 12.3 What it guarantees, and what it does not

- **Guaranteed:** the server installs a password wrap only if the request's signed, claimed
  keyset version is the account's version at the moment of the write, together with the row
  version. For an **honest client**, one that reports the version its `SK` came from, a stale
  wrap is refused, including after it re-read `row_version` following the rotation (the original
  F-4 sequence), and nothing changes. The guarantee is only as good as that report.
- **Not guaranteed: that the wrap was made with that version's `SK`.** The server cannot open the
  wrap (device-proof.md §3). **Residual attack, confirmed by test:** an active device that holds
  `DSK` and `AK` reads the current version from `GET /account/keys`, claims it, signs with both
  keys, and uploads a wrap under the old `SK`; the server accepts. Devices with the current `SK`
  then cannot open the server's wrap, and the old `SK` opens it again, so the rotation is undone.
- **Status: open.** This is a threat-model decision for the owner, and it has not been made: the
  residual is **not accepted**. Facts for that decision: a device holding `AK` already defeats
  what an `SK` rotation protects (cryptographic-design §6.2: only full rotation helps against
  it), and it can also read the new `SK` from the keyset; a revoked device cannot do it, because
  its sessions end and its proofs no longer verify. Closing it would need a new mechanism (for
  example a proof tied to `SK` itself), which this change does not invent.

### 12.4 Nonces, retries and lost answers

- A refused signature burns the nonce. Since §15.5, a `409` spends it as well: the transaction
  rolls back and the nonce is then marked consumed, so the same request, or another payload
  under that nonce, is refused with `device_proof_failed`. (Before §15.5 the nonce reopened with
  the rollback.)
- If the server applied the change but the answer was lost, replaying the same request fails
  (`device_proof_failed`, the nonce is spent) and changes nothing. The engine does not retry. Its
  local wrap stays under the old password. The user gets in with the new password through the
  existing path (the local wrap does not open, so it logs in without proof and opens the server
  wrap with its `SK`), as on any device whose password changed elsewhere.

### 12.5 Regression evidence

`apps/api/test/review/f4-password-keyset.int-spec.ts` (real database, one installation per test):

| Test                                                  | What it shows                                                                                                                                                         |
| ----------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| applies a change made with the current SK and version | the valid path: 204, row version +1, keyset version unchanged, new wrap opens with the new password and `SK`                                                          |
| refuses the old format                                | no `keysetVersion`, a value outside u32, a nonce for `password_change`, and proofs over the old five fields: all refused, nothing changes                             |
| refuses a stale version after SK rotation             | the F-4 sequence: fresh `row_version`, honest old version → 409, and a higher version → 409; everything unchanged; after adopting `SK'` the retry succeeds            |
| each proof covers every field                         | each of five fields altered, with only one of the two proofs over the altered body: 10 × `device_proof_failed`, nothing changes                                       |
| a concurrent SK rotation and password change          | three races: exactly one wins, and the server's wrap always opens with the `SK` of the keyset it ends up with                                                         |
| a lost response and a retry                           | a replay after success is refused; a refused request stays refused; a new nonce replaces the open one                                                                 |
| residual: a client holding DSK and AK ...             | the server **takes** the malicious stale client's request; the wrap then opens with the old `SK` and not with `SK'`. It records the open limit; it is not a guarantee |

`packages/vault/src/review/followup-repro.test.ts` adds two engine tests: a rotation that lands
between the client's check and its write is refused, the signed version is the one the client
held, nothing is retried, and the user's next attempt succeeds; a lost answer is not retried, a
second attempt with the old password fails at step-up without changing anything, and the new
password unlocks. The earlier F-4 client test still passes.

**Against the vulnerable server.** With the `keyset_version` condition removed from the update,
the stale-version test fails (the server installs the stale wrap). With the version left out of
the server's signed payload, six of seven tests fail (no proof verifies). The race test does not
depend on the new check: `row_version` already serialises a rotation and a change; the new check
closes the case where `row_version` is fresh and the `SK` is not.

### 12.6 Compatibility

- **Web and extension:** updated (one shared engine) and tested.
- **Mobile:** **pending.** The mobile branch was not touched and is based on `bdf5ba5`, before
  op 12. Until it takes [mobile-handoff-f4.md](../planning/mobile-handoff-f4.md) and runs its
  tests against this server, its password change fails with `400` and changes nothing. Not all
  clients are updated.
- Recovery and reopening completions (ops 9, 11) also write a password wrap. They take `SK` from
  the keyset they just read under `row_version`, so they were left unchanged.

## 13. F-19: key lifetimes in the client engine

Commit `51432e2` (`packages/vault`). It completes the partial fix in §11.1 (`a7bb0be`). Still not
D-19; the real-data restrictions stand.

### 13.1 Ownership rule

Each engine operation owns every key buffer it derives, unwraps or reads from the device store
(`KeyScope` in `key-scope.ts`). The crypto layer returns new buffers that the caller owns
(operations.ts). The device store returns a new copy of the device record on every read
(store.ts, now documented as part of its contract).

When an operation hands a buffer to something that outlives it, it **releases** it. That holder
is the session, a pending recovery or pairing, or the device record held in memory, and the lock
zeroes it later. Whatever the operation still owns when it settles is zeroed, whether it returned
or threw. Buffers the caller passed in are never owned.

| Path                                      | Owner, and when ownership moves                                                                                                                                                                                                                    | Zeroed                                                                                                                                                                  |
| ----------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| unlock (local wrap)                       | `unlock` owns the stored `SK`, `AK` and the keyset's `SK` and `VK`. Once the session exists it takes `SK`, `AK` and `VK`.                                                                                                                          | The keyset's `SK` copy, always. On a wrong password, a failed write, a refused or missing device, or a lock: everything.                                                |
| unlock with the server wrap               | As above. `AK` comes from the server's wrap.                                                                                                                                                                                                       | `AK` if the device write fails. That failure is now reported as itself, not as `wrong_password`.                                                                        |
| unlock with the previous password         | `adoptServerKeys` puts the new `SK` and a second `AK` and `VK` in the unlock's scope. The session takes the new `SK`.                                                                                                                              | The second `AK`, the `VK` copy, and the old stored `SK` (after the write). On a wrong new password or a failed write: everything. A failed write is reported as itself. |
| adopting a rotated `SK` (`refreshKeyset`) | `refreshKeyset` owns the newer keyset's `SK` and `VK`. The session takes the new `SK` only after the device write committed.                                                                                                                       | The `VK` copy, always. The old `SK`, after the write. The new `SK` if the write fails or a lock overtakes it; the next unlock adopts it again.                          |
| resume (extension restart, D-27)          | The host's `AK` stays the host's. The engine copies it, and the session takes the copy, the stored `SK` and `VK`.                                                                                                                                  | The keyset's `SK` copy. On a key that does not open the keyset: everything the engine made.                                                                             |
| `pairingWait` (device B)                  | It owns the received `SK`, `AK` and the keyset's `SK` and `VK`; the session takes `SK`, `AK` and `VK`. The pairing (code secret, ephemeral key, device key) belongs to `joining` until success; the session stores its own copy of the device key. | On any failure or lock: what was received. A failure after the session existed discards the pairing too (F-12), and the user starts the pairing again.                  |
| pairing cancelled                         | `joining`                                                                                                                                                                                                                                          | Everything (unchanged; kept as a guard test).                                                                                                                           |
| `recoveryBegin`, `reopenBegin`            | The pending recovery takes `AK` and the keyset's `SK` and `VK`.                                                                                                                                                                                    | A second start zeroes the first one's keys before it replaces them.                                                                                                     |
| reopening with the password, finish       | The reopening's `AK`, `SK` and `VK` are separate copies, equal to the session's keys.                                                                                                                                                              | Those copies, when it finishes. The session keeps its own.                                                                                                              |
| `setupFinish`, `recoveryFinish`           | The generated device key, until the session's copy is stored.                                                                                                                                                                                      | Always: after success, or when the request or the write fails.                                                                                                          |
| `rotateSecretKey`                         | The new `SK`, until the write after the server's acceptance. The session takes it then, and the old `SK` is zeroed.                                                                                                                                | The new `SK` on a refused or lost request, a failed write or a lock. A device that missed the result adopts `SK'` from the keyset later, under `AK`.                    |
| lock and logout (`clearMemory`)           | (none)                                                                                                                                                                                                                                             | Now also the session's `SK`, along with `AK`, `VK`, the device key and the pending setup, recovery and pairing.                                                         |
| reads for status only                     | `phase`, `setupBegin`, `login`, `pairingJoin`, `pairingWait` and `recoveryBegin` read the record only for its ids and status.                                                                                                                      | The record's `SK` copy, at once.                                                                                                                                        |

**A lock that overtakes an operation.** The lock zeroes, at once, what the session and the
pending setup, recovery and pairing hold. Keys still inside a running operation's scope are zeroed
when that operation settles, not at the moment of the lock. That operation can neither write nor
install a session (R19), so the window lasts as long as its remaining network wait.

### 13.2 What this does not erase

Zeroing is best-effort. It reaches only the `Uint8Array`s the engine holds, and it is not memory
erasure.

- **Strings** cannot be overwritten. This covers:
  - passwords and `pendingPassword`;
  - base64 forms of keys: `RAK` in the recovery request, the device key's JSON before it is
    sealed, and `AK` in `chrome.storage.session` while the extension is unlocked (D-27);
  - decrypted item bodies, which `bodies.clear()` only drops;
  - API response JSON.
- **Runtime copies** are out of reach: the structured clones IndexedDB makes, copies the garbage
  collector moves, and buffers the runtime allocates for encoding.
- **Library memory** is out of reach: libsodium's WASM linear memory. The crypto layer wipes the
  intermediates it documents (operations.ts), and this was not checked separately.
- **Worker termination.** The web client sends `wipe` and terminates the worker after at most
  250 ms either way. A wipe that has not run by then leaves the memory to be released
  unoverwritten.
- **Extension restart.** A service worker the browser stops is not zeroed. Its `AK` survives as a
  base64 string in `chrome.storage.session` until the lock (D-27, unchanged).
- **The store contract.** The zeroing assumes every `DeviceStore` returns a new copy on every
  read and keeps no reference to buffers it was given. The IndexedDB store does both. The mobile
  store must be checked ([mobile-handoff-f19.md](../planning/mobile-handoff-f19.md)).
- **Buffers the tests do not capture.** The tests capture what the crypto interface and the
  store return. Copies the engine makes itself (for example `fromB64` of the stored device key)
  are not captured. The device key's zeroing on lock is covered by the earlier F-12 and R19 tests.

### 13.3 Regression evidence

`packages/vault/src/review/f19-key-lifecycle.test.ts` (engine with the real crypto and a
fake-indexeddb store) captures every secret key that the crypto layer returns and every `SK` the
store hands out. It then asserts which ones still hold a non-zero byte, by label only, so no key
bytes reach the logs. Successful paths also check that the keys kept still work: an item saved
afterwards opens on a later unlock.

- **21 tests.** 20 fail on the previous engine; the cancelled pairing passes on both and is a
  guard.
  - **Unlock:** a wrong password; a successful unlock keeps only `AK`, `VK` and the stored `SK`;
    a lock during the network wait; logout.
  - **Resume:** the caller's `AK` stays intact; a key that does not open the keyset.
  - **Adoption:**
    - a rotated `SK`, adopted; and with a failed write, after which the next unlock adopts it;
    - the previous-password path: success, a wrong new password, a failed write;
    - the server wrap with a failed write.
  - **Pairing:** a lock after approval; a failed write at enrollment, after which the pairing must
    start again; a completed pairing; cancel.
  - **Recovery and reopening:** a second recovery start; a recovery whose write fails; a
    password reopening.
  - **Setup and rotation:** a setup whose write fails; a refused `SK` rotation.
- **Behaviour change.** On the server-wrap and previous-password unlock paths, a failed device
  write used to be reported as `wrong_password`. It now surfaces as the failure it is: the
  worker reports it as `internal`, and a `StoreTakenError` as `open_elsewhere`.

### 13.4 Shared change for mobile

The engine and the store contract are shared. The mobile branch was not touched; what it must
adopt and check is in [mobile-handoff-f19.md](../planning/mobile-handoff-f19.md). Mobile
compatibility is **pending**.

## 14. Commit `4249cbe` (branding), outside this review

`4249cbe` "feat(brand): final mark, platform icons and a dark theme for web and extension" was
made at 13:35 on 2026-10-28 in the shared checkout. It is not part of the F-4 work, under the
configured identity, and reached PR #1 with the F-4 push (§12). Its scope (18 files, +215/−4):

- **`docs/brand/`:** the mark, favicon, app icon and Android foreground SVGs; light and dark
  colour tokens (`tokens.css`); and `render-icons.mjs`.
  - That script is a Node script that uses the Playwright Chromium to render PNGs.
  - It writes into this repository and also into a sibling `ruvee-mobile` checkout (its iOS and
    Android icon folders).
  - Neither the build nor CI runs it.
- **Web:** `icon.svg` and `apple-icon.png`; dark values for the colour tokens under
  `prefers-color-scheme` (`globals.css`); `theme-color` per colour scheme (`layout.tsx`).
- **Extension:** 16 to 128 px icons in the manifest and toolbar; dark token values,
  `color-scheme: light dark` and an input text colour (`styles.css`).
  - No permission, host permission, content-security policy or script changed.
  - No code that handles keys, the API or storage changed.

**Review status.** The owner chose a review (2026-10-28). It was done as below. The commit is
neither reverted nor approved; **visual approval is pending with the owner.**

### 14.1 Findings

| Check                            | Result                                                                                                                                                                                                                                                                                              |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Provenance and licences          | Seven hand-written SVGs of plain geometry: a rounded square, a circle and a line. No fonts, embedded images or third-party artwork, so no licence to track. The five PNGs are reproducible: the script's default run regenerates them byte for byte.                                                |
| SVG content                      | No `<script>`, event handler, `href`/`xlink:href`, `url()`, `<foreignObject>` or external reference. `favicon.svg` and the web `icon.svg` carry one inline `<style>` (a dark fill under `prefers-color-scheme`), which is inert in an image.                                                        |
| PNG content                      | Only the `IHDR`, `IDAT` and `IEND` chunks, with no text or metadata. Sizes are as named: 180, 16, 32, 48, 128.                                                                                                                                                                                      |
| Network, permissions, CSP, build | The manifest adds `icons` and `action.default_icon` only: no permission, host permission, CSP or script change. The extension pages made no request outside the extension. The web icons are same-origin files that Next.js links. No package script, build step or CI job runs `render-icons.mjs`. |
| Cross-checkout write (script)    | **Fixed in `5c2aa32`.** Without an argument the script wrote eleven mobile icons into `../ruvee-mobile`. It now writes this checkout only; the mobile icons need an explicit `--mobile-out <dir>`, which must exist.                                                                                |
| Readability (axe, WCAG 2.1 A/AA) | No violations, in light or dark, on: the welcome screen, the password step of setup, the vault with an item open, the locked screen, and the extension's popup and options pages. Measured after the colour transitions settle; mid-transition samples gave false positives.                        |
| Contrast that axe does not check | **Revise:** in dark, the primary button's hover state is white on `#8a72ff`, 3.54:1. That is below 4.5:1 for its 14 px text; light hover is 6.5:1. Input borders are about 1.7:1 in both themes, which predates this commit.                                                                        |
| Keyboard focus                   | The focus ring is visible in dark on the web sidebar, the inputs, and the extension popup's primary button.                                                                                                                                                                                         |
| Icons at actual size             | They render correctly at 16, 32, 48, 128 and 180 px, at 1× and 2×, on light and dark backgrounds. The 16 px favicon and toolbar icon keep the ring open (the heavier small-size stroke).                                                                                                            |
| `theme-color`                    | One value per scheme: `#f8f7f4` light, `#16151c` dark.                                                                                                                                                                                                                                              |

### 14.2 Recommendation

**Keep, with one revision.** The dark primary-button hover colour (`--color-brand-hover`, and
`--brand-hover` in the extension) should be one that keeps white text at 4.5:1 or more, such as a
darker violet. That is a colour-value change, not a redesign, and it is left to the owner with the
visual review. Nothing found calls for a revert. The screenshots were taken from the real build
against a throwaway synthetic account; they are evidence for that review, not a substitute for it.

If it were reverted after all, an ordinary `git revert 4249cbe` pushed as a fast-forward would do,
with no force-push. The script fix (`5c2aa32`) would then need adjusting, since it changes a file
that the commit added.

## 15. S-4: proof nonces after a failed operation

Investigated across every operation that consumes a nonce (§15.1 to §15.4); the owner chose
option B, implemented in §15.5. Still not D-19.

### 15.1 Where each operation consumes its nonce, and what can refuse afterwards

The signatures are checked first, with no state change, and an invalid one burns the nonce.
Then, inside one transaction, the nonce is consumed and the effect is applied. A refusal or a
database failure after consumption rolls the consumption back.

| Op                      | Checks after consumption, in the same transaction                       | Can the failed check become true later?                                                                 |
| ----------------------- | ----------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| 2 `session_proof`       | the session is not revoked and not yet proven                           | no: revocation and proof are permanent                                                                  |
| 7 `device_revoke`       | the target device of this account is not revoked                        | no for a revoked device; a device id that does not exist could only appear by being enrolled with it    |
| 5 `secret_key_rotate`   | `row_version = expected` and the keyset version unchanged               | only for an `expected` above the current one; honest clients sign the version they just read            |
| 6 `recovery_key_rotate` | `row_version = expected`                                                | as above                                                                                                |
| 8 `pairing_approve`     | the pairing is still `requested` by that device, which is still pending | no: a pairing is never requested again and a device never returns to pending (a restore deletes nonces) |
| 9 `recovery_complete`   | the recovery session is live, the device not revoked, `row_version`     | no for the first two; `row_version` as above                                                            |
| 11 `reopen_complete`    | the guard is `reopening` with this session's code, `row_version`        | no: a later restore deletes every nonce; `row_version` as above                                         |
| 12 `password_change_v2` | `row_version` and `keyset_version` equal the claimed ones               | as above, for both versions                                                                             |

Ops 1 and 10 (login) use an in-memory challenge consumed with the login state; they are not
affected. Op 5 and op 6 also refuse a stale `row_version` before verifying the proof; that leaves
the nonce untouched, with the same result.

### 15.2 Reproduction and regression evidence

`apps/api/test/review/s4-nonce-lifecycle.int-spec.ts` (real database, one installation per test,
op 12 and op 7 as representatives). As first written it had 9 tests, all passing on the code
of that time; they described the behaviour as found. §15.5 changed four of these results.

| Case                                 | Result                                                                                                                                                                    |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| invalid proof                        | burns the nonce; the correctly signed request is refused afterwards                                                                                                       |
| valid proof, precondition refused    | the same request is refused the same way three times; nothing changes (op 12: stale row version; op 7: device already revoked, one event)                                 |
| transaction fails without a decision | a one-time database error (a trigger on the event insert) gives `500` and changes nothing; the identical retry applies once, and a third send is refused                  |
| lost response                        | the replay of an applied revocation is refused; one event                                                                                                                 |
| concurrent duplicates                | 8 identical revocations and 8 identical password changes at once: exactly one `204` each, seven `device_proof_failed`, one event, row version +1                          |
| a different payload after a refusal  | signed under the same open nonce by the same keys, it **applies**                                                                                                         |
| a future row version                 | refused now; after another write raises `row_version` to it, the same request **applies**                                                                                 |
| bindings                             | another operation's nonce, another session's nonce (with this session's `sessionRef`), another account id, an altered payload: all `device_proof_failed`, nothing changes |
| expiry and replacement               | an expired nonce is refused; a nonce left open by a rollback is dead after a newer one is issued or after it expires                                                      |

### 15.3 What this establishes

- **A nonce authorizes only its own operation, session, account and payload.** The device proof
  binds the operation, account, device, session reference and payload. `consume` binds the
  session and operation.
- **Concurrent requests cannot apply a mutation twice.** The conditional `UPDATE … consumed_at IS
NULL` lets exactly one through. The others wait for its row lock and then find it consumed.
- **A lost response has a safe recovery.** The replay is refused and nothing is applied twice.
  The client takes a new nonce (F-4 §12.4 for the password change).
- **Expiry and replacement hold**, including for a nonce reopened by a rollback.
- **A rollback cannot enable a later mutation for a request an honest client signed.** Every
  check after consumption tests something that only moves one way.
- **The boundary.** It can for a request signed with a value that only becomes true later, such as
  a future `expectedRowVersion` or `keysetVersion`, within the nonce's 2 minutes, unless the
  nonce is replaced first. The same open nonce also takes a second, different payload. Both need
  the device key, and for key operations `AK`. Anyone holding them can ask for a fresh nonce, so
  this gives a signer no new power. What it weakens is the rule "one attempt per nonce" (§6),
  and any future operation that adds a check that can become true again.

### 15.4 Decision for the owner

| Option                                                    | Behaviour                                                                                                                                                                                                                                                             | Cost                                                                                                                                                                                                              |
| --------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **A. Keep** (current)                                     | One committed effect per nonce. A transient failure is retried with the identical request.                                                                                                                                                                            | The boundary in §15.3 stays. Every new operation must keep its checks after consumption one-way, and that rule lives in the documentation and in reviews.                                                         |
| **B. Spend the nonce on a decided refusal** (recommended) | When the operation itself refuses after a valid proof (`409`, `404`, `pairing_state`, a revoked session or device, `reopen_failed`), the consumption is committed separately. A database failure that decides nothing still leaves the nonce for the identical retry. | One more write per refusal. The burn can itself fail, which leaves A's behaviour. The tests for the different payload and the future version flip to "refused". Clients need no change: they never reuse a nonce. |
| C. Spend the nonce on every failure                       | One attempt per nonce, always.                                                                                                                                                                                                                                        | Loses the safe retry after a transient failure, and a lost "failed" answer would look the same as a lost success.                                                                                                 |

### 15.5 Option B, implemented

Owner decision (2026-10-28): option B. `ProofService.spend` now runs every nonce-consuming
operation: ops 2, 5, 6, 7, 8, 9, 11 and 12. It consumes the nonce and applies the effect in one
transaction.

- **Decided refusal:** when the effect throws an `ApiException` with a 4xx status after
  consumption, the transaction rolls back and the nonce is marked consumed in a separate write.
- **Anything else** decided nothing, and the nonce stays open for the identical retry.
- **If the separate write fails,** the refusal is still reported and the nonce stays open, as in
  option A.

**Regression evidence.** `s4-nonce-lifecycle.int-spec.ts` now has 10 tests and
`f4-password-keyset.int-spec.ts` 7; all 17 pass. Against the server code before §15.5, five fail:

- a refused request's replay is refused as spent (ops 12 and 7); spending touches only that nonce;
- 8 concurrent duplicates of a refused request: none applies, and the nonce ends spent;
- a different payload under a refused nonce is refused (was: the open limit, it applied);
- a request with a future row version stays refused once that version arrives (was: the open
  limit, it applied);
- F-4's lost-response test: a refused password change spends its nonce.

**Unchanged.** These tests passed before and still pass:

- after a one-time database failure, the identical retry applies once;
- invalid proofs burn their nonce;
- a lost response's replay is refused;
- 8 concurrent duplicates of a valid request apply once;
- operation, session, account and payload binding;
- expiry and replacement, for a nonce left open by a failure too.

**What it does not cover.** A request refused **before** its proof is checked does not touch the
nonce. Examples are op 5's and op 6's early stale-version check, malformed bodies and step-up.
That is unchanged. Such a request changes nothing, and the same check refuses it again.

## 16. F-16, F-20 to F-25, S-5, the connection failure and the instance lock

Owner request of 2026-10-28. Synthetic data and task-owned resources only. Still not D-19; the
real-data restrictions stand. Outside this batch, unchanged and open:

- the F-4 residual (a malicious active device), not accepted;
- the branding visual approval and its proposed hover colour;
- the mobile branch.

### 16.1 F-16: repeated conflicts (confirmed defect, fixed)

- **Defect.** The engine kept one draft per item (a `Map` keyed by item). A second conflict on an
  item that was already in conflict overwrote the first draft. A resolution also had no
  precondition. "Keep mine" was written on top of whatever server version had arrived since the
  panel opened, and on top of a newer unsynced edit of the same item.
- **Behaviour now** (sync-protocol §6, owner-approved): drafts accumulate per item and are
  deduplicated. A resolution names its draft and the server revision it was decided against, and
  is refused with `conflict_changed` or `conflict_pending_edit` if either no longer holds. A server
  change after the choice was queued is a conflict again, with the choice kept as a draft. The
  bounds are 10 drafts per item, 100 in all, and 512 KiB of records. At a bound the mutation stays
  queued, nothing is pushed, and the status is `conflicts_full`. Nothing is evicted.
- **Mechanisms used:** the existing revision precondition (`baseRevision`, `409`) and the
  existing local records. The protocol was not extended, and the server is unchanged.
- **Engine API change (shared with mobile):**
  - `resolveConflict` takes `draftId` and `remoteRevision`;
  - `ConflictView` adds `draftId`, `remoteRevision` and `drafts`;
  - new error codes `conflict_changed` and `conflict_pending_edit`;
  - a new `SyncState`, `conflicts_full`.
- **Stored conflicts** written before this change have no `draftId`; one is assigned when they are
  read.
- **Web:** the conflict panel passes both values, shows how many versions are kept, and shows the
  refusal and the new state instead of dropping the error. The sync panel explains
  `conflicts_full`. The extension never edits items, so it holds no conflicts.
- **Evidence:**
  - `packages/vault/src/review/f16-conflicts.test.ts` has 6 tests; 5 fail on the previous engine.
    The sixth, a server change after the choice was queued, already held through the revision
    check and is kept as a guard.
  - `sync-logic.test.ts` adds 3 tests for the bounds, deduplication and the kind.
  - The F-3 regression was reworked: "mine" with an unsynced edit is now refused, and after that
    edit syncs, "mine" still produces one mutation per commit.

### 16.2 F-20 to F-25

| ID   | Disposition                                                                    | What was done                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| ---- | ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| F-20 | Confirmed defect, fixed                                                        | A save that finished after the user opened another editor ran the old editor's `onSaved`, which closed the new editor and discarded what was typed there. The editor now reports only while it is the one shown; the save itself still completes. `apps/web/src/components/app/item-editor.test.tsx`: the replaced-editor case fails on the old editor; a normal save still reports.                                                                            |
| F-21 | Confirmed, fixed                                                               | The extension's pages could ask the service worker for `detail` (an item's notes and username), `items` and `acknowledgeRecoveryNotice`, which they never call. The allow-list is now exactly the eight methods they call. `apps/extension/src/messages.test.ts` reads the pages' sources and checks that the list equals what they use, and that the three are refused. Both tests fail on the old list.                                                       |
| F-22 | Informational, unchanged                                                       | Bodies are parsed before authentication and the gate, as stated: up to 64 KiB on every route and 4 MiB on `POST /sync/commits`. Caddy sets no body limit. Parsing after authentication would need the guards to run before body parsing, which Nest does not do. No code change; the bound is the size limits.                                                                                                                                                  |
| F-23 | Informational, unchanged                                                       | Op 3 (registration) does not sign `saltPw`, `keysetVersion`, `vault.vkId` or `username`. Only a holder of the single-use setup token on the request path could change them, and that holder could register the account with its own keys anyway. Signing them would change op 3's signed bytes, a protocol change, so it is left as a decision, not made here.                                                                                                  |
| F-24 | Confirmed defect, fixed                                                        | `proof_nonces` rows were never deleted. Issuing a nonce now deletes this session's consumed rows and every row that expired more than 10 minutes ago. The margin covers another instance's clock; an expired or consumed nonce never verifies, so deleting its row changes no result. The S-4 spec adds one test, which fails on the old code with 5 rows left.                                                                                                 |
| F-25 | Confirmed by reading; **fixed in §17.1** (this row describes the state before) | The API runs as the role that owns `ruvee_control` and has `CREATEROLE`. It reads the guard and installation rows and writes reopening codes and the guard. backup-restore.md now says so instead of implying a separate application role. Separating the roles (an application role with only the grants above) is a privilege-design decision for the owner and is not built. Until then, an SQL injection in the API would act with the admin role's rights. |

### 16.3 S-5: a server that changes the device id (confirmed, fixed)

- **Which fields a recovery's answer can lie about.** The account id and `AK`'s id are bound into
  the recovery wrap, so a wrong one fails to unwrap. The vault id comes from the keyset, under
  `AK`. Only the device id is the server's word.
- **Defect.** A server that returned another device id for the same account, key and vault made
  the browser call its own vault "another account's". The UI then offered to erase it, unsynced
  edits and R20 floors included, with one checkbox.
- **Fix.** That combination is now `integrity`, with or without the confirmation, and nothing is
  erased. A genuinely different account (another account id or key) still takes the
  confirmation path, unchanged.
- **Evidence.** `packages/vault/src/review/s5-recovery-identity.test.ts`: the lying server is
  refused and the vault stays enrolled (fails on the old engine with `local_data_other_account`).
  An honest server still keeps the local vault and its pending edit.
- **Residual.** A server that substitutes another real account's material needs a recovery wrap
  that opens with this Recovery Key. None exists for another account.

### 16.4 §5.2: the transient database connection failure (not reproduced; open)

- **Ownership and lifecycle reviewed:**
  - every `pg.Client` in the test helpers is closed in a `finally`;
  - `migrate` is a separate process;
  - a harness closes its app before dropping its database;
  - the app's pool (`PrismaService`) and the lock connection both use `READINESS_DB_TIMEOUT_MS`
    (2 s) as their connect timeout.

  No leak or ownership defect was found.

- **Two new instrumented runs** at the default worker count (§16.5) had no `P1001`.
  - Connection set-up, from arrival to authorization: p50 5 ms and max 0.27 s in run 1, max
    0.10 s in run 2. This was with forced checkpoints of up to 9.3 s and a 1-minute load average
    of about 20.
  - So high load did not slow connections here. The earlier link (7 slow connections, all inside
    checkpoints, in run A1) stays the only evidence.
- **Disposition:** not reproduced, open, and not attributed to load. If it recurs, the evidence
  layout below captures it. No timeout, retry or skip was added.

### 16.5 The test-run evidence

- **Location:** on the review machine, outside the repository (in the review worktree's untracked
  `.evidence/` folder): `f16-int-20261028T173353-1/` and `…T173511-2/`, with the runner
  and the log-analysis script. Each folder holds the vitest
  JSON, the console output, the 1-minute load every 2 s, and the PostgreSQL log for exactly that
  window (connections, disconnections, checkpoints, statements over 2 s).
- **Run 1:** all 32 files and 278 tests passed in 78 s.
- **Run 2:** two 10-second hook timeouts, in `f4-password-keyset` (`afterEach`) and
  `r7-r8-backup` (`afterAll`). Both are the database drop of their teardown. Six
  `DROP DATABASE … WITH (FORCE)` statements took 6–14 s between 13:35:28 and 13:35:33. Every
  checkpoint in the run was `immediate force wait`, the worst 9.3 s with 7.2 s of fsync.
- **Disposition:** this is the §5.1 mechanism (a drop forces a checkpoint, and concurrent drops
  queue), observed again. It is a test-infrastructure limit, not a product defect. Its measured
  mitigations remain in the README.

### 16.6 The instance lock after S-1 (open; owner decision)

- **What depends on one process, by reading the code:**
  - **In each process's memory:**
    - the per-address authentication window (20 per minute);
    - the per-session request limit (300 per minute);
    - per-address wrong reopening-code guesses;
    - pending login states.
  - **In the database, atomically:** the per-account login, bootstrap and recovery limits; the
    reopening code's failed attempts; every session, nonce, key and sync write.
- **What an overlap does.**
  - Two processes serving at once split the in-memory limits: a client can use each process's
    window, so up to twice the per-address and per-session budget.
  - A login started on one process cannot finish on the other, which fails safely.
  - It does not weaken any database-enforced limit or any write.
  - `s1-instance-lock.int-spec.ts` adds a test with two throttle services on separate clients.
    Twelve parallel password checks for one username, alternating between them, evaluate exactly
    five in all. Each service still has its own 20-attempt address window.
- **What the periodic check gives.** After a silent connection loss, an overlap of at most one
  check interval plus `READINESS_DB_TIMEOUT_MS` (10 s + 2 s by default). Only a process paused
  for longer (stopped or suspended) can exceed that, and it re-checks only when it runs again.
  This is not strict single-instance enforcement.
- **Closing it would need one of these:**
  1. **A lease.** The holder serves only within a fixed time of its last successful check, and a
     process that takes the lock waits that long before serving. Simple, but every start is
     delayed by about 12 s, test harnesses included.
  2. **A heartbeat row.** Kept in `ruvee_control` (not backed up), so a new holder waits only
     the remaining lease of a holder that did not release cleanly. A new control table, which
     `admin init` and the restore must handle.
  3. **Moving the in-memory limits and login states into the database**, so that one process
     stops mattering.
- **Disposition.** None was built: each is a design trade-off for the owner. Until one is
  chosen, the deployment rule "exactly one API process per database" stays an operator
  requirement. The lock only detects a second process; it does not prevent it. This is a
  blocker before any multi-process or real-data deployment, not an accepted risk.

### 16.7 A pairing race found by CI (confirmed defect, fixed)

- **Observed.** CI run 40839236462, on `49713a2`, WebKit two-device workflow. Its trace is kept
  with the other evidence (`.evidence/ci-40839236462-webkit/`).
  - B's poll of the pairing state started 23 ms after A's approval began. It returned `200` with
    the approved reply.
  - B enrolled without proving its new key. Its `complete` and first sync were refused (`403`),
    and the app showed "Offline" with no items.
- **Cause.** The access guard decides from the device status it read when it authenticated the
  request: still `pending`, so no proof is required. The pairing handler then read the pairing
  row after the approval had committed. Approval activates the device and approves the pairing
  in one transaction, so the reply went to an active device's unproven session. That skips
  device-proof.md §8, which says to prove the key before reading the reply.
- **Impact.** Availability, not confidentiality. The reply is encrypted to B's ephemeral key, and
  B's later requests were refused. Locking and unlocking proves the session and recovers it.
- **Fix.** The handler applies the rule itself: a requester's read of an approved pairing needs a
  proven session (`device_proof_required`). The engine already answers that by proving, then
  polling again. Unrelated to the F-16 batch; it predates it.
- **Evidence.**
  - `pairing.int-spec.ts` adds a test. It authenticates B's poll with the pre-approval snapshot
    (pending, unproven) after the approval committed; the previous code returned the reply.
  - The WebKit two-device workflow passed three times locally afterwards (§16.8).

### 16.8 Local checks for the final head

- Unit tests, lint, typecheck and format pass in every package.
- The API integration suite: 32 files, 280 tests.
- `test:vault` passed once in each of Chromium, Firefox and WebKit before the §16.7 fix, and
  three more times in WebKit after it. The extension e2e passed 13 tests.
- Not repeated after §16.7: the Chromium and Firefox vault runs, and the extension e2e. That fix
  changes only the API's pairing-state handler; CI runs all of them.

## 17. F-25 roles, and the instance-lock recommendation

### 17.1 F-25: least-privilege database roles (fixed, development)

The owner approved separating the API's runtime role from the owner and administrator roles,
for development, on 2026-10-29. The design is in
[database-roles.md](../architecture/database-roles.md), and setup and migration are in
[the guide](../guides/database-roles.md). In short:

- **The roles.**
  - **Runtime:** the API's `DATABASE_URL`. It owns nothing and has no role attribute and no
    membership. It holds only `RUNTIME_GRANTS`: table privileges per table, plus one column
    UPDATE so that `accounts` rows can be locked. It may read two columns each of `installation`
    and `restore_guard`, and execute five reopening functions.
  - **Owner:** owns `public`, and migrations run as it.
  - **Operator:** `ruvee-admin`. It owns the database and `ruvee_control`, has `CREATEROLE` for
    the loader, and inherits the owner.
  - **Loader:** unchanged.
- **Reopening without UPDATE on the restore state.** Five `SECURITY DEFINER` functions, owned by
  the operator, each check the persisted state and make one change. They have a fixed
  `search_path`, every name is schema-qualified, and PUBLIC cannot execute them.
  `reopen_complete` runs inside the API's completion transaction, so the guard opens together
  with the new credentials, or not at all.
- **Closed when a grant is missing.** A missing gate grant answers `maintenance`. A missing
  function grant opens nothing. In production, a role with more than its list serves nothing.
- **`ruvee-admin`.**
  - It refuses a superuser and the runtime role for `init` and `restore`.
  - It reads `RUVEE_ADMIN_DATABASE_URL` and `RESTORE_DATABASE_URL`, never `DATABASE_URL`.
  - `grant-runtime` puts the list back exactly after a migration.
- **Residual.** A compromised runtime role keeps every privilege it needs to serve:
  - it can read all ciphertext, wraps and OPAQUE records;
  - it can insert sessions, and so act as any account through the API;
  - it can write as the API writes.

  It cannot open a restored installation without a usable code, change the schema or the
  control state, gain a role, or reach the host. During a reopening, a compromised API
  **process** sees the code and can complete the reopening itself; the database cannot check
  OPAQUE. Details: database-roles.md §5. No protection is claimed beyond that boundary.

**Evidence** (synthetic data, task-owned PostgreSQL 18 container `ruvee-task-f25-pg`):

- `test/review/f25-roles.int-spec.ts`: 8 tests, using roles made with the guide's statements:
  - exact privileges, owners and function hardening;
  - 37 forbidden statements as the runtime role (33 on a restored database, 4 on a fresh one), each `42501`;
  - GRANT attempts that change no access list;
  - each reopening function refusing a precondition that does not hold, and an authorized
    transition rolled back with its transaction;
  - a missing gate grant giving `maintenance`, and missing function grants opening nothing;
  - administrative steps refusing a superuser and the runtime role, and a backup and migrations
    failing as the runtime role;
  - an extra grant detected, closing production, and undone by `grant-runtime`;
  - in production, an API started before `init` answering `maintenance`, then serving after
    `init` without a restart;
  - the guide's move of a database set up before F-25.
- `test/database-roles.spec.ts`: 7 static checks:
  - the list covers exactly the inventory;
  - migrations hold no privilege, ownership or role statement;
  - the functions are hardened;
  - the CLI never reads `DATABASE_URL`;
  - privilege errors are recognised.
- **The whole integration suite** now runs the API as each test database's own runtime role,
  and every restore and reopening runs as the operator. Two fixtures needed the new grants:
  - R14's hand-made guard now receives PREPARE's grant;
  - S-4's injected failing trigger now has its sequence granted, because the trigger runs as the
    runtime role. Without the grant it failed every time, not once.

  Neither changes what the test checks.

- **A test that checked less than it claimed (R1, since S-1):** R1 served its restored database
  from a second app while the first, still open, held the instance lock. Every request to the
  second app was refused `server_unavailable` by the lock, never by the gate. Its "503" passed for
  the wrong reason, which was seen once the test asserted `reopening`. The first app now stops
  before the second starts, the gate's own answer is asserted, and the CSRF check has an open
  installation of its own.

- **Negative control:** the reopening code before this change (direct UPDATEs on
  `ruvee_control`) fails all 19 reopening tests under the runtime role.
- **A defect found while building it:** with PUBLIC's `CONNECT` revoked, the runtime role could
  not connect before `init`, or during a restore before APPLY POLICY. The API answered
  `server_unavailable` instead of `maintenance`, which loses the clients' restore message. Now
  the database setup and PREPARE grant `CONNECT`, and R14 covers it.

**Not done:** no real host has these roles, the instructions were not applied to any existing
database, and `.env` is unchanged. D-19 must review the functions and the role checks.

### 17.2 The instance lock: recommendation (decision needed)

This is separate from F-25, and nothing here is built.

**What actually relies on one API process** (§16.6, re-read for this): the per-address
authentication window (20 per minute), wrong reopening-code guesses per address (10 per
15 minutes), the per-session request limit (300 per minute), and pending login states (OPAQUE
server state, 60 s). The per-account login, bootstrap and recovery limits, the reopening code's
failure count, nonces, sessions and all writes are atomic in PostgreSQL, and two processes cannot
weaken them (`s1-instance-lock.int-spec.ts`). A login state is single-use within its own process,
and a `loginId` exists in only one process. A split therefore makes a login fail; it cannot make
one succeed twice.

**Failure modes of the current lock** (a session advisory lock with a 10 s check):

| Failure                                              | What happens                                                                                                                                                                                                                                                                                                                                                                             |
| ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The lock's connection is lost; the old process lives | The server frees the lock when the backend ends, and a new process may take it. The old process notices at once on a reset, or within 10 s + 2 s on a silent loss. Meanwhile it still admits requests, and its pool connections may still work.                                                                                                                                          |
| Event-loop stall in the old process                  | Its check does not run. If its backend survives the stall, it still holds the lock and nothing overlaps. If the server ends the backend during the stall (keepalive, an administrator, a proxy), the old process resumes and answers the requests it queued before its next check. The overlap is the stall plus up to one interval: unbounded.                                          |
| Network partition, then reconnect                    | Until the server notices the dead client (TCP keepalive; the server default is hours), the lock stays held and no new process can serve: an availability failure, not a split. After that, a new process serves; the old one, once reconnected, finds the lock taken and stops. During the partition the old one cannot reach the database, but its in-memory limits still admit starts. |
| A new process starts while the old one serves        | The new process cannot take the lock, serves nothing (`server_unavailable`), and retries every 5 s. There is no overlap unless the old one loses the lock.                                                                                                                                                                                                                               |
| In-flight requests and stale ownership               | `assertServing` is checked once, when the request arrives. A request admitted just before the lock was lost runs to completion, with no fencing token, so its writes are not tied to the ownership it was admitted under.                                                                                                                                                                |

A startup delay or a heartbeat alone does not change any row of this table. It shortens or
detects the overlap, but a stalled or partitioned process cannot know that it lost ownership
before it acts.

**The two designs that would close it:**

1. **Fenced ownership.**
   - **Mechanism.** A lease row (holder id, an increasing epoch, and an expiry in database time),
     taken and renewed by conditional UPDATE. The holder stops admitting requests before its
     lease can expire, measured from the start of its last successful renewal on a monotonic
     clock.
   - **The part that makes it mutual exclusion:** every write transaction must check the epoch
     in the same transaction, for example `SELECT … FROM lease WHERE epoch = $mine FOR SHARE`,
     or a trigger reading a per-connection setting. Then the database refuses a write from a
     stale holder, however long it was stalled.
   - **It does not cover:** decisions taken from memory (a per-address window that let a login
     start), which are not writes. Those stay split during an overlap; only their effects that
     reach the database are fenced.
   - **Costs:**
     - every write path gains the check (a Prisma extension or triggers on every table);
     - a crashed holder blocks new processes for up to the lease time (startup delay);
     - and it is new, security-relevant concurrency code.
2. **Moving the security-relevant limits into PostgreSQL.**
   - **Mechanism.**
     - The per-address authentication window and the wrong-code window become atomic counters,
       as `auth_throttle` already is.
     - Pending login states move to a table: the id hashed, consumed with a conditional DELETE,
       60 s TTL, and the OPAQUE server state stored as now.
     - The per-session request limit can stay per process, documented as load protection,
       not security. Or it becomes a counter too, at one write per request.
   - **Effect.** Then no security property depends on how many API processes run. The advisory
     lock stays as an operational guard against accidental double starts, explicitly not a
     correctness mechanism.
   - **Costs:** a few writes per authentication request, a migration, and a table that is
     deleted on restore like nonces.

**Recommendation: option 2.** The guarantees that depend on one process are exactly these limits
and login states, and option 2 makes them hold for any number of processes. Fencing would have
to reach every write and would still leave in-memory decisions split. Until option 2 is built
and reviewed, the rule "exactly one API process per database" remains an operator requirement.
Ruvee does not claim multi-process support, and it introduces no Redis.

**Decision needed from the owner:**

- either approve option 2, with the per-session limit kept per process or moved too;
- or keep the single-process rule and accept the overlap in the table above for a single host.

The overlap stays a blocker before any multi-process or real-data deployment until then.
