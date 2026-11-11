# Follow-up review checklist

**For a fresh review of one exact commit.** This is a checklist for an independent reviewer, not a
review. It does not complete D-19, and nothing in it is approved by being listed.

- **Commit under review:** `1702ea6` on `vault/web-vault` (the last code commit; later
  commits change documentation only). It adds the legacy-account hardening of review §13 to
  `711c04f`, the commit of the previous checklist. Check it out detached and review that tree, not a branch
  tip.
- **Findings and their evidence:** [predeployment-review.md](predeployment-review.md), §2 and the
  dispositions in §12 and §13. **Protocol under review:** [device-proof.md](device-proof.md),
  [ADR-0011](../adr/0011-device-proof-of-possession.md).
- **Ground rules:** synthetic data only; throwaway PostgreSQL databases (`ruvee_it_*`,
  `ruvee_e2e_*`); no deployment. Each item names where to look and what would refute it.

## 1. Routing and authorization

- [ ] Every handler declares an access level, and the global guard refuses one that does not
      (`apps/api/src/sessions/access.guard.ts`, `access.decorator.ts`). Grep every controller.
- [ ] Gate and CSRF decisions use handler metadata, never the URL; upper-case, encoded and
      doubled paths are 404 (R1; `test/review/r1-path-case.int-spec.ts`, `test:caddy`).
- [ ] Cookie xor bearer; a cookie never accompanies an extension-origin request; an extension
      origin passes CSRF only on `login/start`, `login/finish` and `refresh` (`@ExtensionMayCall`,
      R23; `test/review/p2-api.int-spec.ts`).
- [ ] Pre-proof allowlist is exactly the five `@AllowBeforeProof` handlers (device-proof.md §5);
      every other `session`/`active`/`step-up` handler answers `device_proof_required` to an
      unproven session (`test/review/r2-r3-login.int-spec.ts`).
- [ ] The authorization table of device-proof.md §7 matches the code, route by route: tier 2
      (proven session), tier 3 (`pairings/:id/approve`), tier 3+ (password, Secret Key, kit, with
      the AK proof required by operation, `NEEDS_ACCOUNT_KEY_PROOF`), tier 3s (revoke).
- [ ] Recovery and reopen sessions are accepted only on their own controllers; a normal session is
      never accepted there, and the reverse.
- [ ] Rate limits: per-username reservations are atomic (R3); per-address, wrong-code and
      per-session windows and pending logins are shared in PostgreSQL (§17.2 option B,
      `test/review/shared-limits.int-spec.ts`, and with two OS processes
      `test/review/two-processes.int-spec.ts`), so no limit depends on the instance lock. The
      10,000-row bounds are approximate (§18.2). The login-state seal follows authentication.md
      §4.1 (ADR-0002 primitives, not yet reviewed). The API
      still refuses to serve from a second process on the same database (`InstanceLockService`,
      `test/review/topology.int-spec.ts`). Check what a transaction-mode pooler would do to the
      advisory lock.
- [ ] Pairing creation: open-count and hourly window under the account row lock (R21).

## 2. Restore control isolation and verified backup inputs

- [ ] The guard tables live in `ruvee_control`, owned by the admin role; the loader and API roles
      cannot write them; every API query names the schema (R8; `r7-r8-backup.int-spec.ts`).
- [ ] LOAD reads each backup file once, by descriptor, and hashes the ciphertext in the decryption
      stream; the trusted digest is required (R9; `r9-verified-bytes.int-spec.ts`).
- [ ] Backup and restore URLs refuse query parameters; the dumped database is the checked one
      (R7).
- [ ] The restore target is empty by every object kind, not only tables (R23;
      `assertEmptyDatabase`, `p2-api.int-spec.ts`).
- [ ] The installation lifecycle: no control schema is closed; nothing is cached, `open` included
      (§18.7: a same-named replacement); `init` runs once per new database (R14;
      `r14-gate-lifecycle.int-spec.ts`, `two-processes.int-spec.ts`).
- [ ] Reopening: code single-use and bound to the restore; completion re-checks the session and
      the code under the guard row lock (R11, R13); proof nonces and sessions are gone after APPLY
      POLICY.
- [ ] `docker exec` prefix: an early end of input leaves `pg_restore` a truncated archive (R15).

## 3. Checkpoint monotonicity and recovery data preservation

- [ ] The checkpoint never decreases across syncs, saves and lost or replayed commit replies (R5;
      `packages/vault/src/review/r5-r6-client.test.ts`).
- [ ] Keyset version never decreases (INV-09), including through recovery (R20).
- [ ] Recovery on a browser that holds the account keeps its records, pending edits, conflicts,
      import state and floors (R6).
- [ ] A refused recovery or reopening of a pre-D-31 account changes nothing on the server or in
      the browser: records, pending edits, conflicts, kit and reopening code
      (`legacy-migration.test.ts`, `legacy-avpk.int-spec.ts`, `reopen.int-spec.ts`).
- [ ] The migration report names every pending edit and conflict, and the local export refuses
      to leave them out unacknowledged (`legacy-migration.test.ts`, `test:migrate`).
- [ ] Start-over erases only with the pending and conflict counts the user saw (R22).
- [ ] An import batch is fed only into an empty queue with nothing in flight (R22).
- [ ] A lock during any engine operation: the operation cannot write or leave a session afterwards
      (R19; `p2-client.test.ts`), and the extension never stores `AK` back after a lock (extension
      e2e "R19").

## 4. D-31 trust establishment, transcripts, key lifecycle and bypass paths

- [ ] **Transcripts** (`packages/crypto/src/device-proof.ts`): `DSI` and `AKSI` are fixed-length
      and domain-separated; the payload encoding is length-prefixed and covers every field the
      server acts on, per operation (compare each `proofPayload` call on both sides). No signature
      in one context verifies in another (`device-proof.spec.ts`).
- [ ] **AK-derived key:** `KDF(AK, "rvakver1")` as an Ed25519 seed next to Ruvee's other `AK`
      derivations; the secret half never leaves the call.
- [ ] **Trust establishment**, one path at a time (device-proof.md §8):
  - [ ] setup: `DPK` and `AVPK` with both signatures, bound to the setup token;
  - [ ] pairing: `req_mac` (`pair-req-2`) covers `dpk_B`; A's op-8 proof covers it; a key swapped
        after A read the request is not enrolled; a malformed request is burned (R23);
  - [ ] recovery on a fresh browser: a new `DPK`; the `AVSK` proof checked against the stored
        `AVPK`; `RAK` without `AK` fails (`recovery.int-spec.ts`);
  - [ ] reopening: the password path proves the restored key at login (op 10) and completion
        (op 11); the Recovery Kit path enrolls a new key on a fresh browser and leaves the snapshot
        device's key and the `AVPK` unchanged (`reopen.int-spec.ts`);
  - [ ] accounts from before D-31 (device-proof.md §9): no `AVPK` is ever established. With
        `ak_verify_key` null, `recovery/start` and `reopen/recovery/start` answer
        `migration_required` before creating a device, session or spending the code;
        `proveCompletion` refuses before verifying anything; completions no longer write
        `ak_verify_key` at all; tier-3+ needs a stored `AVPK`. Try an `AVSK` made with a key of
        your choosing, with `AK`'s own key, and a password-only session (`legacy-avpk.int-spec.ts`).
        Grep every write of `ak_verify_key`: registration only.
  - [ ] migration path: export of the last verified snapshot, import into a fresh installation
        under new keys, the new account's `AVPK` from bootstrap only
        ([legacy-account-migration.md](../guides/legacy-account-migration.md)).
- [ ] **Nonces:** issued under the session row lock (one open per session and operation),
      consumed in the operation's own transaction, expired after 2 minutes, burnt by an invalid
      proof, deleted on restore; a replay after a lost reply changes nothing
      (`p2-api.int-spec.ts`, `r2-r3-login.int-spec.ts`).
- [ ] **Key lifecycle:** `DSK` sealed under `K_local`; loaded on unlock and resume; zeroed on lock
      and logout; never in a WebCrypto key or extension storage; a locked engine cannot sign.
- [ ] **Bypass search:** no password-only or `RAK`-only path registers a `DPK` or `AVPK`; only
      registration writes `AVPK`; only registration, pairing approval, recovery completion and
      reopening completion write a `DPK`; a pre-proof session cannot obtain a nonce for anything
      but its own proof.
- [ ] **Device names:** none in V1 (device-enrollment.md §1). The pairing confirmation depends on
      the MAC-covered platform and the user's own code entry, not on a name; the Devices screen
      does not present the short id or server times as proof.
- [ ] **Claims not made:** a valid signature proves possession for one payload, not that a wrap
      decrypts (device-proof.md §3).

## 5. Run before signing off

```bash
pnpm format:check && pnpm lint && pnpm typecheck && pnpm build && pnpm test
```

```bash
pnpm --filter @ruvee/api test:integration
```

Browser suites per engine (`RUVEE_E2E_BROWSER` = `chromium`, `firefox`, `webkit`; WebKit is
Playwright's build, not Safari): `test:vault`, `test:restore`, `test:import`, `test:migrate`; Chromium only:
`test:headers`, the extension suite, `test:e2e`; and `test:caddy`.
