# Status and handoff

Updated 2026-10-28. Every branch is on GitHub (public `rudolf1118/ruvee`). Remote CI runs for pushes
to `main` (which still holds Phase 1) and for pull requests. Commit IDs changed once on 2026-10-28; old IDs are mapped in
[history-rewrite.md](history-rewrite.md).
This is a development build with synthetic data only. Nothing here has been independently
reviewed, and it must not hold real secrets (D-19).

## Where the work is

| Branch                | Contents                                                                               |
| --------------------- | -------------------------------------------------------------------------------------- |
| `web/p2-04-csp-spike` | Ends at P2-04 (`e044474`): OPAQUE under the CSP, diagnostics-only export               |
| `vault/web-vault`     | Continues from it: the first functional web vault (this document's subject)            |
| Earlier branches      | P2-01, P2-02, P2-03, P2-05 and Phase 0/1, each stacked on the one before (see git log) |

Run `git log --oneline main..vault/web-vault` for the commits.

## What works now

A complete single-user web vault across several browsers, against the real API and database:

- **Account setup** with the operator's setup token, a master password (D-09 policy), and a
  Recovery Kit that must be typed back before the account is created (D-06).
- **OPAQUE login** (D-02), cookie sessions (D-08), CSRF checks, throttling, logout. A browser that
  only logs in is a **pending device** and cannot read anything (D-04, INV-06).
- **Pairing** a second browser with a 128-bit code (D-21); the approving device verifies the
  request MAC, the new device verifies the reply and the keyset before storing anything.
- **Unlock** offline from the local copy; **lock** (manual, 15 minutes idle, session end) wipes
  and terminates the vault worker.
- **Logins and secure notes**: create, edit, favorite, Trash, restore, permanent deletion; reveal
  and copy with clipboard clearing after 30 seconds. Passwords leave the worker only on reveal,
  copy or edit.
- **Recovery with the Recovery Kit** on a new or existing browser: a new master password and a
  mandatory new Recovery Kit; every other session ends, other devices are told, and they move to
  the new password the next time they unlock online.
- **Devices**: a list of the account's devices and their sessions; signing out one session;
  removing another device after typing the master password again (step-up, INV-14), as retired
  or as lost, with the limits of revocation spelled out (device-enrollment §6). The removed
  device's sessions end at once, and it erases its local copy when it next connects.
- **Master password change** (authentication.md §9): step-up, the same `AK` under a new wrap and
  OPAQUE record, every other session ended; the other devices move to the new password the next
  time they unlock online.
- **Secret Key rotation** (D-24): removing a device as lost replaces `SK` in the same step-up;
  **Security** replaces it on request, and the notice after a recovery leads to Devices. Other
  devices adopt the new `SK` when they next unlock online; one that missed both an `SK` and a
  password change asks once for its previous password.
- **Recovery Kit rotation** under **Security** (account-recovery.md §5): the new kit must be typed
  back, then the master password confirms it; the old kit stops working with this server.
- **Activity**: the account's security events, newest first, with the ones worth a second look
  highlighted (failed sign-ins, Recovery Kit use, failed pairing checks).
- **Browser extension** (`apps/extension`, Chromium MV3, development build): log in, pair from
  the web app, unlock, and fill a login into a page of exactly the saved origin, on request.
  Token sessions (10-minute access token, rotating refresh token, reuse ends the session); `AK`
  in `chrome.storage.session` across service-worker restarts (D-27); auto-lock after 15
  minutes. The popup never receives a password. The engine is shared with the web app
  (`packages/vault`).
- **Encrypted export** (D-13 option A): Security → Encrypted export makes a file of the vault's
  existing ciphertext that only the Recovery Kit typed at export opens; it is never uploaded.
  "Open an encrypted export" on the welcome screen opens one read-only, with no account, after
  checking every part of it. **Restore into a new account** imports it into a fresh installation:
  new account and keys through the normal setup, every item re-encrypted locally and uploaded as
  new items, resuming after interruptions without duplicates
  ([user guide](../guides/encrypted-export.md)).
- **Sync**: every commit carries an encrypted manifest; pulls are verified (chain, digest,
  records at their revisions) before anything is applied; a failure makes the vault read-only.
  Offline edits queue encrypted and upload later; concurrent edits become explicit conflicts
  (keep mine, keep theirs, keep both). Changes from other devices arrive by polling (60 s, focus,
  "Sync now").

## Verified (locally, 2026-10-26)

| Check                                                                                                                                                                                                                                                                                                                                                                                                                                                            | Result                          |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `pnpm format:check`, `pnpm lint`, `pnpm typecheck`                                                                                                                                                                                                                                                                                                                                                                                                               | Pass                            |
| `pnpm test` (contracts 37, API 72, web 33, vault 62 and 1 skipped, extension 27, crypto 60)                                                                                                                                                                                                                                                                                                                                                                      | Pass                            |
| `pnpm test:integration` (98, 16 files, including encrypted backup, reopening, R1, R3, R13; real OPAQUE and envelopes, each suite on its own `ruvee_it_*` database; the restore suites run real `pg_dump`/`pg_restore` 18)                                                                                                                                                                                                                                        | Pass                            |
| `pnpm --filter @ruvee/crypto test:browsers` (24 checks, Chromium/Firefox/WebKit, page and worker)                                                                                                                                                                                                                                                                                                                                                                | Pass                            |
| `pnpm --filter @ruvee/web test:headers` (33: headers, CSP, OPAQUE and crypto probes, local fonts, three engines)                                                                                                                                                                                                                                                                                                                                                 | Pass                            |
| `pnpm --filter @ruvee/web test:e2e` (design preview and welcome screen on `next dev`)                                                                                                                                                                                                                                                                                                                                                                            | Pass                            |
| `pnpm --filter @ruvee/extension test:extension` (Chromium, 9: pairing, exact-origin fill and refusals, proven worker restart and resume, auto-lock and expired unlock, `storage.session` refused to page scripts, stale fill after navigation, previous-password unlock, refresh-token reuse, logout, revoked extension reconnecting, capture)                                                                                                                   | Pass                            |
| `pnpm --filter @ruvee/web test:import` (two installations, each with its own API and database: export from A, restore into a fresh B, unlock B with new credentials, check every item, A and the file unchanged, capture checks)                                                                                                                                                                                                                                 | Pass: Chromium, Firefox, WebKit |
| `pnpm --filter @ruvee/web test:restore` (2 tests: the reopening through the Recovery Kit path on a new browser, and R14: two devices, reopening through the password path, `ruvee-admin` encrypted backup, restore with identity and trusted digest, maintenance, review and opening; the device ahead keeps its data read-only, exports a verified copy with the pending edit acknowledged, and is erased only on typed confirmation; the device in step syncs) | Pass: Chromium, Firefox, WebKit |
| `pnpm --filter @ruvee/web test:vault` (three browsers: setup, pairing, sync, conflict, lock, recovery, password change, removal, `SK` and kit rotation, activity; INV-01 and INV-16 capture), per engine                                                                                                                                                                                                                                                         | Pass: Chromium, Firefox, WebKit |
| Remote CI                                                                                                                                                                                                                                                                                                                                                                                                                                                        | **Not run** (nothing pushed)    |
| Safari, a real Caddy binary, phones, older laptops                                                                                                                                                                                                                                                                                                                                                                                                               | **Not run**                     |

## Running it

Requirements: Node 24, pnpm 12, Docker for PostgreSQL. All of this stays on 127.0.0.1.

```sh
cp .env.example .env          # first time only; then set the values below if you already have one
pnpm install
pnpm db:up                    # PostgreSQL on 127.0.0.1:5433
pnpm turbo run build --filter=@ruvee/api
# Database roles first: docs/guides/database-roles.md (owner, operator, runtime; F-25)
(cd apps/api && DATABASE_URL=<owner URL> npx prisma migrate deploy)     # only on a database you can reset
(cd apps/api && RUVEE_ADMIN_DATABASE_URL=… RUVEE_RUNTIME_ROLE=… node dist/admin/cli.js init)
mkdir -p .secrets && (cd apps/api && node dist/admin/cli.js opaque-setup --out ../../.secrets/opaque-server-setup)
(cd apps/api && RUVEE_ADMIN_DATABASE_URL=… node dist/admin/cli.js bootstrap-token)  # prints a 60-minute setup token
pnpm dev                      # API on :4000, web on :3100 (/api is forwarded to the API)
```

`.env` needs `OPAQUE_SERVER_SETUP_FILE`, `PUBLIC_ORIGIN=http://127.0.0.1:3100` and
`SESSION_COOKIE_SECURE=false` (see `.env.example`); an older `.env` lacks them and the API refuses
to start. Production-like local run: build the web export and run
`RUVEE_API_ORIGIN=http://127.0.0.1:4000 pnpm --filter @ruvee/web serve:export` (port 3101, with
`PUBLIC_ORIGIN=http://127.0.0.1:3101`).

Tests that need PostgreSQL take a server URL whose role can create databases and create their own
throwaway databases on it:

```sh
DATABASE_URL=postgresql://…@127.0.0.1:5433/ruvee pnpm test:integration
RUVEE_E2E_ADMIN_DATABASE_URL=postgresql://…@127.0.0.1:5433/ruvee RUVEE_E2E_BROWSER=firefox pnpm --filter @ruvee/web test:vault
```

## Review packet

[phase-2-review-packet.md](../security/phase-2-review-packet.md) maps every invariant to its tests,
lists the interpretations made while building, and scopes the independent review (D-19). It is a
self-review.

## Decisions

Approved by the owner **for development only** on 2026-10-25: D-02 (OPAQUE), D-21 (pairing),
D-22 (`RAK` recovery verifier), D-24 (`SK` rotation on lost removal, offered after recovery), D-27 (extension `AK` in
`chrome.storage.session`), D-13 option A (export format, 2026-10-26), D-29 option B (age-encrypted server backups, 2026-10-26), D-30 option B (reopening after a restore, 2026-10-26),
and the product defaults D-17, D-09, D-06, D-08, D-10, D-23. On 2026-10-27: accounts from
before D-31 never get an `AVPK` and move to a new account
([guide](../guides/legacy-account-migration.md)), and V1 has no device names.
Earlier: D-25, D-01, D-04, D-20. D-16 resolved for development by evidence. Interpretations made
while building, to confirm in review:

- The `u8(platform)` codes in the pairing request MAC: web 1, extension 2, ios 3, android 4.
- A paired device pulls from genesis and requires the chain to pass through the received
  checkpoint (an "anchor"), because it has no records at the checkpoint's `seq`.
- Registration also creates the empty vault (`register/finish` carries `vault`), since the
  keyset already names it; there is no separate `POST /vaults`.
- Zod runs in jitless mode so it never probes `new Function` under the CSP.

Still open: D-03 and D-26 (profile 1 stays provisional; no phone measured), D-19 (who reviews),
D-07, D-05, D-11 to D-15, D-18.

## Known gaps and risks

- **Extension gaps:** no account setup or recovery (web only), no item editing, copy or search
  beyond the page's matches, no fill into same-origin frames, no Firefox or Safari, no store
  packaging. A page navigating in the instant between the worker's last check and injection is
  covered only by the in-page origin check and its unit test.
- **Server backup and restore (M1) is not ready for real data.** Encrypted backups (D-29 B, age),
  the revised D-28 restore and the reopening (D-30 B) are implemented and tested on synthetic
  databases only, with an [operator guide](../guides/server-backup-restore.md). `ruvee-admin
backup` still refuses real databases: D-19 is open and nothing is deployed.
- **Not built:** importing into a vault that already holds items (merge),
  the pairing
  QR code, device names (deferred for V1, 2026-10-27), the password generator, cards and
  identities, SSE push, re-seeding, full key rotation, mobile.
- **One API process per database** stays an operational rule, enforced by the instance lock.
  Since 2026-10-29 (follow-up review §18) no limit or login state depends on it: request
  windows and pending logins are shared in PostgreSQL, so an accidental overlap keeps one budget
  (checked with two independently launched API processes, §18.7). This is not multi-process or high-availability support (process clocks, configuration and the
  OPAQUE setup file are per process).
- **A raw database copy** (not through `ruvee-admin restore`) still brings back devices removed
  after it, with their sessions (`apps/api/test/backup-restore.int-spec.ts`); only the restore
  tool applies the D-28 policy.
- **Accounts from before D-31** (synthetic only) can't sync, re-enroll, recover or reopen; they
  move to a fresh account by export and import, with pending edits and conflicts copied by hand
  ([legacy-account-migration.md](../guides/legacy-account-migration.md)).
- Common-password rejection (part of D-09) needs a reviewed list.
- The web client is trusted code served by the server (D-07, T-18): a malicious server could
  serve code that reads secrets.
- `SK` sits in IndexedDB unencrypted by anything but the browser profile (R-06).
- libsodium.js 0.8.4 still has V-15; `packages/crypto` contains it by passing only subkey length
  32, and the harness tripwire fails when an upstream fix ships.
- Clipboard clearing is best effort (browsers cannot check what the clipboard holds).
- `next dev` fetches the Google fonts at start (`next/font/google`); without network, or when the
  fetch fails, the design-preview e2e (`test:e2e`) fails with `NextFontGoogleFontFileReplacer`
  errors. Seen once on 2026-10-25, then three clean runs. The production export is unaffected.

## Next task

**M1 is implemented for synthetic data and not accepted for real data.** Backup, restore and
reopening are done
([backup-restore.md §3.11](../architecture/backup-restore.md#311-status-of-the-m1-implementation-2026-10-26)).
Next: the independent review (D-19, including `age-encryption`, the backup code and the
reopening), then a private deployment rehearsal with scheduled off-host backups, a non-superuser
restore role and a timed restore.
