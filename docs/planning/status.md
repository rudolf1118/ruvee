# Status and handoff

Updated 2026-10-25. Everything is **local**: nothing has been pushed, and remote CI has never run.
This is a development build with synthetic data only. Nothing here has been independently
reviewed, and it must not hold real secrets (D-19).

## Where the work is

| Branch                | Contents                                                                               |
| --------------------- | -------------------------------------------------------------------------------------- |
| `web/p2-04-csp-spike` | Ends at P2-04 (`ed43986`): OPAQUE under the CSP, diagnostics-only export               |
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
- **Token sessions** for the extension (API only so far): extension logins get a 10-minute bearer
  access token and a rotating refresh token; a reused refresh token ends the session.
- **Sync**: every commit carries an encrypted manifest; pulls are verified (chain, digest,
  records at their revisions) before anything is applied; a failure makes the vault read-only.
  Offline edits queue encrypted and upload later; concurrent edits become explicit conflicts
  (keep mine, keep theirs, keep both). Changes from other devices arrive by polling (60 s, focus,
  "Sync now").

## Verified (locally, 2026-10-25)

| Check                                                                                                                                                                                                    | Result                          |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------- |
| `pnpm format:check`, `pnpm lint`, `pnpm typecheck`                                                                                                                                                       | Pass                            |
| `pnpm test` (contracts 34, API 68, web 73, crypto 60)                                                                                                                                                    | Pass                            |
| `pnpm test:integration` (49; real OPAQUE and envelopes, each suite on its own `ruvee_it_*` database)                                                                                                     | Pass                            |
| `pnpm --filter @ruvee/crypto test:browsers` (24 checks, Chromium/Firefox/WebKit, page and worker)                                                                                                        | Pass                            |
| `pnpm --filter @ruvee/web test:headers` (30: headers, CSP, OPAQUE and crypto probes, three engines)                                                                                                      | Pass                            |
| `pnpm --filter @ruvee/web test:e2e` (design preview and welcome screen on `next dev`)                                                                                                                    | Pass                            |
| `pnpm --filter @ruvee/web test:vault` (three browsers: setup, pairing, sync, conflict, lock, recovery, password change, removal, `SK` and kit rotation, activity; INV-01 and INV-16 capture), per engine | Pass: Chromium, Firefox, WebKit |
| Remote CI                                                                                                                                                                                                | **Not run** (nothing pushed)    |
| Safari, a real Caddy binary, phones, older laptops                                                                                                                                                       | **Not run**                     |

## Running it

Requirements: Node 24, pnpm 12, Docker for PostgreSQL. All of this stays on 127.0.0.1.

```sh
cp .env.example .env          # first time only; then set the values below if you already have one
pnpm install
pnpm db:up                    # PostgreSQL on 127.0.0.1:5433
pnpm turbo run build --filter=@ruvee/api
(cd apps/api && DATABASE_URL=… npx prisma migrate deploy)              # only on a database you can reset
mkdir -p .secrets && (cd apps/api && node dist/admin/cli.js opaque-setup --out ../../.secrets/opaque-server-setup)
(cd apps/api && DATABASE_URL=… node dist/admin/cli.js bootstrap-token)  # prints a 60-minute setup token
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
`chrome.storage.session`),
and the product defaults D-17, D-09, D-06, D-08, D-10, D-23.
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

- **Not built:** the pairing QR code, device labels (`DEVICE_LABEL` rule undecided), the password
  generator, cards and identities, import/export, SSE push, re-seeding, key rotation, the browser
  extension, mobile.
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

**The browser extension** (Phase 5): secure manual autofill with strict origin matching, on the
same crypto package and API. It needs token sessions (`POST /auth/refresh`, D-08 token
lifetimes), which the API does not have yet, and a decision on where its vault worker runs under
Manifest V3.

Interpretation to confirm in review: other devices adopt a rotated `SK` at their next online
**unlock** (where the password is in hand to re-wrap locally), not during a background sync.
