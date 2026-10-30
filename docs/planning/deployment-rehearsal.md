# Private deployment rehearsal: plan, acceptance and open items

Prepared 2026-10-30. The operator steps are in
[private-rehearsal.md](../guides/private-rehearsal.md). Nothing has been deployed: no VPS, DNS
name, tailnet or backup storage exists for Ruvee yet, and none was touched in preparing this.

> **A passing rehearsal is not production approval.** It shows that one person can install,
> operate, back up and restore a Ruvee server with synthetic data. Real data stays refused by the
> code (backups only of `ruvee_e2e_*` databases) and by D-19 until the owner decides otherwise
> after an independent review.

## 1. Candidate

- **Code:** the head of `vault/web-vault` (draft PR #1) that carries this file. Its full commit id
  is the one in the CI run's artifact `deploy-rehearsal-<commit>`. Required: every CI job green on
  that exact commit, including "Deployment rehearsal host".
- **Build artifacts:** built on the host from that commit with the frozen lockfile; the host's
  `deploy/bin/build-manifest` output must equal the CI artifact's `build-manifest.txt` (guide §3).
  The web export is reproducible since `7b27f52` (the build id is the commit); before it, two
  builds of one commit differed in 14 of 46 files.
- **Versions:** those CI recorded for the commit (`versions.txt` in the same artifact): Node.js 24
  (exact patch), PostgreSQL 18 (exact minor, PGDG), Caddy 2.11 (exact patch), `age` from Ubuntu.

## 2. Plan

### 2.1 Target

One x86-64 VPS, Ubuntu 24.04 LTS, 2 vCPU, 4 GB RAM, 40 GB SSD, 2 GB swap. One API process
(`ruvee-api.service`), PostgreSQL 18 on localhost with `fsync`, `synchronous_commit` and
`full_page_writes` on, Caddy serving the matching export and its generated headers
(`ruvee-caddy.service`), the three database roles (owner, operator, runtime), synthetic accounts
and credentials only.

### 2.2 Configuration and secrets

Names and files: guide §1 and §5, templates in `deploy/env/`. Every secret is generated where it
is kept, never in chat or the repository:

| Secret                                   | Generated                             | Kept                                                                                                        |
| ---------------------------------------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Owner, operator, runtime DB passwords    | `openssl rand -hex 32` on the VPS     | runtime in `api.env` (0600 root); operator in `operator.env` (0400 ruvee-ops); owner not stored on the host |
| OPAQUE server setup                      | `ruvee-admin opaque-setup` on the VPS | `/etc/ruvee/api/` (0600 ruvee-api); one offline copy                                                        |
| Backup age identity                      | `age-keygen` on the offline machine   | offline only (two copies); public key in `operator.env`                                                     |
| Backup digests                           | printed by each backup                | offline, with the date, apart from backup storage                                                           |
| Setup token                              | `ruvee-admin bootstrap-token`         | used once within 60 minutes                                                                                 |
| Synthetic account password, Recovery Kit | the rehearsal operator, on the device | the rehearsal operator's own notes; never reused                                                            |

### 2.3 Network exposure and access

- **Recommended:** a tailnet. The VPS has no public HTTP(S): `ufw` allows 443 and 22 only on
  `tailscale0`; PostgreSQL and the API listen on loopback (checked in CI). Caddy gets a
  publicly trusted certificate for `<host>.<tailnet>.ts.net` from tailscaled, so browsers, the
  extension and the `__Host-` cookie work without installing a CA. Costs: a third-party
  coordination service (it sees which devices connect, not the TLS content), and the host name
  appears in Certificate Transparency logs.
- **Alternative without a third party:** an SSH tunnel per device to the VPS's loopback, with
  Caddy's internal CA installed as trusted on every rehearsal device (two browsers and Chromium
  for the extension). No public name, but every device needs SSH and a manually trusted root,
  and the phone-sized browser case becomes awkward.
- This choice is the owner's (§7). Public DNS and public 80/443 are out of scope for this
  rehearsal.

### 2.4 Order of operations

Host preparation → release build and manifest check → PostgreSQL settings → roles and database
→ `prisma migrate deploy` as the owner → `ruvee-admin init` as the operator (marks the fresh
installation and grants the runtime role) → OPAQUE setup → services → health → bootstrap token →
synthetic account. After every later migration: `grant-runtime`. Details: guide §4 to §7.

### 2.5 Health, restarts, logs, disk

Guide §7: `/health/ready` on loopback; `Restart=always` with a start limit; the journal capped at
1 GB with 2 GB kept free and 30 days; a 15-minute disk check that warns and fails at 80 %. No
alert leaves the host: the rehearsal operator checks `systemctl --failed` and the journal daily.

### 2.6 Backups, storage, custody

Guide §8: manual encrypted backups (`age`, D-29) to `/var/backups/ruvee`, copied to separate
storage and checked against the manifest; the digest recorded offline at once; the identity
offline only, brought to the host for a restore and deleted after it. Every set kept until the
rehearsal report is accepted.

### 2.7 Rollback and cleanup

Guide §10: a new release is a new directory; rollback without a migration repoints `current`;
across a migration, restore the pre-upgrade backup into a new database. Cleanup copies the
evidence off the host first, then removes exactly the rehearsal's databases, roles, files,
identity and host.

## 3. Acceptance criteria

Each criterion is checked on the VPS by the rehearsal operator and recorded with the time, the
commit and what was seen. "CI" marks what the host job already checked on a runner; the
rehearsal repeats it on the real host.

| ID   | Criterion                      | Passes when                                                                                                                                                                                                                                                                                                                      |
| ---- | ------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| A-01 | Release                        | The host's build manifest equals CI's for the candidate commit (CI: same check across directories)                                                                                                                                                                                                                               |
| A-02 | Exposure                       | From outside the tailnet: no open port (scan of the public address); from the tailnet: only 443 (and 22); PostgreSQL and the API on loopback only (CI)                                                                                                                                                                           |
| A-03 | Durability settings            | `SHOW fsync, synchronous_commit, full_page_writes` all `on` (CI)                                                                                                                                                                                                                                                                 |
| A-04 | Headers                        | Pages, a 404 and an `/api/` response over HTTPS carry the build's CSP, HSTS, `no-store` (except `/_next/static/`), no `Server`; HTTP redirects to HTTPS (CI)                                                                                                                                                                     |
| A-05 | Account setup                  | With a bootstrap token, a synthetic account is created in a desktop browser; the Recovery Kit is typed back                                                                                                                                                                                                                      |
| A-06 | Web unlock                     | Lock, then unlock with the master password; wrong password refused; auto-lock after the configured idle time                                                                                                                                                                                                                     |
| A-07 | Extension pairing              | The development extension (Chromium) pairs with the web vault through the pairing code and unlocks                                                                                                                                                                                                                               |
| A-08 | Autofill                       | The extension fills the synthetic login on `http://127.0.0.1:3105` (guide §11) on request, and offers nothing on another origin or port                                                                                                                                                                                          |
| A-09 | Two-device sync                | A second browser profile pairs; an item made on each appears on the other                                                                                                                                                                                                                                                        |
| A-10 | Offline edits                  | One device goes offline, edits an item and adds one; on reconnecting both sync; a conflicting edit made meanwhile on the other device shows as a conflict, keeps both drafts, and is resolved explicitly                                                                                                                         |
| A-11 | API restart                    | `systemctl restart ruvee-api` and a `SIGKILL`: the API is ready again by itself; clients recover without data loss (CI for the service side)                                                                                                                                                                                     |
| A-12 | Host restart                   | `reboot`: PostgreSQL, the API, Caddy and the timer come back without intervention; both devices sync afterwards                                                                                                                                                                                                                  |
| A-13 | Backup                         | A backup as `ruvee-ops`: three 0600 files, the digest recorded offline, a copy on separate storage that matches the manifest (CI without the separate storage)                                                                                                                                                                   |
| A-14 | Restore                        | Into a new, empty `ruvee_e2e_*` database: a wrong digest is refused and creates nothing; the right one restores; the restore id is printed; the identity is deleted from the host afterwards (CI)                                                                                                                                |
| A-15 | Maintenance review             | Served from the restored database, every request gets `503 maintenance` until `restore-complete`, then only the reopening routes (`503 reopening` otherwise); `restore-review` lists the snapshot's devices                                                                                                                      |
| A-16 | Reopening and new Recovery Kit | Reopening with the code and the backup-time password on a device active at backup time; a new master password and a new Recovery Kit are set and the new kit is typed back; the old password and old kit are refused afterwards                                                                                                  |
| A-17 | Newer local data kept          | A device that changed data after the backup shows the restore explanation, keeps its items read-only, exports a verified copy that opens on a clean browser, and keeps pending edits until the user erases the device                                                                                                            |
| A-18 | Runtime credentials            | With the runtime role's URL, `ruvee-admin init`, `grant-runtime`, `bootstrap-token` and `backup` fail; as the runtime role, DDL, `TRUNCATE`, role creation and access to the migration table and the control schema fail; the API user cannot read `api.env` or `operator.env`, and the operator cannot read the setup file (CI) |
| A-19 | Resources                      | Recorded over the rehearsal: the API's and Caddy's memory (`MemoryCurrent`, `MemoryPeak`), CPU time, database and backup sizes, disk use; nothing near the unit limits (1 GB API, 512 MB Caddy)                                                                                                                                  |
| A-20 | Restore duration               | The wall time of the restore command for the rehearsal's backup, recorded with the backup's size                                                                                                                                                                                                                                 |
| A-21 | Logs and disk                  | The journal stays within its cap; the disk check runs every 15 minutes and fails at a lowered threshold                                                                                                                                                                                                                          |
| A-22 | Rollback                       | Repointing `current` at the previous release (same schema) serves again; the documented cross-migration path is walked once on a copy                                                                                                                                                                                            |
| A-23 | Cleanup                        | Evidence copied off; exactly the rehearsal's databases, roles, files and identity removed; nothing else on the host or elsewhere touched                                                                                                                                                                                         |

Not in this rehearsal: the mobile app, Safari, the extension outside Chromium, more than one API
process, public access, real data.

## 4. Open items and what they block

The owner has accepted none of these risks. "Open" means open.

| Item                                                         | Blocks the synthetic rehearsal           | Blocks real-data use                                        | Notes                                                                                                                             |
| ------------------------------------------------------------ | ---------------------------------------- | ----------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Deployment authorization (§8)                                | **Yes**                                  | Yes                                                         | Nothing on a real server happens without it                                                                                       |
| Access method (§2.3)                                         | **Yes**                                  | —                                                           | Tailnet or SSH tunnel; the owner's choice                                                                                         |
| VPS, tailnet and separate backup storage exist               | **Yes**                                  | Yes                                                         | Provisioned by the owner; their details never go into chat                                                                        |
| D-19 independent review                                      | No                                       | **Yes**                                                     | Crypto package, OPAQUE integration including the login-state seal (D-32), pairing, recovery, restore and reopening                |
| F-4 residual (§5)                                            | No                                       | **Yes**                                                     | Open threat-model decision; not accepted                                                                                          |
| Server login-state seal (D-32)                               | No (construction chosen for development) | **Yes**                                                     | Inside D-19's scope; tests are not an approval (§6.2)                                                                             |
| §5.2 intermittent database connection failure                | No (watch for `P1001` in the journal)    | **Yes**, until explained or explicitly decided by the owner | Not reproduced in four instrumented runs                                                                                          |
| Mobile compatibility                                         | No (mobile is not in the rehearsal)      | **Yes, for mobile**                                         | Mobile is not on op 12 (its password change fails with `400`), not checked against the F-19 store contract or the F-16 engine API |
| Real-data backups refused by the code (D-30, D-19)           | No (the database is named `ruvee_e2e_*`) | **Yes**, by design                                          | Changing it is a code change after D-19                                                                                           |
| Unattended backups (a timer holding the operator's password) | No (manual)                              | Yes, as an operations decision                              | Not built                                                                                                                         |
| Alert delivery (disk, failed units)                          | No (checked by hand)                     | Yes, as an operations decision                              | Journal only                                                                                                                      |
| Branding visual approval (`4249cbe`)                         | No                                       | No (not a security item)                                    | One contrast revision proposed (3.54:1 hover)                                                                                     |
| Multi-process or high availability                           | No (one process)                         | No (V1 is one process by design)                            | Not supported; the instance lock enforces one server                                                                              |
| F-22, F-23                                                   | No                                       | No                                                          | Informational                                                                                                                     |

## 5. F-4 decision brief

**What an active device holding `AK` can already do.** `AK` (the account key) unwraps the keyset,
which holds the vault key and the current Secret Key `SK`. A device that is signed in, unlocked
and holds `AK` and its device key `DSK` can read every item, read the current `SK`, and sign
sensitive operations. Changing the password or the Secret Key does not take `AK` away from it.

**What Secret Key rotation protects, and what it does not.** Rotating `SK` replaces the second
factor that, with the password, opens the server-side wrap of `AK`. It protects against someone
who stole the **old `SK`** (from a lost device, a backup of the device, XSS) and later gets a copy
of the server database: with the old `SK` they could guess the password offline; after rotation
the server's wrap no longer opens with it. It does **not** protect against a device that still
holds `AK`, and it does not lock out a device that is still active: such a device reads the new
`SK` from the keyset on its next sync, by design.

**Why revocation and Account Key rotation are different.** Revoking a device ends its sessions
and makes its device-proof key useless on the server: it can no longer sync or sign anything,
but what it already decrypted and the `AK` it holds stay with it. Account Key rotation (full
rotation: new `AK`, vault key and item keys, everything re-encrypted) is the only thing that stops
a former holder of `AK` from reading **future** data. It is designed (cryptographic-design.md
§6.3) and **not built**; it is a Phase 4 item.

**The F-4 residual.** A device that is active, holds `DSK` and `AK`, and is malicious (or runs a
malicious client) can, after someone rotated `SK`, upload a password wrap made with the **old**
`SK`, claim the current keyset version, and sign it with both keys. The server cannot open the
wrap to check, accepts it, and from then on the old `SK` opens the server's wrap again: the
rotation is undone for the server-side copy. A revoked device cannot do this. Such a device could
already read everything and the new `SK` directly.

**The precise guarantee proposed for V1 (op 12, `01e8a35`).** The server installs a new password
wrap only if, at the moment of writing, the request's signed `keysetVersion` equals the account's
keyset version **and** its `row_version` matches, in one conditional update; otherwise `409` and
nothing changes. For an **honest** client, which reports the version its `SK` came from, a wrap
made with a stale `SK` is therefore never installed. The server does **not** guarantee that a
wrap was made with that version's `SK`; a malicious active device holding `AK` can still do the
above. Closing that needs a new mechanism (for example a proof bound to `SK` itself), which is
not designed. The decision open to the owner: accept this residual for real data, with the
reasoning above, or require such a mechanism first. Until then it blocks real data.

## 6. Reporting and evidence

### 6.1 Overhead of the shared limits

Recovered from the retained raw output and spec, now in the repository:
[2026-10-30-shared-limits-overhead.md](../security/evidence/2026-10-30-shared-limits-overhead.md).
Median of the 9 per-round p50s, local only: authenticated `GET` 1.34 → 2.37 ms, `login/start`
2.26 → 5.07 ms, `login/finish` 5.39 → 7.15 ms. Method: one in-process API through supertest,
sequential requests, task PostgreSQL on Docker Desktop, three interleaved runs of three rounds
per build. Limitations: one laptop, no concurrency, no Caddy or TLS; and the measured tree was
the working tree eleven minutes before the commits, not re-measured on the commit (the evidence
file says why). Not a capacity figure.

### 6.2 Approval record of the server-state encryption

The construction was chosen by the owner on **2026-10-30 at 05:46:53 UTC**, in the development
session, in answer to the question "The login-state seal (AES-256-GCM + HKDF from the OPAQUE
setup) is outside ADR-0002. Which construction should the shared login states use?": the answer
was **"ADR-0002 per-state key (Recommended)"**, with its specification shown (keyed BLAKE2b
derivation of `K_seal` and a per-login `K_state`, XChaCha20-Poly1305 with a random 24-byte nonce,
length-prefixed AAD over every bound column), over "shared windows only" and "keep AES-GCM,
record an exception". That is the whole record: it chose a construction for the development
build. It did not approve the seal for real data, and the passing tests (22 in the crypto
package, the shared-limits and two-process suites) are not an approval. It is recorded as D-32
in [open-decisions.md](../architecture/open-decisions.md), and D-19's scope now names it.

## 7. Decisions that block the rehearsal

1. **Authorization** to provision and change the VPS (§8).
2. **The access method:** tailnet (recommended) or SSH tunnels with a trusted internal CA.
3. **Where the separate backup storage is,** and who holds the offline identity and digests.

Nothing else blocks the synthetic rehearsal. Everything in §4 marked for real data stays open.

## 8. What needs deployment authorization

The first action that needs it: **logging in to the VPS and starting guide §4** (creating users,
installing packages, changing the firewall). Everything before it, preparing this repository and
checking it on CI's disposable runners, is done.
