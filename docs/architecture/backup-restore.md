# Backup and restore

Status: **Proposed (2026-10-26).** **D-13 option A was approved by the owner for development on
2026-10-26**, and the export (§4) is implemented to that design; the restore rules for server
backups (§3.6) are still blocked on **D-28**. ADR: [ADR-0010](../adr/0010-backup-and-portable-export.md). Not
independently reviewed (D-19).

## 1. What the repository already requires

Quoted exactly.

**D-13** ([open-decisions.md](open-decisions.md), later-phase decisions):

> | D-13 | Portable encrypted export format | Design in Phase 7 within account-recovery.md §7 | Phase 7 |

**[account-recovery.md §7](../security/account-recovery.md#7-restoring-from-backups)**, the
constraints D-13 must meet:

> - An export must contain the encrypted records, the manifest and the keyset, together with a
>   wrap of `AK` that the **Recovery Key** can open, so that it can be restored without the server
>   and without an enrolled device.
> - It must never contain plaintext.
> - Restoring it onto a clean device has no trusted checkpoint. The client shows the export's
>   manifest date and author device, which are authenticated values, and treats the content as of
>   that date.

and for server backups:

> - Restoring them needs the **OPAQUE server secret**, which is backed up separately
>   ([authentication.md §Server secrets](authentication.md#server-secrets)). Without it, logins
>   fail, and the user re-registers OPAQUE through the Recovery Key flow.
> - Decrypting restored data still needs the password and `SK`, or `RK`, **as they were at
>   backup time**. If the password or Recovery Key was changed after the backup, the user needs
>   the old ones. The backup guide must tell the user to keep old Recovery Kits for as long as old
>   backups exist, or to rotate keys fully and then delete old backups.
> - A server restored to an older state looks like a rollback to every device whose checkpoint is
>   newer. Those devices stop and warn ([INV-07](security-invariants.md)). Re-seeding the server
>   from a device's newer local copy is specified in
>   [sync-protocol.md §Server restore](../architecture/sync-protocol.md#server-restored-from-an-older-backup).

**Related, unresolved:**

- D-12: "Vault reset: may other devices export before wiping? | Yes, an encrypted export if one
  exists by then | Phase 3".
- [cryptographic-design.md §4.3](../security/cryptographic-design.md#43-purposes): "Purpose values
  `0x09`–`0x0F` are reserved for attachments, portable backups and device-bound local wraps in
  later phases. They must be specified before use."
- INV-21: "The OPAQUE server secret is never stored in PostgreSQL or database backups, never
  logged and never returned by an API."
- [Roadmap](../planning/implementation-roadmap.md#later-phases-outline), Phase 7: "import and
  export (D-13), … encrypted backups", gated on "Export and attachment designs reviewed"; Phase 9:
  "restore tests, disaster recovery, operational docs".
- Plaintext export: "Phase 7. Plaintext export requires step-up (INV-14). The format is D-13." It
  is **outside** every milestone here.
- Re-seeding (`POST /sync/reseed`) is a Phase 4 design, not implemented.

## 2. Two different things

|                                | **Operational server backup** (disaster recovery)                                               | **Portable encrypted export** (user-controlled)                                                        |
| ------------------------------ | ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Who makes it                   | The operator (here, the owner), on the server                                                   | The user, in the web app, on an unlocked device                                                        |
| What it protects against       | Loss or corruption of the server: disk, host, bad migration                                     | Loss of the server _and_ its backups; leaving the instance; an offline copy the user holds             |
| What it contains               | The whole database: ciphertext, wraps, OPAQUE records, devices, sessions, events                | One vault's ciphertext, its keyset and an `AK` wrap the Recovery Key opens; nothing else               |
| Who can read the vault from it | Nobody without the user's password and `SK`, or `RK`, as of backup time                         | Nobody without the Recovery Key the export was made with                                               |
| What else it exposes           | With the OPAQUE setup file too: offline guessing of the password as of backup time (V-01, T-03) | Offline guessing is not feasible: `RK` is 128 random bits; nothing in the file depends on the password |
| New cryptography               | None                                                                                            | None proposed (§4): it is a container for envelopes that already exist                                 |

They are complementary. The server backup restores _the service_ (accounts, devices, login); the
export restores _the vault's contents_ without the service.

## 3. Operational server backup (milestone M1)

Decision-ready design, revision of 2026-10-26. **D-28 is not approved**; nothing here is
implemented except the inventory (`apps/api/src/admin/backup-inventory.ts`) and test scaffolding.

### 3.1 What is backed up

`CONFIG_INVENTORY` and `TABLE_INVENTORY` in `apps/api/src/admin/backup-inventory.ts` are the
machine-checked version of this list: a test fails when a table or configuration variable is
added without a classification.

| Input                        | What it is                                                                                                                                                                                                                                             | Kept where                                                                            | Secret?                                                                                     | On restore                                 |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------ |
| **Database dump**            | `pg_dump --format=custom` of all 13 tables: accounts, OPAQUE records, `AK` wraps, `SHA-256(RAK)`, keyset, devices (with encrypted labels), session and token **hashes**, pairings, items, commits and manifests, events, throttles, setup-token hashes | Operator; encrypted at rest; at least one copy off the server                         | Yes: OPAQUE records allow offline password guessing **together with** the setup file (V-01) | Loaded into a new, empty database          |
| **Sidecar** `<dump>.json`    | Format `ruvee-server-backup/1`, dump SHA-256 and size, newest migration, Ruvee version, snapshot time, and the configuration marked `sidecar`: `PUBLIC_ORIGIN`, `SESSION_COOKIE_SECURE`, `EXTENSION_ORIGINS`                                           | With the dump                                                                         | No                                                                                          | Checked first; its configuration is reused |
| **OPAQUE server setup file** | The server's OPAQUE key material (INV-21)                                                                                                                                                                                                              | Operator; **offline and apart from every dump**, made once when the server was set up | Yes: with a dump it allows offline guessing and server impersonation (T-03)                 | Placed at `OPAQUE_SERVER_SETUP_FILE`       |
| Host configuration           | `DATABASE_URL` (new password), ports, proxy address, log level                                                                                                                                                                                         | Chosen on the new host                                                                | `DATABASE_URL` yes                                                                          | Written anew; never copied                 |
| Attachments                  | Do not exist yet (Phase 7)                                                                                                                                                                                                                             | —                                                                                     | —                                                                                           | —                                          |
| Release files                | The web export, `deploy/Caddyfile`                                                                                                                                                                                                                     | Part of the Ruvee release                                                             | No                                                                                          | Installed from the same or a newer release |
| TLS certificates             | Issued for the host                                                                                                                                                                                                                                    | —                                                                                     | Yes                                                                                         | Issued again                               |

Nothing on a client device is in a server backup, and the server never holds anything that opens
the vault (INV-18).

### 3.2 Encryption, custody, retention, off-server copies (D-29, not blocking)

- **Dump at rest:** encrypted by the operator: either encrypted storage, or `age` to a recipient
  key whose private half the owner holds offline. M1's tool writes a plain dump and leaves this to
  the operator (D-29 option A); a built-in `age` step can follow.
- **Custody:** the owner holds three separate things: the dump's storage key, the setup file's
  offline copy, and their Recovery Kit. No two are stored together.
- **Off-server copies:** at least one dump and the setup file kept off the host; a backup on the
  same disk protects against nothing but mistakes.
- **Retention:** suggested 7 daily, 4 weekly, 6 monthly. Every dump keeps the password and
  recovery wraps of its day: an old dump plus an old Recovery Kit (or old password) opens the
  vault as of that day (account-recovery.md §5). After a suspected compromise, delete dumps older
  than the next full key rotation (Phase 4).

### 3.3 Consistent snapshot and integrity

- One `pg_dump` run reads one repeatable-read snapshot: commits, manifests and items are
  mutually consistent (each commit is one transaction). No downtime is needed.
- The dump is written as `<name>.partial`, its SHA-256 computed, the sidecar written, then the
  dump renamed. An interrupted run leaves no complete-looking file.
- `restore` checks the sidecar's format, SHA-256 and size, and that the dump's schema is not newer
  than the running Ruvee, **before** creating anything.
- After loading, `restore` checks what it can without keys: every manifest envelope is the
  documented size and purpose, `vaults.current_seq` equals the newest commit's `seq`, and every
  item revision is within the commit history. It cannot check ciphertext; clients do that on
  their first sync (INV-07).

### 3.4 Authentication versus decryption

A restore changes what the **server** knows. It cannot change what any **device** holds.

- **Authentication** (OPAQUE record, sessions, tokens, device rows, throttles) is restored as it
  was, and the restore policy can change it: ending sessions, deleting pairings.
- **Decryption material** (`AK_WRAP_PASSWORD`, `AK_WRAP_RECOVERY` and `SHA-256(RAK)`, the keyset
  and its `SK`) is also restored as it was. Ending sessions does **not** make it current again: a
  password, `SK` or Recovery Kit replaced after the snapshot is replaced only on the devices that
  hold the newer state, and on the server it is the old one again until the owner repeats the
  change.
- **Device trust** is cryptographic: an enrolled device holds `SK` and its own wrap of `AK`.
  Deleting sessions makes it sign in again; it does not un-enroll it, and it does not re-enroll a
  device the restored server never heard of.

### 3.5 Restore state machine

```
 VERIFY ──► PREPARE ──► LOAD ──► MIGRATE ──► APPLY POLICY ──► CHECK ──► READY ──► SERVING
   │           │          │         │             │              │         │
   └───────────┴──────────┴─────────┴─────────────┴──────────────┘         └ first API start
     any failure: stop; drop only the database this run created; the old database,
     the dump and the setup file are never modified
```

| State        | Does                                                                                 | Fails safely because                                     |
| ------------ | ------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| VERIFY       | Sidecar format, SHA-256, size, schema version; setup file present and readable       | Nothing exists yet                                       |
| PREPARE      | Creates a **new, empty** database named by the operator; refuses one with any table  | Only that database exists                                |
| LOAD         | `pg_restore` into it                                                                 | Partial loads stay in the new database, which is dropped |
| MIGRATE      | `prisma migrate deploy` to the running version                                       | Same                                                     |
| APPLY POLICY | The D-28 rules (§3.6) in **one transaction**                                         | All or nothing                                           |
| CHECK        | §3.3 structural checks; a marker row `restore_completed` written last                | A run without the marker is incomplete by definition     |
| READY        | Prints what was restored (snapshot time, counts) and the owner's next steps          | —                                                        |
| SERVING      | The API refuses to start on a database whose newest restore has no completion marker | An interrupted restore can never be served               |

Re-running a failed restore starts again from VERIFY with a new database name.

### 3.6 Recommended V1 restore policy (D-28 option A, as specified)

Applied in APPLY POLICY, before the API serves anything:

1. **Every session ends:** all `cookie`, `token` and `recovery` sessions are revoked (new revoke
   reason `restored`). Refresh tokens belong to those sessions and stop working with them. Access
   tokens are session hashes and stop too. (Login and step-up states are in memory and are gone
   with the old process.) Proven necessary: without this, a refresh token rotated after the
   snapshot, and a recovery session ended after it, work again
   (`backup-restore.int-spec.ts`).
2. **Pairings are deleted.** A pairing in progress at snapshot time is gone; it is restarted.
3. **Unused setup tokens are deleted.** Proven necessary: restoring a copy taken before the
   account existed otherwise reopens registration to whoever held that token
   (`backup-restore-early.int-spec.ts`).
4. **A `server_restored` event** records the snapshot time, and `GET /account` returns
   `lastRestoredAt` and `restoredToAt` (as it returns `lastRecoveryAt`), so every client can say
   plainly what happened. Clients use it only for wording; it cannot be trusted for security.
5. **Nothing else changes:** devices, OPAQUE record, wraps, keyset, items and throttles stay as
   in the snapshot. In particular no device is revoked or re-enabled automatically: the server
   cannot know what happened after the snapshot.
6. **Clients** (small changes):
   - show "This server was restored to <time>" with what it means for this device, instead of
     the generic integrity message, when `server_behind`, `keyset_rollback`, a wrap that no
     longer opens, or an unknown device coincides with a restore notice;
   - offer **Start over on this device**: wipe the local store (after offering the export below)
     and log in again, then pair from a device that is in step with the server, or recover with the Recovery
     Kit as of the snapshot;
   - allow an **encrypted export of the local copy** when the server is unreachable or behind,
     confirmed by the master password against the local wrap instead of an online step-up, so the
     newest data can be kept before starting over. (Today `exportVault` needs the server.)

### 3.7 Changes made after the snapshot

| After the snapshot…           | The restored server                                                                                                          | Devices that saw the change                                       | Owner action                                                                                                                |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Items changed                 | Has the older items                                                                                                          | Stop read-only (`server_behind`, INV-07)                          | Export the newer copy locally, start over, re-enter what is missing                                                         |
| A device was removed          | Lists it as active again; its session is ended (rule 1) but it can sign in again if it knows the password as of the snapshot | —                                                                 | **Remove it again**; as lost if it was lost, which rotates `SK` again (D-24)                                                |
| A device was added            | Has never heard of it                                                                                                        | Signs in as a new pending device; cannot sync                     | Start over on it and pair again                                                                                             |
| Password changed              | Accepts only the **old** password for login                                                                                  | Unlock locally with the new one, but cannot sign in               | Sign in with the old password once (from any device, or recover), then change it again                                      |
| `SK` rotated                  | Has the old keyset and the wrap under the old `SK`                                                                           | Stop at the next online unlock (`keyset_rollback`, INV-09)        | Start over on them, then **replace `SK` again**: the old `SK`, which a lost device may hold, is current again on the server |
| Recovery Kit replaced         | Accepts only the **old** kit                                                                                                 | —                                                                 | **Make a new kit again**; the old kit works again until then                                                                |
| Recovery started or completed | The recovery is undone; a recovery session open at snapshot time is ended (rule 1)                                           | The recovering device holds newer wraps: as for a password change | As for a password change and a new kit                                                                                      |
| Pairing in progress           | Deleted (rule 2)                                                                                                             | The joining device waits, then times out                          | Pair again                                                                                                                  |
| Sessions, refresh tokens      | Ended (rule 1)                                                                                                               | Sign in again                                                     | —                                                                                                                           |
| Security events               | Lost, except `server_restored`                                                                                               | —                                                                 | Keep the old server's logs if any survive                                                                                   |

### 3.8 How existing clients detect the older history

- **Checkpoint ahead of the server** → `server_behind` (sync-protocol §5 check 4): nothing is
  applied; the vault stays readable and read-only. Tested
  (`vault-engine.test.ts` "a device ahead of the snapshot stops read-only").
- **Keyset newer than the server's** → `keyset_rollback` at the next online unlock. Tested.
- **Checkpoint at or behind the snapshot, same chain** → syncs normally; the restore is invisible
  to it. Tested.
- **A device ahead, after the restored server accepted new commits from another device** → the
  chain at its checkpoint differs: `history_rewritten`, read-only.
- **Unknown device id** (added after the snapshot) → its sign-in creates a new pending device;
  the client reports that it could not sign in.
- **A device without any checkpoint** (new, or recovered after the restore) cannot tell an older
  state from a newer one (R-07).

### 3.9 What the backup alone cannot repair or revoke

- Changes made after the snapshot: they exist only on devices, until re-seeding (M3) or manual
  re-entry.
- Revocations, password changes, `SK` rotations and Recovery Kit replacements made after the
  snapshot: undone on the server; they must be repeated. Until they are, an old password, an old
  kit and an old `SK` work again against this server.
- Anything any device or person already copied: wraps, records, keys (cryptographic-design §6.4).
- Every older dump still opens with the credentials of its own day.
- The history of security events after the snapshot.

### 3.10 What the owner does during a real restore

1. Stop the old server if it still runs, so no device writes to it.
2. If the old server is gone and a device is ahead of the newest dump, make an encrypted export
   on that device first (§3.6 client change), or decide that the snapshot is enough.
3. On a clean host: install the same or a newer Ruvee, create an empty database, put the setup
   file's offline copy in place, and write `.env` from the sidecar's values and new host values.
4. Run `ruvee-admin restore <dump>`; read its summary.
5. Start the API and Caddy at the **same** `PUBLIC_ORIGIN`.
6. On each device, sign in with the password **as of the snapshot**. Devices in step continue;
   others offer **Start over on this device**, then pair or recover.
7. Repeat every security change made after the snapshot: remove devices again (as lost where it
   applies), change the password again, replace `SK` again, make a new Recovery Kit again.
8. Re-enter changes made after the snapshot from the local export, opened read-only.

**Lost for good:** vault changes after the snapshot that were on no device; security events after
the snapshot. **Must be redone:** device enrolments, the security changes in step 7.

### 3.11 Missing mechanisms (the M1 implementation)

- `ruvee-admin backup` and `ruvee-admin restore` (none exist; the CLI has `opaque-setup` and
  `bootstrap-token`), and the CI image's PostgreSQL 18 client tools.
- Revoke reason `restored`, event type `server_restored` with an allow-listed snapshot time, a
  `restore_completed` marker and the API's refusal to start without it (migration with down).
- `GET /account`: `lastRestoredAt`, `restoredToAt`.
- Client: the restore notice, **Start over on this device**, and the offline encrypted export.

## 4. Portable encrypted export (milestone M2)

### 4.1 Recommendation: a container of existing envelopes, opened only by the Recovery Kit

The export holds envelopes that Ruvee already produces and verifies, plus one new instance of an
existing one. It adds **no new cipher, KDF, MAC or purpose**:

| Part      | Existing construction                                                                                                              | Authenticated by                                                                           |
| --------- | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `AK` wrap | `AK_WRAP_RECOVERY` (purpose `0x02`): `AK` under `RWK = KDF(RK)`, context `account_id ‖ ak_id ‖ ak_epoch`, key id `recovery_key_id` | AEAD under `RWK`                                                                           |
| Keyset    | `KEYSET` (`0x03`) as stored on the server                                                                                          | AEAD under `K_keyset` from `AK`, context `account_id ‖ keyset_version`                     |
| Manifest  | `MANIFEST` (`0x06`) at the newest `seq` the exporting device verified                                                              | AEAD under `K_manifest` from `VK`; contains `items_digest`, counts, author device and time |
| Items     | Item records (`ITEM_KEY` `0x04` + `ITEM_BODY` `0x05`) exactly as synced, and tombstones                                            | `items_digest` in the manifest, and each envelope's own context                            |

The `AK` wrap is made **at export time from the Recovery Key the user types**, with a fresh
16-byte `recoveryKeyId` as its key id (the client already
does this when it creates a kit, `wrapAccountKeyForRecovery`). This proves the user holds a key
that opens the export before the file exists, and keeps the export independent of later kit
rotations: it opens with the kit typed, nothing else.

Every field outside an envelope is a copy of a value that some envelope authenticates; the
importer compares and refuses any difference (§4.3). So the file needs no separate MAC, and
truncation, reordering, a missing item or an extra item are all caught by `items_digest`.

Alternatives (D-13 options B and C) are in §7.

### 4.2 Schema (version 1, as implemented in `packages/vault/src/export-file.ts`)

One UTF-8 JSON document, `application/vnd.ruvee.export+json`, extension `.ruvee`. All byte
values are unpadded base64url of the exact bytes (cryptographic-design §2). Unknown fields are
refused.

```json
{
  "format": "ruvee-export",
  "version": 1,
  "accountId": "<uuid>",
  "vaultId": "<uuid>",
  "akId": "<16 B>",
  "akEpoch": 1,
  "recoveryKeyId": "<16 B, this wrap's key id>",
  "recoveryWrap": "<AK_WRAP_RECOVERY envelope, exactly 93 B>",
  "keyset": { "version": 2, "envelope": "<KEYSET envelope, 61..16445 B>" },
  "manifest": { "seq": 1234, "envelope": "<MANIFEST envelope, exactly 198 B>" },
  "items": [{ "itemId": "<uuid>", "revision": 7, "record": "<item record> | null" }]
}
```

Bounds: at most 100,000 items; `record` as in sync-protocol §4.2 (`null` is a tombstone);
`items` sorted by `itemId` bytewise; the whole file at most 512 MiB. The time and the author
device are **not** header fields: they are read from the authenticated manifest.

### 4.3 Opening an export (all checks before anything is shown)

1. Parse strictly against the schema; any unknown field, duplicate item, bad bound or bad
   base64url fails.
2. Parse the typed Recovery Key (checksum); derive `RWK`. Open `recoveryWrap` with the expected
   key id `recoveryKeyId` and context `accountId ‖ akId ‖ akEpoch` → `AK`; the expectations come
   from the file's fields and the AEAD rejects any that differ from what it authenticates (INV-03).
   Failure: "This Recovery Key doesn't open this export."
3. Open `keyset.envelope` with `accountId` and `keyset.version` → `SK`, vault keys. The keyset's
   only vault must have id `vaultId`.
4. Open `manifest.envelope` under `K_manifest` with `vaultId` and `manifest.seq`; its plaintext
   `vault_id` and `seq` must match. Recompute `items_digest`, `live_count` and `tombstone_count`
   from `items` (record hashes, revisions, states); all must match.
5. Open every record at its revision (`ITEM_KEY`, `ITEM_BODY`), validate the body schema.
6. Show: "Vault as of <manifest created_at>, last changed by <device>", with no claim that it is
   the newest copy (no checkpoint exists, account-recovery §7).

Any failure fails the whole import; nothing partial is shown or stored.

### 4.4 Restoring an export

- **Read-only, on a clean device, no server:** steps 1 to 6 in the web app's worker, in memory
  only; locking or closing discards it. No account, no network.
- **Into a fresh installation** (implemented; §4.4a): a new account is created with **new** keys
  (`AK`, `SK`, `VK`, a new Recovery Kit, a new password), and every item is decrypted in the
  worker and re-encrypted as a new item under a fresh id, queued as ciphertext and uploaded
  through the normal commit path, so an interrupted import resumes. The old account's keys are
  never reused, so no old copy of the old `SK`, wraps or sessions carries over.
- **Into the existing account:** not in M2. (Merging needs a conflict design; restoring deleted
  items belongs with version history, Phase 7.)

Sessions, devices, pairings and recovery attempts are not in an export at all; a restore starts
with one new device and no history.

### 4.4a Import into a fresh installation: state machine

Portable import restores **vault contents** into a **new account**. It is not an operational
server restore (§3): no account, device, session, OPAQUE record, security event or recovery
state of the source is carried over, and the source's manifest chain is not reused.

```
 OPENED ──(Continue)──► SETTING_UP ──(setup finished, vault empty)──► QUEUED ──► UPLOADING ──► COMPLETE
   │                        │                                                       │
 cancel: nothing         cancel: an empty new account                          interrupted: resumes
 created                 (log in or recover; import later from Security)        at the next unlock
```

| State          | Where it lives                                                                                                                                                                                                         | What exists                                                                                                                                       | On cancel or failure                                                                                                                                                                                                                   |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OPENED**     | Worker memory only                                                                                                                                                                                                     | The export, fully verified (§4.3); a preview                                                                                                      | Close: nothing was created anywhere                                                                                                                                                                                                    |
| **SETTING_UP** | Worker memory; the server during `register/finish`                                                                                                                                                                     | The existing setup flow: bootstrap token, new username and password, **new** Recovery Kit that must be typed back (D-06)                          | Before `register/finish`: nothing on the server. If the browser stops after the server accepted it, an empty account exists; the user logs in or recovers it with the new kit and imports from Security (the "empty vault" path below) |
| **QUEUED**     | One IndexedDB transaction: an encrypted `import` local record (counts, source date; no plaintext) and an `imports` store of item records **already re-encrypted** under the new keys, each with a fresh random item id | All items, as ciphertext, on this device                                                                                                          | Atomic: either every item is queued or none is                                                                                                                                                                                         |
| **UPLOADING**  | The existing pending queue and commit path (sync-protocol §4, §7)                                                                                                                                                      | Batches of at most 100 items or 256 KiB move from `imports` into the pending queue; an item leaves `imports` only after it is in the synced state | Offline, closed tab, browser restart: the next unlock continues. New items cannot be added meanwhile, so the import is the only writer                                                                                                 |
| **COMPLETE**   | The `import` record marked complete                                                                                                                                                                                    | Every queued item is on the server and in this device's verified state                                                                            | —                                                                                                                                                                                                                                      |

Guarantees it relies on, all existing:

- **No duplicates on retry:** each destination item id is fixed when it is queued and is created
  with base revision 0. A commit retried after a lost response reuses its commit id, and the
  server refuses a second creation of an existing id (`revision_conflict`); the client then sees
  its own record (sync-protocol §6, "recognises its own commit").
- **Never "complete" while partial:** completion requires an empty `imports` store, an empty
  pending queue and no commit in flight, after a verified sync.
- **New history:** the new vault's chain starts at its own genesis; every imported item is a new
  item at revision 1 in a normal commit. The source manifest only authenticated the file (§4.3).
- **No plaintext at rest:** bodies are decrypted and re-encrypted in the worker; the queue holds
  only item records. There are no temporary files.

**The empty-vault path.** Import is allowed into the account this device is unlocked in only
when that vault has never held an item (no live item, no tombstone, nothing pending) and no
import was started before. This is how an interrupted account creation resumes, and it is not a
merge. A vault that already holds items, including a partial import whose local queue was lost
(browser data cleared mid-upload), is refused: the user can compare with the export opened
read-only, or import into another fresh installation. Nothing is deleted automatically.

**What is imported** (item schema 1 has no references between items, attachments or folders):
type, title, login username, password, URLs and notes, note text, tags, favorite, trash state and
its time, and the created and updated times. Items in Trash stay in Trash. Deleted items in the
export (tombstones) are deletion markers with no content; they are counted in the preview and
not imported. Format version 1 cannot hold an item the importer does not support: an item that
does not decode makes the whole file fail (§4.3 step 5), so nothing is dropped silently.

### 4.5 Consistency, versioning, interruption

- The exporting device exports only state it has verified against its checkpoint, with no
  pending local changes (it syncs first and refuses while conflicts or pending mutations exist).
- `version` changes on any format change; an importer refuses versions it does not know.
- The file is produced in the worker and handed to the browser as one download; a partial file
  fails step 4.
- Rollback: an older export file is a valid older vault. Only the authenticated date and author
  tell them apart; the user decides.

### 4.6 If the Recovery Kit is lost

The export can never be opened. Nothing on the server or in any other file helps. The export
screen says this before creating the file. Devices do not learn the server kit's id, so
`recoveryKeyId` is generated for each export and does not name a kit; the file name carries only
the date. The user must remember which kit they typed.

### 4.7 Never on the server

The export is produced and read in the client. It is never uploaded, and the API gets no export
endpoint. Plaintext export (CSV and the like) is out of scope here.

## 5. Recommended first milestone: M1, server backup and restore

M1 comes first because:

1. **It protects against the likeliest loss.** A single self-hosted server with one disk is the
   largest risk to the owner's data today, and there is no documented or tested way back.
2. **It needs no new format and no new client cryptography.** The dump is a database copy; the
   security work is in the restore rules (D-28), which are server-side and testable with the
   existing harness and the scaffolding already in the repository.
3. **It exercises protections that exist**: rollback detection (INV-07, INV-09) and Recovery Kit
   recovery, under the real condition they were designed for.
4. **The export depends on more**: D-13, an independent review of the format (D-19 scope), and
   the export screen's step-up and Recovery Key entry.

M1 does **not** include re-seeding (M3, Phase 4 design) or any export.

## 6. Restore acceptance-test plan (synthetic data only)

Each test creates its own `ruvee_it_*` / `ruvee_e2e_*` database and synthetic accounts.

**M1, server backup** (after D-28). The characterization tests already in the repository
(`backup-restore*.int-spec.ts`, `vault-engine.test.ts` "clients after a server restore") show
today's behaviour and become the "before" half of R4 to R8.

| ID  | Test                                                                                                             | Expected                                                                                         |
| --- | ---------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| R1  | Back up while a client commits in a loop                                                                         | The restored chain verifies end to end; no half commit                                           |
| R2  | Restore into a fresh database; sign in with the snapshot-time password                                           | Login works; a device in step syncs                                                              |
| R3  | Restore without the setup file                                                                                   | Login fails; Recovery Kit (snapshot-time) recovery succeeds                                      |
| R4  | Cookie, access, refresh and recovery tokens from before the snapshot, including a refresh token rotated after it | All refused (rule 1)                                                                             |
| R5  | A pairing open at snapshot time; an unused setup token                                                           | Gone (rules 2, 3); registration stays closed                                                     |
| R6  | A device removed after the snapshot                                                                              | Listed again; signs in only with the snapshot-time password; the review shows it                 |
| R7  | Password changed after the snapshot                                                                              | Only the old password signs in; the device with the new wrap unlocks offline and sees the notice |
| R8  | `SK` rotated after the snapshot                                                                                  | The device with the newer keyset stops (`keyset_rollback`) and offers Start over                 |
| R9  | Items changed after the snapshot                                                                                 | The device ahead stops (`server_behind`); its offline export holds the newer items               |
| R10 | Recovery Kit replaced after the snapshot                                                                         | The old kit recovers, the new one does not; the notice says so                                   |
| R11 | Corrupted dump, wrong SHA-256, truncated file, newer schema, missing setup file                                  | Refused in VERIFY; nothing created                                                               |
| R12 | Restore killed in each state                                                                                     | The old database untouched; the new one has no completion marker and the API refuses it          |
| R13 | Scan dump and sidecar                                                                                            | No OPAQUE setup, no plaintext, no raw token (INV-01, INV-13, INV-21)                             |
| R14 | Browser: devices A (ahead) and B (in step) against a restored server                                             | B continues; A shows the restore notice, exports, starts over and pairs from B                   |

**M2, portable export** (after D-13)

| ID  | Test                                                                                           | Expected                                                                            |
| --- | ---------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| E1  | Export, then open on a clean browser profile with no server                                    | Items match; date and author shown                                                  |
| E2  | Wrong Recovery Key; a kit of another account                                                   | Refused at step 2; nothing shown                                                    |
| E3  | Flip one byte in each part; drop, add, reorder or duplicate an item; change `seq` or `version` | Refused; nothing shown                                                              |
| E4  | Truncated file; unknown field; oversized values                                                | Refused by the parser                                                               |
| E5  | Import into a fresh installation, interrupted halfway, then resumed                            | Every item present once; new account keys differ from the old                       |
| E6  | Capture                                                                                        | No plaintext and no Recovery Key on the wire or at rest; nothing uploaded           |
| E7  | Vectors                                                                                        | A fixed synthetic export opens identically in Node, the browser page and the worker |

## 7. Decision table

| ID       | Decision                              | Options                                                                                                                                                                                                                                                                                                                                   | Recommended           | User-visible consequence                                                                                                                                                                                                                                                                               |
| -------- | ------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **D-13** | Portable export format                | **A.** Container of existing envelopes; `AK` wrapped under the Recovery Key typed at export (§4). **B.** A, plus an export passphrase: `AK` also wrapped under an Argon2id key from a new passphrase (new purpose `0x09`). **C.** Encrypt the export with the established `age` format (passphrase or X25519 recipient) over A's content. | **A**                 | To make or open an export, you need your Recovery Kit. Without it the export is useless. With B, a passphrase opens the file, so a stolen file can be guessed offline at one Argon2id per try. C adds a second library and, in passphrase mode, the same weakness, for no gain over A's existing AEAD. |
| **D-28** | What restoring a server backup undoes | **A.** As specified in §3.6: end every session (cookie, token, recovery), delete pairings and unused setup tokens, record `server_restored`, change nothing else on the server, and the three client changes. **B.** Restore as is. **C.** A, plus re-applying revocations from a journal kept outside the database.                      | **A**                 | After a restore every device signs in again and you review your devices; a device you removed after the backup date must be removed again. With B, a removed device's old session works again. C needs extra infrastructure.                                                                           |
| D-29     | Encrypting dump files at rest         | **A.** The guide requires encrypted storage, apart from the setup file; Ruvee does not encrypt. **B.** `ruvee-admin backup` encrypts with `age` to an operator key.                                                                                                                                                                       | **A** for M1, B later | With A you choose where dumps are kept and must keep them apart from the setup file. Not blocking.                                                                                                                                                                                                     |

## 8. Implementation plan

**M1 (after D-28)**, in order; each step depends on the ones before it:

1. Migration: revoke reason `restored`, event `server_restored`, restore marker (with down).
2. `ruvee-admin backup --out <dir>`: `pg_dump`, `.partial`, SHA-256, sidecar.
3. `ruvee-admin restore <dump> --database-url <empty db>`: the §3.5 states and the §3.6 server
   rules; the API's start-up check for the marker.
4. `GET /account` restore fields; web and extension restore notice; Start over; offline
   encrypted export.
5. Tests R1 to R14; CI installs the PostgreSQL 18 client.
6. Operator guide (§3.10 as a runbook), linked from the README.

**M2 (D-13 approved for development; independent review of §4 still required)**

Status 2026-10-26: steps 1 to 5 are implemented. Export, read-only opening, and import into a
fresh installation (§4.4a): `export-file.ts`, the engine's `exportVault`, `exportOpen` and
`importIntoEmptyVault`, Security → Encrypted export and Import, the welcome screen's restore
path, `import.test.ts`, the fixed fixture in `packages/vault/test/fixtures`, and the
`test:import` browser suite (two installations). E7 holds in Node only (the fixed fixture); the
browsers are covered by fresh exports, not the fixed file.

1. Export builder and verifier in `packages/vault` (pure, over `@ruvee/crypto`), with fixed synthetic vectors (E7). Depends on D-13.
2. Web: Security → "Export an encrypted copy": step-up, sync, Recovery Key entry, download. Depends on 1.
3. Web: "Open an export" without an account (read-only, worker only). Depends on 1.
4. Setup flow "Create an account from an export". Depends on 1, the existing setup and commit paths.
5. Tests E1 to E7. Depends on 1 to 4.

**M3 (Phase 4 design first):** re-seeding a restored or new server from a device.
