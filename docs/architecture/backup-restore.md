# Backup and restore

Status: **Proposed (2026-10-26).** **D-13 option A was approved by the owner for development on
2026-10-26**, and the export (§4) is implemented to that design; the restore rules for server
backups (§3.4) are still blocked on **D-28**. ADR: [ADR-0010](../adr/0010-backup-and-portable-export.md). Not
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

### 3.1 Included

- A logical dump of the Ruvee database (`pg_dump --format=custom`) and a sidecar file
  `<name>.json` with: format `ruvee-server-backup/1`, the dump's SHA-256, its size, the
  `_prisma_migrations` row of the newest applied migration, the Ruvee version, and the creation
  time. Nothing in the sidecar is secret.
- Everything in the database: `accounts`, `opaque_credentials` (OPAQUE records), `account_keys`
  (`AK_WRAP_PASSWORD`, `AK_WRAP_RECOVERY`, `SHA-256(RAK)`, keyset envelope, `salt_pw`, profile,
  `keyset_version`, `row_version`), `devices`, `sessions` and `refresh_tokens` (hashes only),
  `pairings`, `vaults`, `vault_items`, `vault_commits` (with each commit's manifest), `security_events`,
  `auth_throttle`, `bootstrap_tokens` (hashes).

**Not included:** the OPAQUE server setup file (INV-21; it is a separate secret with its own
offline copy, [authentication.md §Server secrets](../security/authentication.md#server-secrets)),
`.env`, TLS keys, and anything on client devices.

### 3.2 Secrets needed to restore, and who holds them

| Secret                               | Holder                                     | Needed for                                                                      |
| ------------------------------------ | ------------------------------------------ | ------------------------------------------------------------------------------- |
| The dump file                        | Operator; stored apart from the setup file | Everything                                                                      |
| OPAQUE server setup file             | Operator; offline, separate copy           | Logins. Without it, each user re-registers through Recovery Kit recovery (R-13) |
| Password and `SK`, as of backup time | User and enrolled devices                  | Opening the vault after logging in                                              |
| Recovery Kit, as of backup time      | User                                       | Recovery if the setup file is lost, or the password changed after the backup    |

The dump alone is ciphertext plus OPAQUE records. Dump **plus** setup file allows offline password
guessing (V-01), so they must never be stored together, and a whole-disk backup that holds both
is protected like the server itself. Encrypting the dump at rest is D-29 (recommended, not
blocking).

### 3.3 Consistency, integrity, versioning, interruption

- **Consistency:** `pg_dump` reads one repeatable-read snapshot, so items, manifests and commits
  are mutually consistent (a commit is one transaction, sync-protocol §4.2). No API downtime is
  needed.
- **Integrity:** `restore` checks the sidecar's SHA-256 and size before touching anything, then
  runs `pg_restore` into a **new, empty** database. It refuses a database that has any Ruvee
  table. A failed or interrupted restore leaves only that new database, which is dropped; the
  running database is never modified.
- **Versioning:** the sidecar records the newest migration. Restoring needs the same or a newer
  Ruvee version; `prisma migrate deploy` then applies any newer migrations. An older Ruvee refuses
  a dump from a newer schema.
- **Interrupted backup:** the dump is written to `<name>.partial` and renamed only after the
  sidecar is written; a run that stops leaves no file that looks complete.

### 3.4 What a restore must undo (D-28, blocking M1)

A restored database is the server _as it was_. The characterization tests in
`apps/api/test/backup-restore.int-spec.ts` show what that means today: **a device removed after
the backup is active again, with its old session**, and every security event since the backup
is gone. Proposed rules, applied by `restore` before the API serves anything:

1. **Sessions:** revoke every `cookie`, `token` and `recovery` session (reason `restored`).
   Every device signs in again; stolen cookies or tokens from before the backup stop working.
2. **Pairings and login states:** delete open pairings. (Login and step-up states are in memory
   and do not survive a restart anyway.)
3. **Devices:** keep them as they were at backup time, but record a `server_restored` event with
   the backup time, and make the web app show, once, on the next sign-in: the date the server was
   restored to, the devices list for review, and that devices removed after that date are listed
   again and must be removed again (as lost, which rotates `SK`, if that was the reason).
4. **Recovery:** `AK_WRAP_RECOVERY` and the verifier are those of backup time. A Recovery Kit
   rotated after the backup works again, and the newer one does not (account-recovery.md §5's
   caveat in the other direction). The notice says so, and offers making a new kit.
5. **Keys:** a password change, `SK` rotation or Recovery Kit rotation made after the backup is
   undone on the server. Devices that made or adopted it hold a newer keyset or wrap. They see a
   keyset rollback (INV-09) or a manifest rollback (INV-07) and stop, read-only, as designed.

What a restore **cannot** do: bring back changes made after the backup (they survive only on
devices that synced them, until re-seeding exists, M3), know which devices were removed after
the backup, or remove copies anyone made before.

### 3.5 Restoring

- **Onto a clean machine:** install the same or a newer Ruvee, create an empty database, run
  `ruvee-admin restore <dump>`, put the setup file where `OPAQUE_SERVER_SETUP_FILE` points, start
  the API. With the setup file, users log in with their password as of backup time. Without it,
  each user recovers with the Recovery Kit as of backup time, which re-registers OPAQUE.
- **Into a fresh installation** (a new server that never ran Ruvee): the same; the restored
  `bootstrap_tokens` are already used, so registration stays closed.
- **Devices ahead of the backup** stop with "the server is behind this device" until re-seeding
  (M3) exists. Today that shows as the read-only integrity state.

### 3.6 Rollback limitations

Restoring is a rollback by definition. Clients with a checkpoint detect it (INV-07, INV-09); a
device without one (newly paired after the restore, or recovered) cannot tell an older state
from a current one (R-07). Restoring **more than once**, or to an older dump than a previous
restore, repeats all of the above.

### 3.7 If a required secret is lost

- **Dump lost:** nothing to restore; devices keep their local copies and could re-seed a new
  server (M3).
- **Setup file lost:** logins fail; each user recovers with the Recovery Kit as of backup time.
- **That Recovery Kit lost too:** a device whose local copy still opens with the password can
  keep reading offline and, once re-seeding exists, rebuild the server. With no such device the
  vault is permanently lost. No operator action can help (INV-18).

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

**M1, server backup**

| ID  | Test                                                                         | Expected                                                                              |
| --- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| R1  | Back up while a client commits in a loop                                     | The restored chain verifies end to end; no half commit                                |
| R2  | Restore the dump into a fresh database; log in with the backup-time password | Login works; the device opens its vault and syncs                                     |
| R3  | Restore without the setup file                                               | Login fails; Recovery Kit (backup-time) recovery succeeds and re-registers OPAQUE     |
| R4  | Sessions and refresh tokens taken before the backup                          | All refused after restore (D-28 rule 1)                                               |
| R5  | A device removed after the backup                                            | Listed again; flagged in the one-time review; its old session refused                 |
| R6  | Password changed after the backup                                            | Only the old password logs in; a device with the new local wrap still unlocks offline |
| R7  | `SK` rotated after the backup                                                | A device holding the newer keyset stops with a keyset rollback (INV-09), read-only    |
| R8  | Commits made after the backup                                                | Devices ahead see "server behind"/rollback (INV-07), nothing applied                  |
| R9  | Recovery Kit rotated after the backup                                        | The old kit recovers; the new one does not; the notice says so                        |
| R10 | Corrupted dump, wrong SHA-256, truncated file, newer schema                  | Restore refuses before changing anything                                              |
| R11 | Restore interrupted (process killed)                                         | The running database is untouched; the partial one is dropped                         |
| R12 | Scan the dump and sidecar                                                    | No OPAQUE setup, no plaintext, no raw token (INV-01, INV-13, INV-21)                  |

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
| **D-28** | What restoring a server backup undoes | **A.** End every session, delete pairings, record `server_restored`, one-time device review (§3.4). **B.** Restore as is. **C.** A, plus re-applying revocations from a journal kept outside the database.                                                                                                                                | **A**                 | After a restore every device signs in again and you review your devices; a device you removed after the backup date must be removed again. With B, a removed device's old session works again. C needs extra infrastructure.                                                                           |
| D-29     | Encrypting dump files at rest         | **A.** The guide requires encrypted storage, apart from the setup file; Ruvee does not encrypt. **B.** `ruvee-admin backup` encrypts with `age` to an operator key.                                                                                                                                                                       | **A** for M1, B later | With A you choose where dumps are kept and must keep them apart from the setup file. Not blocking.                                                                                                                                                                                                     |

## 8. Implementation plan

**M1 (after D-28)**

1. `apps/api/src/admin/backup.ts`: `ruvee-admin backup --out <dir>` (pg_dump, `.partial`, sidecar). Depends on: nothing new.
2. `ruvee-admin restore <dump> --database-url <empty db>`: checks, `pg_restore`, `migrate deploy`, D-28 rules in one transaction. Depends on 1, D-28.
3. Revoke reason `restored` and event type `server_restored` (migration with down); the web app's one-time restore notice and device review. Depends on 2.
4. Tests R1 to R12, building on `test/support/backup-snapshot.ts` and real `pg_dump` (CI installs the PostgreSQL 18 client). Depends on 1 to 3.
5. Operator guide: where to keep dumps and the setup file, restore steps, what users will see. Depends on 1 to 3.

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
