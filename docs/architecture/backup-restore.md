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

Revision of 2026-10-26. The revised D-28 policy (owner-specified) and D-29 option B (approved
for development) are implemented and tested **on synthetic data only**; §3.11 says what is done
and what is not. M1 is **not** accepted for real data: D-30 and D-19 are open. The operator
procedure is in [the operator guide](../guides/server-backup-restore.md).

### 3.1 What is backed up

`CONFIG_INVENTORY` and `TABLE_INVENTORY` in `apps/api/src/admin/backup-inventory.ts` are the
machine-checked version of this list: a test fails when a table or configuration variable is
added without a classification.

| Input                                    | What it is                                                                                                                                                                                                                                                           | Kept where                                                                            | Secret?                                                                                     | On restore                                                   |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| **Database dump** `<stem>.dump.age`      | age-encrypted `pg_dump --format=custom` of all 13 tables: accounts, OPAQUE records, `AK` wraps, `SHA-256(RAK)`, keyset, devices (with encrypted labels), session and token **hashes**, pairings, items, commits and manifests, events, throttles, setup-token hashes | Operator; age-encrypted (§3.2); at least one copy off the server                      | Yes: OPAQUE records allow offline password guessing **together with** the setup file (V-01) | Loaded into a new, empty database                            |
| **Encrypted metadata** `<stem>.meta.age` | Snapshot time, newest migration, the dump's plaintext SHA-256 and size, the backup id, and the configuration marked `sidecar` in `CONFIG_INVENTORY`: `PUBLIC_ORIGIN`, `SESSION_COOKIE_SECURE`, `EXTENSION_ORIGINS`                                                   | With the dump                                                                         | Encrypted: it describes the installation                                                    | Decrypted and checked in VERIFY; its configuration is reused |
| **Manifest** `<stem>.manifest.json`      | Format `ruvee-server-backup/2`, backup id, recipient, each encrypted file's size and SHA-256. Written last: only a manifest makes a set complete                                                                                                                     | With the dump; its SHA-256 (the **backup digest**) also kept apart by the owner       | No                                                                                          | Checked first, against the owner's digest                    |
| **OPAQUE server setup file**             | The server's OPAQUE key material (INV-21)                                                                                                                                                                                                                            | Operator; **offline and apart from every dump**, made once when the server was set up | Yes: with a dump it allows offline guessing and server impersonation (T-03)                 | Placed at `OPAQUE_SERVER_SETUP_FILE`                         |
| Host configuration                       | `DATABASE_URL` (new password), ports, proxy address, log level                                                                                                                                                                                                       | Chosen on the new host                                                                | `DATABASE_URL` yes                                                                          | Written anew; never copied                                   |
| Attachments                              | Do not exist yet (Phase 7)                                                                                                                                                                                                                                           | —                                                                                     | —                                                                                           | —                                                            |
| Release files                            | The web export, `deploy/Caddyfile`                                                                                                                                                                                                                                   | Part of the Ruvee release                                                             | No                                                                                          | Installed from the same or a newer release                   |
| TLS certificates                         | Issued for the host                                                                                                                                                                                                                                                  | —                                                                                     | Yes                                                                                         | Issued again                                                 |

Nothing on a client device is in a server backup, and the server never holds anything that opens
the vault (INV-18).

### 3.2 Encryption at rest and key custody (D-29 option B, approved for development)

Encryption at rest is an acceptance criterion of M1: a dump holds every wrap, verifier and
ciphertext of its day, and with the setup file it allows offline password guessing (V-01).

- **Format and implementation.** The [age v1 format](https://age-encryption.org/v1) with one
  X25519 recipient, through [`age-encryption`](https://github.com/FiloSottile/typage) 0.3.1 (the
  TypeScript implementation by age's author, BSD-3-Clause), pinned exactly in `apps/api`; it
  uses `@noble/ciphers` 2.4.0 and `@noble/hashes` 2.4.0, the versions `packages/crypto` already
  pins, plus `@noble/curves` 2.4.0, `@noble/post-quantum` 0.5.4 and `@scure/base` 2.4.0
  (lockfile). Ruvee implements no primitive and no format: it calls `Encrypter`/`Decrypter`
  (`apps/api/src/admin/backup-files.ts`). The files are standard age files; decrypting one with the
  Go `age` tool was **not** tested here (it is not installed on the development machine).
  Post-quantum (hybrid) recipients are not used: D-29 chose X25519.
- **Server configuration holds the public key only:** `BACKUP_AGE_RECIPIENT=age1…` (validated in
  `env.ts`; an `AGE-SECRET-KEY-1…` value is refused). The identity (private key) is never
  configuration, never generated by Ruvee, and never on the server except during one restore.
- **Backup set** (three files, one stem `ruvee-<UTC timestamp>`):

  | File                   | Contents                                                                                                               | Encrypted                                |
  | ---------------------- | ---------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
  | `<stem>.dump.age`      | `pg_dump --format=custom`, streamed from `pg_dump` straight into age                                                   | Yes                                      |
  | `<stem>.meta.age`      | JSON (`ruvee-server-backup-meta/2`): snapshot, schema, configuration, the dump's plaintext SHA-256 and size, backup id | Yes                                      |
  | `<stem>.manifest.json` | `ruvee-server-backup/2`: backup id, recipient, each file's size and ciphertext SHA-256                                 | No: holds nothing about the installation |

- **No plaintext on disk.** `pg_dump`'s output is piped into the encryptor and the ciphertext
  into a new file; no unencrypted dump file exists at any time. The restore decrypts straight
  into `pg_restore`'s input. The `pg_restore -f -` conversion used by the R13 test runs in memory.
- **Publication.** Every file is written as `<name>.partial`, created exclusively (`wx`) with mode
  0600, and flushed (`fsync`). Only after `pg_dump` exited 0, the encryption finished, the
  metadata and manifest were written and flushed, are the files renamed: the dump, then the
  metadata, then the manifest last, then the directory is flushed. A set without its manifest is
  never a backup.
- **Failures.** A `pg_dump` that exits non-zero after writing part of a dump (its output still
  ends normally), an encryption error, a write error such as a full disk, or SIGINT/SIGTERM
  (an `AbortSignal`) kills `pg_dump` and removes exactly the files this run created. A process
  killed outright (SIGKILL, power loss) can leave `*.partial` files: nothing reads them, and the
  operator deletes them (guide §6). Error output carries tool messages with the database
  password redacted; the password reaches the tools only in `PGPASSWORD`; no key is ever printed.
- **Restore input checks.** The manifest: a plain file of at most 4 KiB, named
  `ruvee-<timestamp>.manifest.json`, exact schema; its files must be the same stem in the same
  directory (no paths), plain files (no links), within the limits (metadata 64 KiB; dump 16 GiB
  by default, `maxDumpBytes`), and match the listed sizes and SHA-256. The identity: a plain file
  of at most 4 KiB, no group or other permissions, exactly one X25519 identity, whose public key
  is the manifest's recipient. Nothing is extracted from an archive: the dump is a single stream
  that `pg_restore` reads. Unsupported formats (including the unencrypted format 1) are refused.
- **Custody:** the owner holds, each apart from the others: the age identity, the setup file's
  offline copy, their Recovery Kit, their master password, and a record of each backup's digest
  (§3.2a). Losing the identity makes every dump unreadable; there is no recovery for it, by
  design. Rotating the recipient protects only future backups.
- **Off-server copies:** at least one backup set and the setup file kept off the host; a backup on
  the same disk protects against nothing but mistakes.
- **Retention:** suggested 7 daily, 4 weekly, 6 monthly. Every dump keeps the password and
  recovery wraps of its day: an old dump plus an old Recovery Kit (or old password) opens the
  vault as of that day (account-recovery.md §5). After a suspected compromise, delete dumps older
  than the next full key rotation (Phase 4).

### 3.2a Integrity and provenance

- **age authenticates the content, not the author.** Each 64 KiB chunk and the header are
  authenticated, so a modified or truncated file fails to decrypt. But age is not signed: anyone
  who knows the public recipient, including a compromised server or anyone who can read its
  configuration, can make a complete, valid backup set that decrypts with the owner's identity.
  Successful decryption therefore proves nothing about who made the backup.
- **A hash beside a backup is not provenance.** The manifest's SHA-256 values are checked, but
  whoever can replace the files can replace the manifest too. They detect accidents (a damaged
  copy, a partial upload), not substitution.
- **The trusted digest.** `backup` prints the SHA-256 of the manifest file, which commits to both
  encrypted files' SHA-256 and so to their contents. The operator keeps that line somewhere the
  backup storage and the server cannot change (on paper, or with the offline identity).
  `restore --trusted-digest <hex>` refuses any other set. This protects against a backup
  substituted in storage or produced by a compromised server **after** the digest was recorded;
  it does not help if the server was already compromised when the backup was made (the digest is
  then of a bad backup), and it is only as good as the place the record is kept.
- **Without it.** `restore --no-trusted-digest` is an explicit choice; the restore records
  provenance `unchecked` in the guard, and the review and the CLI show it before opening.
- **No signing protocol is added.** Signing backups would need a signing key on the server (which
  the compromise in question would hold) or a new offline signing step; neither is proposed
  without a separate decision.

### 3.2b Trust assumptions for `pg_restore`

A decrypted dump is **trusted operational input**, not a harmless document. `pg_restore` executes
its contents as SQL in the target database: a dump made by an attacker (see §3.2a) can create
functions, triggers or other objects, and, if the restoring role were a superuser, run
`COPY … PROGRAM` on the database host. Therefore:

- restore only a set whose digest matches the owner's record; never one from an unknown source;
- run the restore as a role that owns only the new, empty target database and is **not** a
  superuser (`--no-owner --no-privileges` make every object owned by that role). The test
  containers use a superuser for convenience; a deployment must not;
- the restore's structural checks (§3.3) and clients' checkpoints catch an inconsistent or older
  vault history, not hostile SQL.

### 3.3 Consistent snapshot and integrity

- One `pg_dump` run reads one repeatable-read snapshot: commits, manifests and items are
  mutually consistent (each commit is one transaction). No downtime is needed. R1 tests this
  with a client committing during the backup.
- VERIFY checks, **before anything is created**: the manifest against the trusted digest, both
  files' sizes and SHA-256, the identity, the decrypted metadata (schema, same backup id), the
  schema version (not newer than this Ruvee), and then the **whole dump**: it is decrypted once,
  every chunk authenticated, and its plaintext SHA-256 and size compared with the metadata.
- LOAD decrypts the dump a second time straight into `pg_restore`. Its input is closed only after
  the last chunk authenticated and the plaintext hash matched; on any failure `pg_restore` is
  killed first. If the file changed between the two passes, LOAD fails; the guard is still
  `restoring`, so the database can never be opened (tested by changing the file after VERIFY).
- After loading, APPLY POLICY checks what it can without keys: every manifest envelope is the
  documented size, `vaults.current_seq` equals the newest commit's `seq`, and the commits are
  exactly 1 to `current_seq`. It cannot check ciphertext; clients do that on their first sync
  (INV-07).

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

### 3.5 Restore state machine and maintenance mode

A restore always goes into a **new, empty database**, and that database stays in **maintenance
mode** until the owner completes a review with local tooling. Maintenance is a row in a table
the restore tool creates first, `ruvee_restore_guard`, outside the Prisma schema and excluded from
every backup, so a dump can never carry an "open" state into a restore.

```
 VERIFY ─► PREPARE ─► LOAD ─► MIGRATE ─► APPLY POLICY ─► REVIEW ──(restore-complete)──► OPEN
 (digest,   (empty db;   (pg_     (prisma    (one tx: end       (maintenance:          (normal
  identity,  guard row    restore)  migrate)   sessions, delete   every /api request     service)
  whole dump 'restoring')                      transients, event, gets 503 maintenance)
                                               guard 'review')
   any failure before REVIEW: the guard stays 'restoring'; the API serves maintenance;
   restore-complete refuses; the operator discards that database and starts again
```

| State         | Guard row                              | API                          | Fails safely because                                                                                |
| ------------- | -------------------------------------- | ---------------------------- | --------------------------------------------------------------------------------------------------- |
| VERIFY        | —                                      | not pointed at it            | Digest, files, identity, metadata, schema, and the whole dump decrypted and hashed; nothing created |
| PREPARE       | `restoring`, with a fresh `restore_id` | 503 for every `/api` request | The guard is written **before** any restored row exists                                             |
| LOAD, MIGRATE | `restoring`                            | 503                          | A partial load is still behind the guard                                                            |
| APPLY POLICY  | `review` (same transaction)            | 503                          | All or nothing; structural checks inside the transaction                                            |
| REVIEW        | `review`                               | 503                          | Only the local CLI acts                                                                             |
| OPEN          | `open`, `review_completed_at`          | normal                       | Reached only through `restore-complete`                                                             |

The API (`MaintenanceService`, checked first in the global access guard) fails closed: no
guard table means an ordinary, never-restored installation; a guard that is not `open`, or a
guard table without its row, means maintenance. Until it has seen `open`, the API reads the guard
on every request, so `restore-complete` takes effect without a restart. Once it has seen `open`
it stops asking: the guard can never go from `open` back to maintenance for the same database.

### 3.6 Revised V1 restore policy (D-28, revised 2026-10-26)

Required by the owner on 2026-10-26, replacing the earlier option A:

1. **Isolated, maintenance-mode installation:** restore only into a new, empty database, behind
   the guard (§3.5).
2. **Invalidated transient state,** in the APPLY POLICY transaction: every `cookie`, `token` and
   `recovery` session revoked (reason `restored`), which ends every refresh-token family and access
   token; every pairing deleted; every unused setup token deleted. Login and step-up states are in
   memory and do not exist in a new process.
3. **Closed until reviewed:** while the guard is not `open`, every `/api` request, including
   login, registration, recovery, pairing, refresh and sync, returns `503 maintenance`. Health
   endpoints still answer.
4. **Restored credentials cannot lift it:** only `ruvee-admin restore-complete`, run on the server
   host against that database with the printed `restore_id`, opens it. No API endpoint changes the
   guard, and there is no remote administrative endpoint.
5. **A pre-account snapshot is not open registration:** unused setup tokens are deleted (rule 2);
   after the review, registration needs a new token from `ruvee-admin bootstrap-token`.
6. **A restore event and identifier:** `server_restored` with a fresh random `restore_id`, and
   `restore_review_completed` at the end. `GET /account` shows the latest restore so clients can
   explain what happened. The identifier is a label, not cryptographic proof: a malicious server
   can invent or omit it, and clients rely on their own checkpoints (INV-07, INV-09), never on it.

### 3.6a The restore review (local tooling only)

**Trust model.** The operator who can run commands on the server host already holds everything
the server holds: the database, the OPAQUE setup file, `.env`. Local tooling adds no new power,
and no remote administrative endpoint is created. Nothing in the review can decrypt anything
(INV-18): the CLI reads metadata and changes authentication state only.

The restore commands read the restored database's URL from `RESTORE_DATABASE_URL`, never from
the command line, so its password is not in the process list or the shell history.

**`ruvee-admin restore-review`** prints, without any secret value:

- the `restore_id`, the snapshot time and the dump's SHA-256;
- the account (username), or that the snapshot predates the account (`restore` itself prints
  what the APPLY POLICY step removed: sessions, pairings, setup tokens);
- every device as of the snapshot: id prefix, platform, status, enrolled, last seen;
- **what becomes valid again when maintenance ends:** the master password as of the snapshot (its
  OPAQUE record and password wrap), the Recovery Kit as of the snapshot (its wrap and verifier),
  the keyset as of the snapshot and so the `SK` in it, and every device listed as active with
  whatever `SK` and wraps it holds;
- **what the server cannot infer from the snapshot:** devices removed after it, devices added after
  it, password changes, Recovery Kit replacements, `SK` rotations and recoveries after it, items
  changed after it, and anything anyone copied at any time. Ending sessions and replacing `SK`
  never revoke ciphertext or keys already copied; the CLI says so.

**Owner decisions during the review:**

- **Devices removed after the snapshot:** `restore-review --revoke-device <id> --reason lost|retired`
  revokes it again before anything reopens (device status, its sessions, a `device_revoked` event).
  A device revoked here erases its local copy the next time it connects, as any revoked device
  does. For `lost`, the CLI prints that `SK` must be replaced from an enrolled device after the
  review: the server cannot rotate `SK`, because only devices hold `AK`.
- **Passwords and Recovery Kits replaced after the snapshot:** the review prints that the old
  password and the old kit are valid again when maintenance ends. The owner changes the password
  and makes a new kit from a device right after opening. Making these mandatory before normal use
  needs a restricted post-restore session, which is a new authentication state: see D-30.
- **`SK` rotated after the snapshot:** devices that hold the newer keyset stop at their next online
  unlock (`keyset_rollback`); the restored server's keyset holds the old `SK`. The owner starts
  over on those devices and replaces `SK` again. Rotating `SK` again protects only future copies
  of the database; it never revokes anything already copied.

**`ruvee-admin restore-complete --restore-id <id> --devices-reviewed
--accept-restored-credentials`** opens the installation. It refuses unless the guard is in
`review`, the id matches, and both acknowledgements are given; it records
`restore_review_completed`. The API serves normally from the next request.

**What is not enforced, and why (D-30).** After opening, the snapshot-time password and Recovery
Kit work for ordinary login and recovery at once. Forcing a password change or a new kit before
anything else, or keeping recovery closed until a new kit exists, needs an authentication state
the protocol does not have (a session that may do only that). That part is not implemented; it
is decision D-30 (§7). The review makes the consequence explicit instead, and
`--accept-restored-credentials` is the owner's acknowledgement of it.

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
- **Unknown device id** (added after the snapshot) → its sign-in creates a new pending device
  under another id; the client reports `device_unknown`, keeps its copy and syncs nothing.
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

The step-by-step procedure, including backup creation, key custody, failures and a rehearsal, is
the [operator guide](../guides/server-backup-restore.md). In short: restore the encrypted set
into an empty database with the offline identity and the recorded digest; start the API in
maintenance; review and revoke devices removed after the snapshot; open; sign in with the
snapshot-time password; repeat every security change made after the snapshot; export and
re-enter newer data from devices that were ahead.

**Lost for good:** vault changes after the snapshot that were on no device, and pending edits on
a device that is erased; security events after the snapshot. **Must be redone:** device
enrolments, password, Recovery Kit and `SK` changes made after the snapshot.

### 3.11 Status of the M1 implementation (2026-10-26)

**Implemented and tested, synthetic data only:**

- Encrypted backup and verified restore (§3.2 to §3.3): `apps/api/src/admin/backup-files.ts`,
  `server-restore.ts`, `pg-tools.ts`, `cli.ts`; `BACKUP_AGE_RECIPIENT` in `env.ts`.
- `ruvee-admin backup --out <dir> --synthetic-test-only`, `restore --manifest --identity
(--trusted-digest | --no-trusted-digest)`, `restore-review` (with `--revoke-device`),
  `restore-complete`.
- Maintenance mode and the review (§3.5, §3.6a); clients after a restore (§3.12).
- Tests (§6): `backup-encryption.int-spec.ts` (layout, refusals, failed `pg_dump`, full disk,
  interruption, wrong and loose identities, wrong digest, truncation and modification,
  substituted and forged metadata, forged sets, unsafe names and links, limits, old format,
  failure during LOAD), `restore.int-spec.ts`, `restore-edges.int-spec.ts`,
  `restore-acceptance.int-spec.ts` (R1, R3), `backup-confidentiality.int-spec.ts` (R13), the web
  `test:restore` browser suite (R14 and the restore UI), and the engine tests.

**Not verified, or required before real data:**

- D-30 (a restricted post-restore session, §3.13) and D-19 (independent review, which must now
  include `age-encryption` and `backup-files.ts`) are open. `backup` keeps refusing real
  databases until M1 is accepted.
- Decryption with the Go `age` tool (interoperability) was not tested.
- No deployment exists: no scheduled backups, no off-host copy procedure, no restore rehearsal on
  a real host, no non-superuser restore role set up (§3.2b), no monitoring of backup age.
- R2 (sign-in with the snapshot password in a browser after restore) is covered by R14; R7, R8
  and R10 are covered only by engine tests and the characterization, not as browser tests.
- Concurrency in R1 is real but small (a local database; `pg_dump` takes under a second).

### 3.12 Clients after a server restore

Specified here and implemented in `packages/vault` (`exportLocal`, `localState`, `startOver`),
the web app (`restore-help.tsx`, Security → After a server restore) and the extension popup:

- **Restore-specific messages.** `503 maintenance` → state `maintenance`: "being restored by its
  owner", the local copy readable, nothing new queued. `server_behind`, `history_rewritten` and
  `keyset_rollback` → the restore explanation. `GET /account`'s `lastRestore` changes only the
  wording ("the server reports that it was restored"), never a decision.
- **Newer local data is kept, read-only.** Nothing from the restored server is applied over a
  newer checkpoint (INV-07, INV-09). A device the server no longer knows (`device_unknown`) keeps
  its copy. Only a server-side revocation erases a device (P2-11), and after a restore that
  happens only for a device the owner revoked again in the review.
- **Offline encrypted export first.** `exportLocal` needs only the device's own state, the master
  password (checked against the local wrap) and a Recovery Key typed for the file. The file is the
  existing format (§4.2): the last manifest this device verified and its items. The file is opened
  again with the normal reader before it is offered.
- **What the file contains is stated.** It holds the fully verified snapshot only. Pending edits
  and unresolved conflicts were never verified, so the format cannot hold them: the result counts
  them, the user must acknowledge that they are not included, and they stay on the device.
  Exporting pending edits too would need a format extension; that is a separate decision, not
  part of M1.
- **Start over only on request.** `startOver` erases this device only with the typed confirmation,
  the pending count the user was shown, and either a local export of the current state or an
  explicit "erase without an export". Nothing calls it automatically.

### 3.13 D-30: legitimate owner control after a restore (open, not implemented)

**The problem.** After `restore-complete`, the password and Recovery Kit **as of the snapshot**
work again. If either was replaced after the snapshot, it was probably replaced for a reason: it
leaked, or a device holding it was lost. Whoever knows it can log in or recover first.

**Why "force a new password at first login" is not enough.** A rule that the first login after a
restore may only set a new password and make a new kit decides nothing about _who_ that login
is. The attacker who knows the old password is exactly the person the rule must keep out, and
they would be the one forced to "choose a new password", locking the owner out instead.

**Option B, made precise.** Legitimate control after a restore must rest on something the old
credentials do not give. In Ruvee's deployment model the owner is the person with shell access
to the server host: they already authorize account creation with a single-use setup token from
`ruvee-admin bootstrap-token`, and the restore itself (D-28) already trusts them. B reuses that
root of trust:

1. `restore-complete` opens the installation in a new state, **reopening**, and prints a
   single-use **reopen code** (256 bits, only its hash stored, short expiry), like a setup token.
2. While reopening, ordinary login and recovery are refused. A login or a recovery start is
   accepted only with the snapshot-time password (or Recovery Kit) **and** the reopen code.
3. That session is **restricted**: it may only change the password, make a new Recovery Kit, and
   (on a device that unlocked with the password) replace `SK`; nothing else is served.
4. When the new password and the new kit are both in place, the state becomes **open**, the
   restricted session ends, and every other device signs in with the new password.

An attacker with the old password but without host access cannot get past step 2; one with host
access is, in this model, the owner. What B still does not do: it cannot stop anyone who already
holds an old dump and the old credentials from decrypting that copy offline, and it cannot
revoke keys or ciphertext already copied.

**Minimum changes for B:** a migration (guard state `reopening`, reopen-token hash and expiry, a
`restricted` session kind); `restore-complete` issuing the code; login, recovery start and
session creation checking the state and the code; the access guard limiting restricted sessions
to the password, kit and keyset endpoints; the transition to `open`; client screens to enter the
code and complete the forced change; events; tests; and review under D-19.

**The approval question:** Should the first owner session after a restore require a single-use
reopen code issued on the server host, in addition to the snapshot-time password or Recovery
Kit, with that session limited to replacing the password and the Recovery Kit (and optionally
`SK`), and ordinary login and recovery closed until both are replaced — accepting that host
access, not knowledge of old credentials, becomes the root of control after a restore? (Option C
applies the same only to recovery.)

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

**M1, server backup** (revised D-28, D-29 B). Status 2026-10-26, synthetic data: R1, R3, R4,
R5, R6 (review half), R9, R11, R12, R13 and R14 pass (`apps/api/test/backup-*.int-spec.ts`,
`restore*.int-spec.ts`, `apps/web/e2e-restore`, `vault-engine.test.ts`). R2 is part of R14. R7,
R8 and R10 are covered by engine tests only.

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
| R11 | Wrong identity, wrong digest, truncated or modified ciphertext, substituted metadata, newer schema, unsafe names | Refused in VERIFY; nothing created                                                               |
| R12 | Restore stopped after each state                                                                                 | The old database untouched; the new one stays `restoring`, the API refuses it, complete refuses  |
| R13 | Scan the decrypted dump (as SQL) and the files at rest, with sentinel secrets                                    | Auth records and ciphertext only; no OPAQUE setup, plaintext, key or raw token (INV-01, 13, 21)  |
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

| ID       | Decision                                               | Options                                                                                                                                                                                                                                                                                                                                                        | Recommended                                                                   | User-visible consequence                                                                                                                                                                                                                                                                               |
| -------- | ------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **D-13** | Portable export format                                 | **A.** Container of existing envelopes; `AK` wrapped under the Recovery Key typed at export (§4). **B.** A, plus an export passphrase: `AK` also wrapped under an Argon2id key from a new passphrase (new purpose `0x09`). **C.** Encrypt the export with the established `age` format (passphrase or X25519 recipient) over A's content.                      | **A**                                                                         | To make or open an export, you need your Recovery Kit. Without it the export is useless. With B, a passphrase opens the file, so a stolen file can be guessed offline at one Argon2id per try. C adds a second library and, in passphrase mode, the same weakness, for no gain over A's existing AEAD. |
| **D-28** | What restoring a server backup undoes                  | **Revised policy, specified by the owner on 2026-10-26** (§3.6): isolated maintenance-mode installation, all transient state invalidated, closed until a local review completes, restored credentials cannot open it, pre-account snapshot stays closed, `server_restored` with a fresh id. The earlier option A (devices resume at once) is **not** approved. | Revised policy (implemented for development)                                  | Every device signs in again, and only after the owner has reviewed the restore on the server host. Newer data on a device is kept read-only until you export it.                                                                                                                                       |
| **D-29** | Encrypting dump files at rest (**required** for M1)    | **A.** Ruvee writes plain dumps; the operator must use encrypted storage. **B.** `ruvee-admin backup` encrypts with `age` to an X25519 recipient; the server holds only the public key, the owner holds the identity offline, apart from backup storage and the setup file. **C.** `age` with a passphrase (scrypt). **D.** GPG to an operator key.            | **B: approved by the owner for development (2026-10-26)**; implemented (§3.2) | A stolen backup or a compromised server cannot read old backups; restoring needs the offline identity, and losing it loses every backup. age does not prove who made a backup: keep each backup's digest apart (§3.2a).                                                                                |
| **D-30** | Credentials restored from the snapshot after reopening | **A.** As implemented: after the review, the snapshot-time password and kit work at once; the review states it and the owner repeats changes. **B.** A restricted post-restore session bound to a single-use reopen code issued on the server host (§3.13). **C.** B for the kit only: recovery stays closed until a new kit is made.                          | **B**, open: not approved, not implemented                                    | With A, an old password or kit you replaced after the backup works again, for whoever knows it, until you repeat the change. B makes the host operator's code, not the old credentials, decide who takes control after a restore; it needs a new protocol state and its own review.                    |

## 8. Implementation plan

**M1 (revised D-28, D-29 B)**, in order. Status 2026-10-26: steps 1 to 6 are implemented and
tested on synthetic data (§3.11). The milestone is **not accepted for real data** until D-30 is
decided (and, if B, built), D-19 reviews the restore and backup code, and the deployment items in
§3.11 exist.

1. Migration: revoke reason `restored`, events `server_restored` and `restore_review_completed` (with down).
2. `ruvee-admin backup`: `pg_dump` streamed into age, encrypted metadata, manifest last (§3.2).
3. `ruvee-admin restore`, `restore-review`, `restore-complete`: VERIFY with the identity and
   trusted digest, the §3.5 states and the §3.6 rules; the API's maintenance guard.
4. `GET /account` restore fields; web and extension restore notice; Start over; offline
   encrypted export.
5. Tests R1, R3 to R6, R9, R11 to R14 (§6); CI runs the restore tests with the PostgreSQL 18 tools.
6. [Operator guide](../guides/server-backup-restore.md).

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
