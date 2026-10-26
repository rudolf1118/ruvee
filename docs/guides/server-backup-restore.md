# Server backup and restore (operator guide)

For the person who runs a Ruvee server. Design and reasons:
[backup-restore.md §3](../architecture/backup-restore.md#3-operational-server-backup-milestone-m1).

> **Status (2026-10-26): development only.** Everything below is implemented and tested against
> synthetic test databases. It is **not** ready for real data: `ruvee-admin backup` refuses any
> database except a synthetic `ruvee_it_*` / `ruvee_e2e_*` one, and two decisions are open
> (D-30, how the owner takes control after a restore; D-19, the independent review). Nothing
> here has been run on a deployed server. Use it to rehearse, with synthetic data.

## 1. What you need, and where it lives

| Thing                        | What it is                                   | Where it must be                                                                                    |
| ---------------------------- | -------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Recipient `age1…`            | The public key backups are encrypted to      | Server configuration: `BACKUP_AGE_RECIPIENT`. Not secret                                            |
| Identity `AGE-SECRET-KEY-1…` | The private key that decrypts every backup   | **Offline only** (a USB key in a drawer, a paper copy). Never on the server, never with the backups |
| Backup digests               | One 64-character line printed by each backup | Offline, with the identity or on paper; **not** in backup storage                                   |
| OPAQUE setup file            | The server's login key (made once)           | Offline copy, apart from the backups and from the identity                                          |
| Backup sets                  | Three files per backup                       | Backup storage, at least one copy off the server                                                    |
| Your Recovery Kit, password  | Your account's own secrets                   | Wherever you keep them; never with any of the above                                                 |

Whoever has a backup **and** the identity can attempt to guess your password offline if they also
have the setup file; that is why the three are kept apart.

Requirements: the built API (`pnpm --filter @ruvee/api build`), the PostgreSQL client tools of the
server's major version (`pg_dump`, `pg_restore` 18), or `RUVEE_PG_TOOLS_PREFIX` to run them
inside the database container (README, "integration tests").

## 2. Make the key pair (once, offline)

Make the identity on a machine you trust, **not** on the server, with the maintained `age` tool
(age-encryption.org; Ruvee's tools never generate your real identity):

```bash
age-keygen -o ruvee-backup-identity.txt
```

It prints the public key (`Public key: age1…`). Put that value in the server's configuration as
`BACKUP_AGE_RECIPIENT`. Keep `ruvee-backup-identity.txt` offline, mode 0600, and make a second
offline copy. If you lose every copy, every backup is unreadable.

## 3. Make a backup

```bash
DATABASE_URL=… BACKUP_AGE_RECIPIENT=age1… pnpm --filter @ruvee/api admin backup --out /backups --synthetic-test-only
```

- `/backups` must exist. Three files appear, owner-only (0600): `ruvee-<time>.dump.age`,
  `ruvee-<time>.meta.age` and `ruvee-<time>.manifest.json`. The database stays online.
- The command prints **`Backup digest: <64 hex>`**. Write it down offline (§1). It is the only way
  to tell later that a backup is the one you made: age encryption does not say who made a file,
  and anyone who knows the public key can make one.
- Copy the three files off the server. Check the copy with `sha256sum` against the SHA-256 values
  in the manifest; that only detects a damaged copy, not a swapped one.
- If the command fails or is interrupted (Ctrl-C), it removes what it wrote and nothing is
  published. If the process was killed outright, `*.partial` files may remain: delete them; they
  are never a backup.

Retention suggestion: 7 daily, 4 weekly, 6 monthly. Every backup can be opened with the password
and Recovery Kit of its own day, for as long as it exists.

## 4. Restore onto a clean host

1. **Stop the old server** if it still runs, so no device writes to it. Leave devices as they
   are: a device that is ahead of the backup is never erased by itself and can export its data.
2. **Prepare the host:** install the same or a newer Ruvee; create a **new, empty** database and a
   database role that owns only it and is **not** a superuser (a restored dump runs as SQL; see
   backup-restore.md §3.2b); put the OPAQUE setup file's offline copy at
   `OPAQUE_SERVER_SETUP_FILE`; write `.env` with new host values and the same `PUBLIC_ORIGIN`,
   `SESSION_COOKIE_SECURE` and `EXTENSION_ORIGINS` as before (the restore prints nothing secret;
   these values are in the encrypted metadata and in your old configuration).
3. **Bring the identity for this run only:** copy it to the host, mode 0600, in a directory only
   you can read. It is read by this one command and is never configuration.
4. **Restore:**

   ```bash
   RESTORE_DATABASE_URL=… pnpm --filter @ruvee/api admin restore \
     --manifest /backups/ruvee-<time>.manifest.json \
     --identity /path/to/ruvee-backup-identity.txt \
     --trusted-digest <the digest you wrote down>
   ```

   Before it creates anything it checks the digest, every file, the identity, and decrypts and
   hashes the whole dump. It then loads, migrates and ends every session, pairing and unused setup
   token. Note the printed **restore id**. `--no-trusted-digest` exists for when you have no record;
   the restore then says, and the review shows, that provenance was not checked.

5. **Delete the identity from the host** (it is no longer needed). On SSDs a deleted file may be
   recoverable; treat the host as having seen the identity.
6. **Start the API** at the same `PUBLIC_ORIGIN`. Every API request answers
   `503 maintenance`; health checks answer. Clients say the server is being restored and stay
   read-only.

## 5. Review, then open

```bash
RESTORE_DATABASE_URL=… pnpm --filter @ruvee/api admin restore-review
```

It prints the restore id, the snapshot time, the backup digest and whether it was checked, every
device as of the snapshot, **what becomes valid again** (the password, Recovery Kit and keys as of
the snapshot, and every active device), and what the server cannot know.

- For every device you **removed after the snapshot**:
  `restore-review --revoke-device <id> --reason lost|retired`.
- Then open:

  ```bash
  RESTORE_DATABASE_URL=… pnpm --filter @ruvee/api admin restore-complete --restore-id <id> --devices-reviewed --accept-restored-credentials
  ```

  No restart is needed. If the snapshot had no account, setting up needs a new token
  (`bootstrap-token`).

**Right after opening** (D-30 is not built, so nothing forces this): sign in with the password as
of the snapshot, then change the password, make a new Recovery Kit, and replace the Secret Key
(always if a device was lost). Until you do, an old password or kit that you replaced after the
backup works again for whoever knows it. None of this revokes copies anyone already made.

On devices: those in step with the backup continue. Those ahead show "the server reports that it
was restored": open **Security → After a server restore**, download the verified copy (it does
not contain changes still waiting to sync; the screen says how many, and they stay on the device
until you erase it), erase the device only if you choose to, then pair or recover it again and
re-enter newer items from the copy (opened read-only from the welcome screen).

## 6. When something fails

| What happened                                         | What it means                                                    | What to do                                                                      |
| ----------------------------------------------------- | ---------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `verify: … trusted digest …`                          | This is not the backup you recorded                              | Stop. Find the right set; do not use `--no-trusted-digest` to get past it       |
| `verify: … could not be decrypted and authenticated`  | Wrong identity, or a damaged, truncated or altered file          | Try another copy of the set; nothing was created                                |
| `verify: this identity is not the backup's recipient` | You brought the wrong identity file                              | Use the identity matching `BACKUP_AGE_RECIPIENT` at backup time                 |
| `verify: … readable by others`                        | The identity file is not 0600                                    | `chmod 600` it                                                                  |
| `verify: … newer or unknown schema`                   | The backup is from a newer Ruvee                                 | Install the same or a newer Ruvee                                               |
| `prepare: the target database is not empty`           | Never restores over data                                         | Create a new, empty database                                                    |
| `load: …` or `migrate: …`, or the restore was killed  | The new database is half-restored and stays closed (maintenance) | Drop that database; restore again into a new one                                |
| `backup: …` (any)                                     | Nothing was published                                            | Fix the cause (space, tools, recipient) and run again; delete stray `*.partial` |

## 7. Rehearsal (do this before you need it)

Rehearse with synthetic data on a separate machine or database server, never on the real one:

1. Set up a throwaway installation with a synthetic account, two devices and a few items.
2. Make a key pair (§2) and a backup (§3); record the digest.
3. On device A, add an item, then stop the server and add another (it stays pending).
4. Restore (§4) into a new database, with the identity and the digest; review and open (§5).
5. Check: A shows the restore explanation, keeps all items read-only, exports a verified copy
   that opens on a clean browser, and is erased only after you type the confirmation; B, which
   was in step, syncs; an old session cookie is refused.
6. Try the failures in §6 on copies of the set (wrong identity, a changed byte, a wrong digest).
7. Drop the rehearsal databases and delete the rehearsal identity.

The automated version of this rehearsal is `pnpm --filter @ruvee/web test:restore` (README).
