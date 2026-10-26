# ADR-0010: Server backups for disaster recovery; portable exports as envelope containers

- Status: Proposed. D-13 option A approved by the owner for development (2026-10-26); D-28 pending
- Date: 2026-10-26
- Specification: [backup-restore.md](../architecture/backup-restore.md)

## Context

Ruvee has no tested way back from losing its server, and no way for the user to keep a copy of
the vault outside it. Two different needs are often both called "backup": restoring the service
after a disk or host failure, and a file the user holds that opens without the service.
account-recovery.md §7 fixes constraints for both, and D-13 leaves the export format open.

## Decision (proposed)

- **First milestone (M1): operational server backup.** `ruvee-admin backup` writes a consistent
  `pg_dump` with a checksummed sidecar; the OPAQUE setup file is never part of it (INV-21).
  `ruvee-admin restore` restores into an empty database only, then ends every session, deletes
  open pairings, and records a restore event that makes the web app ask for a device review
  (D-28).
- **Second milestone (M2): portable export**, if D-13 option A is approved: one JSON container of
  envelopes Ruvee already defines (the keyset, the newest verified manifest, the item records)
  plus an `AK_WRAP_RECOVERY` made at export time from the Recovery Key the user types. No new
  cipher, KDF, MAC or envelope purpose. It is never uploaded. Importing into a fresh installation
  creates a new account with new keys and re-encrypts every item.
- Plaintext export, merging into an existing account, and re-seeding are out of scope.

## Consequences

- Server loss becomes recoverable with tested steps; what a restore cannot undo is stated, and
  revoked devices coming back is handled by a forced review rather than ignored.
- The export's security rests on the constructions the vault already uses (themselves still
  awaiting independent review, D-19) and on the 128-bit Recovery Key: a stolen export file
  cannot be guessed offline.
- Losing the Recovery Kit makes exports made with it unreadable forever.
- Devices ahead of a restored server stay read-only until re-seeding exists (M3).

## Alternatives considered

- **Export with its own passphrase (D-13 B).** Convenient, but makes the file guessable offline.
- **The `age` format (D-13 C).** Established, but a second encryption library over content that
  is already authenticated encryption, and in passphrase mode the same offline-guessing exposure.
- **Restoring a server backup as is (D-28 B).** Simplest; brings back removed devices and their
  sessions, as the characterization tests show.
