# Mobile handoff: F-16 conflicts, S-5 and F-21

For the session working on `mobile/vault-app` (worktree `ruvee-mobile`). Nothing in that branch
or worktree was changed from `vault/web-vault`. Background:
[followup-review.md §16](../security/followup-review.md#16-f-16-f-20-to-f-25-s-5-the-connection-failure-and-the-instance-lock).

**Status: pending.** The engine API changed in a way the mobile app's code does not compile
against (read, not built, at `8351287`). Mobile is unverified until that session adopts the change and
runs its tests.

## What changed in `@ruvee/vault`

| Change                                                                                                                                                      | What the mobile app must do                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `resolveConflict` now takes `{ id, draftId, remoteRevision, choice }`                                                                                       | Pass the `draftId` and `remoteRevision` of the `ConflictView` it showed. `apps/mobile/app/src/vault/controller.ts` (`resolveConflict(id, choice)`) and `ui/screens/Item.tsx` call the old form.  |
| `ConflictView` adds `draftId`, `remoteRevision`, `drafts`                                                                                                   | An item can hold several drafts; the view is the oldest. After a resolution, call `conflict` again while the item is still in conflict. Showing "1 of N" is recommended.                         |
| New error `conflict_changed`                                                                                                                                | The other version changed while the user decided; nothing changed. Show the message and reload the view.                                                                                         |
| New error `conflict_pending_edit`                                                                                                                           | The item has a newer unsynced edit, which "keep this device's version" would replace; nothing changed. Suggest syncing first or "keep both".                                                     |
| New `SyncState` `conflicts_full`                                                                                                                            | Sync is paused because conflict drafts reached their bound; edits stay queued and nothing was deleted. Ask the user to resolve conflicts. Any exhaustive switch over `SyncState` needs the case. |
| Counts of conflicts (`localState().conflicts`, export "not included", start-over `conflictsSeen`) now count drafts, not items                               | Pass the value `localState` returns, as before; do not count items separately.                                                                                                                   |
| S-5: a recovery whose server returns another device id for the same account, key and vault now fails with `integrity` instead of `local_data_other_account` | No new code; the existing `integrity` message applies.                                                                                                                                           |

Stored conflict records from before the change load as they are (each gets a `draftId`).

## Not affecting mobile

- F-21 narrows the browser extension's allow-list only.
- F-20 is a web editor fix.
- F-24 and the S-4 nonce changes are server-side; requests are unchanged.

## Tests to run there

- The shared engine tests (`packages/vault`), including `review/f16-conflicts.test.ts` and
  `review/s5-recovery-identity.test.ts`.
- The mobile conflict flow end to end: one conflict, a repeated conflict on the same item (two
  drafts), a resolution after the server changed again (`conflict_changed`), and
  "keep this device's version" with an unsynced edit (`conflict_pending_edit`).
- Any mobile screen that maps `SyncState` or `VaultErrorCode`.
