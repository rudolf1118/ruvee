# Mobile handoff: F-19, key lifetimes in the shared engine

For the session working on `mobile/vault-app` (worktree `ruvee-mobile`). Nothing in that branch
or worktree was changed from `vault/web-vault`. Background and limits:
[followup-review.md §13](../security/followup-review.md#13-f-19-key-lifetimes-in-the-client-engine).

**Status: pending.** Mobile is unverified until that session takes this change, checks its store
against the contract below, and runs its tests.

## Base

- Commit `51432e2` on `vault/web-vault`, on top of the F-4 change (`01e8a35`, see
  [mobile-handoff-f4.md](mobile-handoff-f4.md)) and the branding commit `4249cbe` (review §14).
- Take it by merging or rebasing onto `vault/web-vault` at or after `51432e2`, as for F-4. The
  engine and `key-scope.ts` must not be copied in part.

## What changed in the shared package (`@ruvee/vault`)

- `key-scope.ts` (new): `KeyScope` and `withKeys`, the ownership helper the engine uses.
- `vault-engine.ts`: each unlock, resume, adoption, pairing, recovery, setup and rotation path
  zeroes the keys it no longer needs (table in review §13.1). The lock also zeroes the session's
  `SK`. No public method, request or stored format changed.
- **One behaviour change.** On the server-wrap and previous-password unlock paths, a failed device
  write used to be reported as `wrong_password`. It now propagates: `internal` through
  `errorPayload`, or `open_elsewhere` when another engine took the store. A mobile screen that
  assumed `wrong_password` there should show its generic failure instead.

## Store contract the mobile store must meet

The engine now zeroes the `SK` (and other buffers) of records it reads, and buffers it has
written. That is safe only if the store:

1. returns a **new** `DeviceRecord` and a **new** `enrolled.secretKey` buffer on every `device()`
   call, never a cached or shared one; and
2. keeps **no reference** to buffers passed to `putDevice` or `apply` after the returned promise
   resolves (it has copied or persisted them by then).

Read, not tested, on the mobile branch at `98a9fde`:

- `apps/mobile/app/src/storage/device-store.ts` builds a new record on every read and takes
  `secretKey` from `secureStore.getBytes(...)`.
- `getBytes` decodes base64 into a new buffer on each call, and `setBytes` encodes the bytes to a
  string before its first `await`.

So both rules appear to hold. The mobile session must confirm this with the test below. If either
rule fails, the engine's zeroing would corrupt a stored or cached key; the fix then is for the
store to copy (`slice()`) on read and before any asynchronous write.

## Tests to run there

- `packages/vault`: `review/f19-key-lifecycle.test.ts` and the rest of the engine tests.
- A store test on mobile: zero the `secretKey` of one `device()` result, read again, and expect the
  original bytes; zero a buffer right after `putDevice` resolves, read again, and expect the
  bytes that were written.
- The mobile unlock, lock and pairing flows, including a forced storage failure if the app can
  simulate one.

## What it does not change on mobile

Platform memory that the engine cannot reach stays as it was. Examples are JavaScript strings,
copies made by the native secure-store bridge, and the Hermes heap. Review §13.2 lists the limits
that apply to every client.
