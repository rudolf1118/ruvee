# Mobile handoff: F-4, password change bound to the keyset version

For the session working on `mobile/vault-app` (worktree `ruvee-mobile`). Nothing in that branch
or worktree was changed from `vault/web-vault`. Background and guarantee:
[followup-review.md §12](../security/followup-review.md#12-f-4-password-change-bound-to-the-keyset-version).

**Status: pending.** Mobile compatibility is unverified until that session takes this change and
runs its own tests against the updated server.

## Base

- The mobile branch's merge base with `vault/web-vault` is `bdf5ba5` (F-1 to F-4 client fixes).
- The change is commit `01e8a35` on `vault/web-vault` (documented in `7dd94a7`). Its parent,
  `4249cbe`, is an unrelated branding commit; `6dac84b` is the last remediation commit before it.
- Between `bdf5ba5` and `01e8a35` also lie remediation batch 2, whose shared changes are in §11.5
  of the review, and that branding commit.
- Take it by merging or rebasing onto `vault/web-vault` at or after `01e8a35`. Do not copy parts of
  it: the contracts, the crypto encoder and the engine must stay one version.

## What changed in the shared packages

| Package            | Change                                                                                                                                                    |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `@ruvee/crypto`    | `PROOF_OPERATIONS` drops `password_change` (4, retired, never reused) and adds `password_change_v2: 12`. `proofPayload('password_change', …)` now throws. |
| `@ruvee/contracts` | `proofNonceOperationSchema`: `'password_change'` → `'password_change_v2'`. `passwordChangeFinishRequestSchema` requires `keysetVersion: int, 0 … 2³²−1`.  |
| `@ruvee/vault`     | `changePassword` asks for a `password_change_v2` nonce, sends `keysetVersion: enrolled.keysetVersion`, and signs it as the sixth payload field.           |
| API                | `POST /account/password/finish` verifies op 12 and updates only `WHERE row_version = expected AND keyset_version = claimed`, all in one transaction.      |

## Request and transcript

`POST /api/v1/auth/proof-nonce` with `{ "operation": "password_change_v2" }`, then
`POST /api/v1/account/password/finish`:

```json
{
  "registrationRecord": "…",
  "kdfProfile": 1,
  "saltPw": "…",
  "wrappedAkPassword": "…",
  "expectedRowVersion": 7,
  "keysetVersion": 2,
  "nonce": "…",
  "proof": { "device": "…", "accountKey": "…" }
}
```

```
payload = H("ruvee/v1/proof-payload" ‖ u8(12) ‖ LP(registrationRecord) ‖ LP(u8(kdfProfile))
            ‖ LP(saltPw) ‖ LP(wrappedAkPassword) ‖ LP(u64(expectedRowVersion)) ‖ LP(u32(keysetVersion)))
DSI  = "ruvee/v1/device-proof" ‖ u8(1) ‖ u8(12) ‖ account_id ‖ device_id ‖ session_ref ‖ nonce ‖ payload
AKSI = "ruvee/v1/ak-proof"     ‖ u8(1) ‖ u8(12) ‖ account_id ‖ ak_id ‖ u32(ak_epoch) ‖ session_ref ‖ nonce ‖ payload
```

`keysetVersion` is the version of the keyset the device's `SK` came from, the one whose `SK`
derived the new wrap's `AUK`. It is not just the server's current value copied over. The shared
engine already does this; a mobile-specific path must do the same.

## Order of operations (as the shared engine does it)

1. Step-up with the current password.
2. Adopt a newer keyset first (`refreshKeyset`): open the server's keyset with the `AK` the
   device holds, and keep its `SK` only if the server's wrap opens with that `SK` and the step-up
   password. Store `secretKey` and `keysetVersion` together. If it doesn't open, adopt nothing:
   step 3 refuses. Don't assume a stale device can get the new `SK` any other way.
3. `GET /account/keys`; refuse locally (`changed_elsewhere`) unless `akId`, `akEpoch` and
   `keysetVersion` equal the device's.
4. OPAQUE registration, new salt, new wrap under `AUK(new password, SK)`.
5. A fresh nonce, both signatures, `password/finish`.
6. Only after a `204`: replace the stored device record (new `saltPw`, `wrappedAkPassword`,
   `kdfProfile`) in one store write.

## Errors

| Answer                      | Meaning                                                          | Client                                                                                                            |
| --------------------------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `409 row_version_conflict`  | the row or keyset version moved (a rotation, another change)     | `changed_elsewhere`. No automatic retry; the user tries again and step 2 adopts the new keyset                    |
| `400 invalid_request`       | missing or out-of-range `keysetVersion`, or the old nonce name   | a client bug; nothing changed                                                                                     |
| `401 device_proof_failed`   | a signature over other bytes, a spent, expired or replaced nonce | `proof_rejected` (retryable: fetch a new nonce on the next attempt). Never reuse a nonce                          |
| `403 step_up_required`      | step-up is older than 5 minutes                                  | as today                                                                                                          |
| network error after sending | the change may or may not have been applied                      | don't resend. Leave the local wrap as it is; the new password works through the "password changed elsewhere" path |

A refused request changes nothing on the server: not the OPAQUE record, not the wraps, not the
sessions.

## Storage requirements

- The device record update after a `204` (step 6) must be one atomic write. A crash before it
  leaves the old local wrap, which is the lost-answer case above and is safe.
- No new stored field. `enrolled.keysetVersion` already exists and must be updated together with
  `secretKey` whenever a newer keyset is adopted (as the shared engine's `refreshKeyset` does), so
  the signed version always matches the stored `SK`.

## Tests to run there

- The shared engine tests (`packages/vault`), including `review/followup-repro.test.ts`.
- The mobile app's own password-change flow against an API at `01e8a35` or later: a change on an
  up-to-date device succeeds; a change after a rotation on another device is refused with
  `changed_elsewhere` until the device adopts the new keyset.
- Every mobile surface that maps `VaultErrorCode` or the nonce operation names.
