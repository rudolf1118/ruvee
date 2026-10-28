# Device proof of possession (D-31)

> **Status:** D-31 option A selected by the owner as the development direction (2026-10-26): a
> per-device Ed25519 key whose private half is sealed under `K_local` and usable only while
> unlocked. This document is the protocol for that direction. It is **not reviewed**: it needs
> the independent review of D-19 (§12) before real data. ADR: [ADR-0011](../adr/0011-device-proof-of-possession.md).
> It answers predeployment-review R2 and R12. **Amended 2026-10-27** by owner decision: accounts
> from before D-31 never acquire an `AVPK` and move to a new account instead (§9).

## 1. What it changes, in one paragraph

Today the password plus a device's public id gives an `active` session (R2). From now on a
session acts as an enrolled device only after that device proves possession of its own device
key (`DSK`), and every request that replaces encrypted key material also proves possession of
the account key (`AK`) through a key derived from it. The password alone yields at most a short
**pre-proof session** that can read the device's own record and the encrypted key material it
needs to unlock, and nothing else.

## 2. Keys

| Name           | What                                                                                               | Where                                                                                                                                                                        | Lifetime                                                                                                               |
| -------------- | -------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------- |
| `DSK`, `DPK`   | Ed25519 key pair of one device, from `crypto_sign_keypair`                                         | `DPK` on the server (`devices.public_key`). `DSK` on the device, as the `LOCAL_RECORD` named `device-key` sealed under `K_local`; in the worker's memory only while unlocked | Created when the device is set up, pairs or recovers; replaced only by a recovery on that device; gone with the device |
| `AVSK`, `AVPK` | Ed25519 key pair derived from `AK`: `seed = KDF(AK, "rvakver1")`, `crypto_sign_seed_keypair(seed)` | `AVPK` on the server (`account_keys.ak_verify_key`). `AVSK` is never stored: derived when needed while unlocked, wiped after the signature                                   | Changes only when `AK` changes (full rotation, Phase 4, not built)                                                     |

- `KDF` and `H` are as in [cryptographic-design.md §2](cryptographic-design.md#2-notation-and-encodings).
  `rvakver1` is a new KDF context, separate from `rvkeyst1`, `rvlocal1` and `rvmanif1`.
- `DSK` is sealed under `K_local`, so a **locked device cannot sign**: lock wipes the in-memory
  `DSK` with the rest of the key material, and the extension keeps only `AK` in
  `chrome.storage.session` (D-27), from which it re-opens `DSK` after a service-worker restart.
  No WebCrypto or other while-locked signing key exists.
- `AVPK` is public and reveals nothing that decrypts (`KDF` is one-way). Anyone holding `AK`
  can compute `AVSK`; that is the point.

## 3. What a signature proves, and what it does not

- A valid `DSK` signature proves the request came from code holding that device's unlocked key
  material, and binds it to one account, device, session (or login), operation, nonce and
  payload.
- A valid `AVSK` signature proves the request came from code holding `AK`, for that exact
  payload.
- **Neither proves that an envelope is correct or decrypts.** The server cannot open wraps or
  keysets. A client holding `AK` can still upload garbage and lock its owner out of the server
  copy; the client opens its own new wrap before uploading, as it already does.

## 4. Signed bytes

All fields are fixed-length or `LP`-prefixed, so every input parses one way only.

```
DSI  = "ruvee/v1/device-proof" ‖ u8(1) ‖ u8(op) ‖ account_id ‖ device_id ‖ binding ‖ nonce ‖ payload
AKSI = "ruvee/v1/ak-proof"     ‖ u8(1) ‖ u8(op) ‖ account_id ‖ ak_id ‖ u32(ak_epoch) ‖ binding ‖ nonce ‖ payload
sig  = crypto_sign_detached(DSI, DSK)   or   crypto_sign_detached(AKSI, AVSK)       (64 bytes)
```

- `account_id`, `device_id`, `ak_id`: 16 bytes each. `binding`, `nonce`, `payload`: 32 bytes.
- `binding` ties the proof to one login or session:
  - logins: `H("ruvee/v1/login-ref" ‖ login_id)` (the 16-byte `loginId`);
  - first setup: `H("ruvee/v1/setup-ref" ‖ bootstrap_token)` (the 32 raw bytes);
  - every other operation: `session_ref = H("ruvee/v1/session-ref" ‖ session_id)`, which the
    server returns with each nonce.
- `nonce`: the login `challenge`, a server nonce (§6), or 32 zero bytes for first setup (the
  setup token is single-use and the registration atomic, so nothing can replay).
- `payload = H("ruvee/v1/proof-payload" ‖ u8(op) ‖ LP(f₁) ‖ … ‖ LP(fₙ))` over the operation's
  fields below, in this order. Binary fields are their raw bytes, integers their `u8`/`u32`/
  `u64` encoding, absent optional fields `LP` of zero bytes.

| op  | Name                  | Payload fields                                                                                                                                                                                            | DSI         | AKSI |
| --- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ---- |
| 1   | `login`               | `finishLoginRequest`                                                                                                                                                                                      | ✓           |      |
| 2   | `session_proof`       | none                                                                                                                                                                                                      | ✓           |      |
| 3   | `register`            | `registrationRecord`, `device_public_key`, `ak_verify_key`, `wrappedAkPassword`, `wrappedAkRecovery`, `recoveryVerifier`, `keyset`, `vault_id`                                                            | ✓           | ✓    |
| 4   | `password_change`     | Retired (follow-up review F-4); never verified and never reused. Replaced by op 12                                                                                                                        |             |      |
| 5   | `secret_key_rotate`   | `u32(keysetVersion)`, `keyset`, `u8(kdfProfile)`, `saltPw`, `wrappedAkPassword`, `u64(expectedRowVersion)`                                                                                                | ✓           | ✓    |
| 6   | `recovery_key_rotate` | `recoveryKeyId`, `wrappedAkRecovery`, `recoveryVerifier`, `u64(expectedRowVersion)`                                                                                                                       | ✓           | ✓    |
| 7   | `device_revoke`       | `revoked_device_id`, `reason` (UTF-8)                                                                                                                                                                     | ✓           |      |
| 8   | `pairing_approve`     | `pairing_id`, `requester_device_id`, `requester_public_key`, `ciphertext`, `mac`, `label`                                                                                                                 | ✓           |      |
| 9   | `recovery_complete`   | `registrationRecord`, `u8(kdfProfile)`, `saltPw`, `wrappedAkPassword`, `recoveryKeyId`, `wrappedAkRecovery`, `recoveryVerifier`, `u64(expectedRowVersion)`, `label`, `device_public_key`, `ak_verify_key` | ✓ (new key) | ✓    |
| 10  | `reopen_login`        | `finishLoginRequest`                                                                                                                                                                                      | ✓           |      |
| 11  | `reopen_complete`     | as op 9                                                                                                                                                                                                   | ✓           | ✓    |
| 12  | `password_change_v2`  | `registrationRecord`, `u8(kdfProfile)`, `saltPw`, `wrappedAkPassword`, `u64(expectedRowVersion)`, `u32(keysetVersion)`                                                                                    | ✓           | ✓    |

Op 12 (owner approval, 2026-10-28, follow-up review F-4) is the password change. `keysetVersion`
is the version of the keyset whose `SK` the client derived the new wrap's `AUK` with; the server
applies the change only while it is the account's `keyset_version`, in the same conditional
`UPDATE` as `row_version`. As built, only a Secret Key rotation changes `keyset_version`
(registration sets 1). Vault creation and full rotation, which will also change it
(sync-protocol.md §10), are not built; when they are, a change from a device that has not seen the
new keyset is refused and retried after adopting it, which is safe but not necessary. The version
binds the request to the version the client **claims**; the server cannot check that the wrap was
made with that `SK` (§3).

The signing and verification code, including these encoders, is one module of `@ruvee/crypto`
used by both the clients and the API, so the two sides cannot encode differently.

## 5. Login and unlock

**Login (`/auth/login/*`).** `login/start` also returns a 32-byte random `challenge`, kept in the
single-use, 60-second login state with the claimed device. `login/finish` may carry
`deviceProof` = `sig(DSI(op 1))`. After OPAQUE succeeds:

| Claimed device       | Proof                   | Result                                                               |
| -------------------- | ----------------------- | -------------------------------------------------------------------- |
| none, or unknown     | ignored                 | a new `pending` device and a pending session (as before)             |
| `pending`            | ignored                 | a pending session for it (as before)                                 |
| `active`, with `DPK` | valid                   | a **proven** session; the device's older sessions end (`superseded`) |
| `active`, with `DPK` | invalid                 | `401 device_proof_failed`; a security event                          |
| `active`             | absent, or no `DPK` yet | a **pre-proof** session; nothing else of the device changes          |
| `revoked`            | any                     | `401 device_revoked` (as before)                                     |

A pre-proof login never ends the device's other sessions, so a password holder cannot sign the
genuine device out (R2).

**Unlock on an enrolled device** (all local first, so there is no circular dependency):

1. Derive `AUK` from the typed password and the local `SK`, and open the **local** password wrap:
   `AK`, then `K_local`, then the `device-key` record: `DSK`.
2. If that worked: restore the server session; if it is missing or not proven, log in with
   `deviceProof`. The session is proven at once.
3. If the local wrap did not open (the password changed on another device): log in **without**
   proof. The pre-proof session may read `GET /account/keys`; the client opens the new server
   wrap with its local `SK`, gets `AK`, opens `DSK`, then asks for a nonce and sends
   `POST /auth/session-proof` (op 2). The session becomes proven and the device's older sessions
   end.
4. If the server's keyset is newer than the local one (`SK` rotated elsewhere) and the password
   also changed, the client asks for the previous password (`previous_password_required`, as
   today): the old local wrap gives `AK`, hence `DSK`, and step 2 applies.
5. A device with no `device-key` record cannot prove anything: it stays usable offline, with all
   its local data. If its account has an `AVPK` it re-enrolls with the Recovery Kit (§8); if not
   (an account from before D-31), it is told to move to a new account (§9). `GET
/devices/current` says which (`accountHasVerifyKey`).

**Pre-proof session.** A cookie or token session of an `active` device with `proven_at` null.

- Allowed: `GET /devices/current`, `GET /account/keys`, `POST /auth/proof-nonce` (only for
  `session_proof`), `POST /auth/session-proof`, `POST /auth/logout`. Everything else is
  `403 device_proof_required`.
- Expires 10 minutes after creation if still unproven (`session_expired`).
- One failed `session-proof` revokes it (`proof_failed`); the client logs in again.
- Rate limits: the per-session limit (300/minute); one open nonce per operation (§6).
- What it exposes: the account key material (`AK` wraps, salt and profile, keyset envelope).
  These are useless without `SK` and are in every database copy already; the threat model
  records it (T-14).

Sessions of a `pending` device are unchanged: they reach only what a pending device may
(device-enrollment.md §1).

**Token clients** (the extension) follow the same rules: proof status belongs to the session
row, so every refresh keeps it, and revocation, reuse detection and expiry are unchanged.

## 6. Nonces

- `POST /api/v1/auth/proof-nonce`, `POST /api/v1/recovery/proof-nonce` and
  `POST /api/v1/reopen/proof-nonce` return `{ nonce, sessionRef, expiresAt }` for one named
  operation, bound to the calling session, its account and device.
- Stored in `proof_nonces` as `SHA-256(nonce)` with the session, operation and an expiry of
  **2 minutes**. Issuing a nonce replaces the session's open nonce for the same operation, so a
  session has at most one open nonce per operation and retries never pile up; of two concurrent
  requests of one kind in one session, the one holding the replaced nonce fails safely.
- The operation first verifies the signatures (no state change), then, **in the same
  transaction as its own effect**, consumes the nonce with one conditional
  `UPDATE … WHERE nonce_hash = $1 AND session_id = $2 AND operation = $3 AND consumed_at IS NULL
AND expires_at > now()`. Exactly one concurrent request can consume it; the others get
  `401 device_proof_failed`.
- A request with an invalid signature burns its nonce. A failure for any reason leaves the client
  to fetch a new nonce; retries never reuse one.
- **What a nonce authorizes, as built (follow-up review S-4, §15 there):**
  - The nonce authorizes **one committed effect**, not one attempt. A refusal after the
    signatures verified (`409`, `404`, `pairing_state`, a revoked device or session) rolls the
    consumption back with the rest of the transaction, and so does a database failure. The nonce
    stays open until it is used, replaced or expired.
  - The exact same request then gets the same refusal for every payload an honest client signs.
    Every check after consumption tests a value that only moves one way: row and keyset
    versions, revocation, a pairing's state, expiry, the restore guard. A restore deletes every
    nonce.
  - A transient failure can be retried with the identical request, and it applies once.
  - Not covered: a payload made to pass a check later, such as a future `expectedRowVersion`. It
    can apply within the nonce's 2 minutes once that state arrives, and so can a different
    payload signed under the same open nonce. Both need the keys that signed the request.
  - Whether a refusal should also spend the nonce is an open decision (S-4).
- The login `challenge` is the nonce of op 1 and 10: in memory, single-use with the login state.
- `proof_nonces` is never trusted after a restore: APPLY POLICY deletes every row, as it deletes
  pairings, and ends every session.

## 7. Authorization surface

Every route, after the maintenance gate (R1) and CSRF:

| Tier | Requirement                                                                                                              | Routes                                                                                                                                                                                                                                 |
| ---- | ------------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0    | none                                                                                                                     | `register/*`, `login/*`, `refresh`, `recovery/start`, `reopen/login/*`, `reopen/recovery/start`, health                                                                                                                                |
| P    | pre-proof allowlist (§5)                                                                                                 | `devices/current`, `account/keys`, `auth/proof-nonce` (`session_proof`), `auth/session-proof`, `auth/logout`                                                                                                                           |
| S    | pending device                                                                                                           | `account`, `devices/current`, `logout`, `pairings/:id` (read, request, cancel)                                                                                                                                                         |
| 2    | **proven session** of an active device                                                                                   | `account`, `devices`, `sessions` (list, end one), `account/events`, `vault`, `sync/changes`, **`sync/commits`** (every item change, trash and permanent deletion is a commit), `pairings` (create, read, cancel, complete), `reauth/*` |
| 3    | proven session **and** fresh operation-bound `DSK` proof                                                                 | `pairings/:id/approve` (op 8)                                                                                                                                                                                                          |
| 3+   | proven session, step-up **and** `DSK` proof **and** `AVSK` proof                                                         | `account/password/finish` (4), `account/secret-key` (5), `PUT account/recovery` (6)                                                                                                                                                    |
| 3s   | proven session, step-up **and** `DSK` proof                                                                              | `devices/:id/revoke` (7)                                                                                                                                                                                                               |
| R    | recovery session, Recovery Key proof (`RAK`), and at completion a new `DPK` with its own `DSK` proof and an `AVSK` proof | `recovery/material`, `recovery/password/start`, `recovery/complete` (9)                                                                                                                                                                |
| O    | reopen session (host code), and at completion `DSK` and `AVSK` proofs                                                    | `reopen/material`, `reopen/password/start`, `reopen/complete` (11); the password path's `reopen/login/finish` needs a `DSK` proof (10)                                                                                                 |

Why sync commits are tier 2 and not operation-bound: their damage is bounded by the manifest
chain and checkpoints (INV-07), their author is the device of a proven session, and a per-commit
nonce would add a round trip to every save without stopping the remaining attacker (code running
in the unlocked origin, which can sign anyway). Ending another session is tier 2 for the same
reason: it costs a re-login, nothing more. `account/password/start`, `reauth/*` and
`recovery/password/start` create no state; they need what their tier says.

## 8. Trust establishment for each device key

- **First setup.** The client generates `DSK` and `AK`; `register/finish` carries `DPK`, `AVPK`
  and both signatures (op 3, bound to the setup token). The setup token authorizes creating the
  account; the server stores public keys only, never chooses or sees a secret one, and the
  signatures show the client holds both private keys. The first session is proven.
- **Pairing.** B generates `DSK` at the code step, in memory only. Its request MAC becomes
  `req_mac = MAC(K_pair, "ruvee/v1/pair-req-2" ‖ pairing_id ‖ device_id_B ‖ u8(platform_B) ‖ epk_B ‖ dpk_B)`,
  so A verifies the exact `DPK` it approves. A's approval carries its own `DSK` proof (op 8)
  over that `DPK`; the server sets B's `public_key` from the stored request only if A's signature
  covers it. B then unwraps `AK` as today, seals `DSK`, and proves its pending-turned-active
  session (op 2) before `pairings/:id/complete`. If B is interrupted between approval and that
  step, its `DSK` is lost: the approved device row can never be proven (it holds no privilege);
  B logs in again as a new device and pairs again, and the orphan row is removed under Devices.
- **Recovery.** The recovering device generates a new `DSK` before `recovery/complete`, which
  carries `DPK` (op 9, signed by the new `DSK`) and an `AVSK` proof. If the account has an
  `AVPK`, the `AVSK` proof is checked against it, so a party that learned only `RAK` (R-08)
  cannot install wraps any more. The device's key is replaced and its new session is proven.
  Recovery never writes `AVPK`. An account with none (from before D-31) is refused with
  `migration_required` at `recovery/start`, before a device or session exists, and again at
  completion (§9).
- **Reopening a restored server.** The `DPK`s and `AVPK` are restored as of the snapshot. The
  password path proves the device with its restored `DPK` at `reopen/login/finish` (op 10) and
  at completion (op 11) together with an `AVSK` proof, which closes R12. The Recovery Kit path is
  a recovery (new `DPK`). Reopening never writes `AVPK`. A snapshot from before D-31 has none, so
  it reopens by neither path: the kit path is refused at its start, without spending the code,
  and every completion is refused (`migration_required`, §9).
- **No password-only path enrolls a key.** `DPK`s are accepted only with the setup token, an
  approving device's proof, or a recovery or reopening checked against the stored `AVPK`. `AVPK`
  is written only by registration, with the setup token.

## 9. Accounts from before D-31 (synthetic data only)

**Owner decision (2026-10-27): fresh-account migration.** An account from before D-31 has no
`AVPK`, and nothing gives it one: not a recovery, not a reopening, not a password, not even a
proof made with `AK`, because the server would have to take the presented key on trust. Such an
account stays synthetic-only and is never made eligible for real data. This replaces the earlier
rule that the first recovery established `AVPK`.

- The migration adds `devices.public_key`, `account_keys.ak_verify_key`, `sessions.proven_at`
  and `proof_nonces`; it changes no existing row. Every existing session is therefore unproven
  and older than 10 minutes, so none keeps any privilege.
- Every tier-3 or higher operation already needs a proven session, and those that replace key
  material also an `AVSK` proof against the stored `AVPK` (§7): with none stored, they fail.
- `recovery/start` and `reopen/recovery/start` answer `409 migration_required` after the
  Recovery Key (and the code) checked out, before anything is created or spent; the two
  completions answer the same if the `AVPK` is gone by then. Nothing is changed.
- The browser keeps its local copy, pending edits and conflicts, and works offline. Its data
  moves by the existing export and import:
  [legacy-account-migration.md](../guides/legacy-account-migration.md). The local export holds
  only the last verified snapshot, so the client lists every pending edit and conflict by item
  for the user to copy by hand; nothing is deleted, reset or replaced in place.
- An account created since D-31 has its `AVPK` from registration, and a device of it without a
  key re-enrolls with the Recovery Kit as before (§8).

## 10. Restore

`DPK`s and `AVPK` are restored with the snapshot; sessions are ended and `proof_nonces` deleted
by APPLY POLICY; login challenges live only in the API's memory. A signature captured before the
backup names a nonce or challenge that no longer exists, so nothing replays against a restored
server.

## 11. Errors

`403 device_proof_required` (a pre-proof session outside the allowlist), `401
device_proof_failed` (a bad or reused proof, an expired nonce), `409 device_key_mismatch` (an
`AVPK` that does not match the account's), `409 migration_required` (an account from before
D-31, which has no `AVPK`; §9).

## 12. Claims that need independent review (D-19)

- The two transcript formats and the payload encoders: domain separation, that no signature in
  one context verifies in another, and that every security-relevant field is covered.
- `KDF(AK, "rvakver1")` as an Ed25519 seed next to Ruvee's other `AK` derivations.
- The pairing MAC change (`dpk_B` inside `req_mac`) and that the server cannot enroll a key A
  did not approve.
- That the authorization table (§7) is complete, and the pre-proof allowlist minimal.
- The nonce lifecycle: issue, bind, consume atomically with the effect, expire, delete on
  restore.
- That no password-only or `RAK`-only path can register a `DPK` or `AVPK`, including on the
  reopening paths, and that an account without `AVPK` gets one by no path at all (§9).
