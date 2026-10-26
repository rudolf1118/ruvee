# D-31 (proposed): device proof of possession and wrap-replacement checks

> **Status: proposal for the owner's decision. Not approved, not implemented.** It answers
> predeployment-review R2 (and R12, which has the same root). Nothing here is a reviewed
> cryptographic protocol; whichever option is chosen must be written up as an ADR, given test
> vectors and reviewed independently (D-19) before real data. Until then R2 and R12 stay open.

## 1. The problem, in Ruvee's own terms

- `POST /auth/login/finish` trusts the `deviceId` the client sends. The password plus a known,
  non-revoked device id yields an `active` session for that device
  (`auth.service.ts` `loginFinish`). Device ids are not secret: they appear in `GET /devices`,
  security events, logs and every database copy.
- An `active` session may replace `AK_WRAP_PASSWORD`, `AK_WRAP_RECOVERY` and the keyset after a
  step-up, which is the password again. The server checks only the envelope **headers**
  (`account-security.service.ts` `passwordFinish`, the kit rotation, the reopening completion).
  It cannot tell a real wrap of `AK` from random bytes.
- So the password alone gives T-14 powers (lock the owner out of the server copy, rotate the
  kit to garbage, revoke devices), contrary to device-enrollment.md §1 and INV-06, which say a
  password alone yields a `pending` device. Vault contents stay safe: decryption needs `SK`.

Two separate questions follow, and both need an answer:

1. **Device possession:** how an enrolled device proves it is that device, with something other
   than its public identifier.
2. **Key possession:** how the server checks that whoever replaces a wrap holds `AK`.

## 2. Options

### Option A: per-device signing key, plus an account verification key derived from `AK` (recommended for discussion)

**Device key.** At enrollment each device generates an Ed25519 key pair (`DSK`, `DPK`) with
libsodium `crypto_sign`. The server stores `DPK` in the device row. `DSK` lives where `SK` lives
(device-enrollment.md §5), encrypted under `K_local`, so it is usable only while unlocked.

**Login.** `login/start` returns, with `loginId`, a 32-byte random `challenge` stored in the
same single-use login state. The client finishes OPAQUE, and for an enrolled device sends
`sig = Sign(DSK, "ruvee/v1/device-login" ‖ account_id ‖ device_id ‖ loginId ‖ challenge ‖ H(finishLoginRequest))`.
The server verifies `sig` against the stored `DPK` **after** OPAQUE succeeds. With no valid
signature, the login creates a new `pending` device, as for an unknown id; it never adopts an
existing device. Both are required: a valid signature never replaces the password.

**Binding to the session and the sensitive operation.** Step-up (`reauth/finish`) and every
request that changes credentials or devices (password change, kit rotation, `SK` rotation,
device revoke, reopening completion) carry
`Sign(DSK, "ruvee/v1/device-op" ‖ session_id_hash ‖ op_name ‖ H(canonical request body) ‖ server_nonce)`.
`server_nonce` is single-use, issued by the reauth start; `session_id_hash` is a value the
server derives from the session (never the cookie itself). This binds the proof to one session,
one operation and one body, so it cannot be replayed into another request.

**Key possession (wrap replacement).** The client derives
`(AVSK, AVPK) = crypto_sign_seed_keypair(KDF(AK, "rvakver1"))`. The server stores `AVPK` with the
keyset at account creation and after a full rotation. Every upload that replaces a wrap or the
keyset includes
`Sign(AVSK, "ruvee/v1/wrap-replace" ‖ account_id ‖ ak_id ‖ ak_epoch ‖ H(new wrap or keyset) ‖ server_nonce)`.
The server refuses any replacement without a valid signature under the current `AVPK`.

This proves the uploader held `AK`. It does **not** prove the new wrap opens to `AK`: the client
must still unwrap its own new wrap before uploading (it already does for the password path),
and a client holding `AK` can always destroy its own account.

### Option B: per-device secret with a server-side hash, plus an `AK`-derived verifier

A device receives a random 256-bit `device_secret` at enrollment; the server stores
`SHA-256(device_secret)` and the client presents the secret at login. Wraps carry
`MAC(KDF(AK, "rvakver1"), …)`, and the server stores that key to check the MAC.

- Simpler: no new primitive.
- Weaker: the secret is a bearer token. A malicious or compromised server, or anyone who reads
  the server's memory or TLS-terminated traffic, learns it and can replay it. The server must hold
  the MAC key, so anyone with the database can forge wrap replacements (they could already
  replace rows, but the check would no longer separate "had the database" from "had `AK`").

### Option C: no device proof; every password login is `pending`

Every login creates or reuses only a `pending` device; activation always needs pairing or the
Recovery Kit.

- No cryptography added; it closes the device half of R2.
- Every new browser session needs pairing, including on an already-enrolled device whose cookie
  expired (D-08: 14 days absolute). That is a usability change the owner must accept.
- Does not answer the key-possession half. Combine it with Option A's or B's verifier.

## 3. Effects on each flow (Option A; B and C differ as noted)

| Flow                               | What changes                                                                                                                                                                                                                       | Open points                                                                                                                                                                                                                    |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **First device (bootstrap)**       | The bootstrap request adds `DPK` and `AVPK`.                                                                                                                                                                                       | None beyond the format.                                                                                                                                                                                                        |
| **Pairing**                        | B generates `(DSK, DPK)` before the request; `DPK` is added to the request that `req_mac` covers, so A approves exactly that key and the server cannot substitute it (device-enrollment.md §3.3).                                  | The pairing protocol's MAC input changes: its review (§3.4) must cover it.                                                                                                                                                     |
| **Recovery (Recovery Kit)**        | The new device registers its `DPK` in the same request that proves `RAK`; it obtains `AK`, so it can sign wrap replacements.                                                                                                       | Whether recovery itself should also invalidate every other device's `DPK` (it rotates `SK` after device loss already).                                                                                                         |
| **Reopening (D-30)**               | The password path's completion requires the device signature (the device was active at the snapshot, so its `DPK` was restored) and the `AVPK` signature; this closes R12. The Recovery Kit path signs with the `AK` it recovered. | Devices enrolled after the snapshot have no restored `DPK`: they re-pair, as today.                                                                                                                                            |
| **Revocation**                     | The server deletes or marks the `DPK`. A revoked device cannot activate again with the password alone.                                                                                                                             | None.                                                                                                                                                                                                                          |
| **`SK` rotation, password change** | No change to `DSK`; the replacement carries the `AVSK` signature.                                                                                                                                                                  | None.                                                                                                                                                                                                                          |
| **Full rotation (Phase 4)**        | New `AK` gives a new `AVPK`; the upload is signed under the **old** `AVSK` and carries the new `AVPK`.                                                                                                                             | Must be part of the Phase 4 design.                                                                                                                                                                                            |
| **Backup and restore**             | `DPK` and `AVPK` are restored as of the snapshot; the existing device review (D-28) covers devices revoked later.                                                                                                                  | None new.                                                                                                                                                                                                                      |
| **Migration of existing accounts** | Existing devices have no `DPK`. A one-time "register my key" step is exactly what an R2 attacker would do first, so it must not be allowed from a password-only session.                                                           | **Owner decision:** (a) development data is synthetic, so require re-enrollment (reset) and allow no migration; or (b) allow registration only from a session that existed before the cutover, once. (a) is simpler and safer. |
| **Extension, mobile (later)**      | Same scheme; mobile keeps `DSK` in the platform key store.                                                                                                                                                                         | Phase 5 and 6 designs.                                                                                                                                                                                                         |

## 4. What the owner is asked to decide

1. Option A, B, C, or C combined with A's verifier.
2. Adding Ed25519 (`crypto_sign`) to the approved primitives (ADR-0002), if A is chosen.
3. Whether step-up and the listed sensitive operations require the device signature (A), or only
   login does.
4. The migration choice in §3.
5. That the result is written as an ADR with test vectors and goes to the independent review
   with the pairing protocol (D-19).

## 5. Limits, whichever option is chosen

- XSS in the web origin, while unlocked, can use `DSK` and `AVSK` (T-18, T-19). This raises the
  bar from "password plus a public id" to "code running on an enrolled, unlocked device"; it does
  not defend against that.
- A malicious server can still refuse service, serve old data (handled by checkpoints, INV-07),
  or lie about device lists; it cannot forge the signatures.
- Nothing here changes what a device that already holds `SK` and the password can decrypt.
